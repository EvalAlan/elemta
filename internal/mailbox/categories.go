package mailbox

// Inbox categories at delivery.
//
// Each message stored at delivery is classified (internal/mailcategory) and
// given a hidden keyword naming its category, which the webmail shows as an
// inbox tab. Classifying here rather than in the webmail means it happens
// once per message, works for mail that arrives while nobody is signed in,
// and gives IMAP clients the same answer through the keywords.
//
// A user's corrections are stored as category rules: an address or @domain
// and the category they chose. The webmail records one each time the user
// moves a message to another tab. Rules beat the classifier's own guess.
//
// Mail filed as spam gets no category: Junk and Quarantine have no tabs.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/EvalAlan/elemta/internal/mailcategory"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// maxCategoryRules bounds one account's rules. Each correction adds one, so
// this is generous, but delivery reads them all for every message.
const maxCategoryRules = 2000

// CategoryRule is one sender the user put in a category.
type CategoryRule struct {
	Sender   string `json:"sender"`   // address or @domain
	Category string `json:"category"` // mailcategory.Category.Name()
}

// CategoryRules returns the account's rules, sorted by sender.
func (e *Engine) CategoryRules(ctx context.Context, account string) ([]CategoryRule, error) {
	out := []CategoryRule{}
	rows, err := e.DB.QueryContext(ctx, `SELECT entry, category FROM mailbox_category_rules WHERE account=$1 ORDER BY entry`, account)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r CategoryRule
		if err := rows.Scan(&r.Sender, &r.Category); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func cleanCategoryRule(r CategoryRule) (CategoryRule, error) {
	sender, err := senderRule(r.Sender)
	if err != nil {
		return CategoryRule{}, err
	}
	c, ok := mailcategory.Parse(r.Category)
	if !ok {
		return CategoryRule{}, fmt.Errorf("%w: %q isn't a category", mailpolicy.ErrInvalid, r.Category)
	}
	return CategoryRule{Sender: sender, Category: c.Name()}, nil
}

// SetCategoryRules replaces the account's rules.
func (e *Engine) SetCategoryRules(ctx context.Context, account string, in []CategoryRule) ([]CategoryRule, error) {
	var clean []CategoryRule
	for _, r := range in {
		if strings.TrimSpace(r.Sender) == "" {
			continue
		}
		c, err := cleanCategoryRule(r)
		if err != nil {
			return nil, err
		}
		// A later entry for the same sender wins, as it would in a form.
		clean = slices.DeleteFunc(clean, func(x CategoryRule) bool { return x.Sender == c.Sender })
		clean = append(clean, c)
	}
	if len(clean) > maxCategoryRules {
		return nil, fmt.Errorf("%w: at most %d category rules", mailpolicy.ErrInvalid, maxCategoryRules)
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_category_rules WHERE account=$1`, account); err != nil {
		return nil, err
	}
	for _, r := range clean {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_category_rules(account, entry, category) VALUES($1,$2,$3)`, account, r.Sender, r.Category); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return e.CategoryRules(ctx, account)
}

// PutCategoryRule adds or changes one rule: what moving a message to a tab
// does. Choosing Primary for a sender is kept as a rule too, since it
// overrides a guess the classifier would otherwise make again.
func (e *Engine) PutCategoryRule(ctx context.Context, account string, r CategoryRule) (CategoryRule, error) {
	c, err := cleanCategoryRule(r)
	if err != nil {
		return CategoryRule{}, err
	}
	// The count check and the insert race, so two tabs could each add the
	// last rule. One rule over the bound is harmless.
	var n int
	var present bool
	if err := e.DB.QueryRowContext(ctx, `SELECT count(*), bool_or(entry=$2) IS TRUE FROM mailbox_category_rules WHERE account=$1`, account, c.Sender).Scan(&n, &present); err != nil {
		return CategoryRule{}, err
	}
	if !present && n >= maxCategoryRules {
		return CategoryRule{}, fmt.Errorf("%w: at most %d category rules; remove some in Settings", mailpolicy.ErrInvalid, maxCategoryRules)
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_category_rules(account, entry, category) VALUES($1,$2,$3)
		ON CONFLICT (account, entry) DO UPDATE SET category=EXCLUDED.category, created=now()`, account, c.Sender, c.Category)
	return c, err
}

// categoryOverrides loads the account's rules for the classifier.
func (e *Engine) categoryOverrides(ctx context.Context, account string) (mailcategory.Overrides, error) {
	rules, err := e.CategoryRules(ctx, account)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	out := make(mailcategory.Overrides, len(rules))
	for _, r := range rules {
		c, _ := mailcategory.Parse(r.Category)
		out[r.Sender] = c
	}
	return out, nil
}

// categoryKeyword classifies a delivery and returns its keyword, or "" for
// Primary. Failing to read the rules isn't worth refusing mail over: the
// message is classified without them.
func (s *Service) categoryKeyword(ctx context.Context, d delivery) string {
	overrides, err := s.engine.categoryOverrides(ctx, d.account.ID)
	if err != nil {
		s.log.Warn("reading category rules failed; classifying without them", "account", d.account.ID, "error", err)
	}
	return mailcategory.Classify(d.raw, overrides).Keyword()
}

// withCategory adds the delivery's category keyword to flags, unless the
// user's filter already chose a category.
func withCategory(flags []string, keyword string) []string {
	if keyword == "" {
		return flags
	}
	if mailcategory.FromKeywords(flags) != mailcategory.Primary {
		return flags
	}
	return append(slices.Clone(flags), keyword)
}
