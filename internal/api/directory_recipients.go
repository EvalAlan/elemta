package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/busybox42/elemta/internal/campaign"
	"github.com/busybox42/elemta/internal/datasource"
)

// DirectoryLister lists accounts from the configured authentication directory.
//
// Narrower than datasource.DataSource on purpose: this feature reads a list of
// people and must not be able to authenticate anybody or change an account.
type DirectoryLister interface {
	ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]datasource.User, error)
}

// SetDirectory attaches the account directory used for campaign recipient
// import. A nil directory leaves the feature reporting itself unavailable
// rather than absent, so the dashboard can say why.
func (s *Server) SetDirectory(directory DirectoryLister) {
	s.directory = directory
}

const (
	// directoryPageSize is what we ask for per call. Directories commonly cap
	// a single response, so the list is paged rather than requested in one go.
	directoryPageSize = 500
	// directoryMaxAccounts bounds the whole import. A campaign built from a
	// directory of unknown size should not be able to exhaust memory here, and
	// an operator about to mail more people than this deserves to be told
	// rather than silently given a prefix.
	directoryMaxAccounts = 25000
)

// handleDirectoryRecipients returns the directory as campaign recipients.
//
// This imports into the compose form rather than resolving at send time. A
// campaign that says "everyone" and expands when it starts will mail a
// different set of people than the operator reviewed, and there is no way to
// check it beforehand. Importing shows exactly who is about to be mailed, and
// the list can then be edited.
func (s *Server) handleDirectoryRecipients(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{"available": s.directory != nil}
	if s.directory == nil {
		// Not an error: most deployments authenticate against a file and have
		// no directory to import from. Say so plainly so the dashboard can
		// explain instead of showing a failure.
		response["reason"] = "No account directory is configured for this server"
		response["recipients"] = []campaign.Recipient{}
		writeJSON(w, response)
		return
	}

	limit := directoryMaxAccounts
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "limit must be a positive number", http.StatusBadRequest)
			return
		}
		if parsed < limit {
			limit = parsed
		}
	}

	users, truncated, err := s.listDirectoryUsers(r.Context(), limit)
	if err != nil {
		// The directory being unreachable is an operational fault worth
		// surfacing, not an empty list. An empty list would read as "nobody
		// works here" and quietly produce a campaign with no recipients.
		response["available"] = false
		response["reason"] = "The account directory could not be read: " + err.Error()
		response["recipients"] = []campaign.Recipient{}
		writeJSONStatus(w, http.StatusBadGateway, response)
		return
	}

	recipients, skipped := campaign.RecipientsFromDirectory(users)
	response["recipients"] = recipients
	response["count"] = len(recipients)
	response["skipped"] = skipped
	response["truncated"] = truncated
	if truncated {
		response["reason"] = "The directory has more accounts than this import returns; the list is incomplete"
	}
	writeJSON(w, response)
}

// listDirectoryUsers pages through the directory up to limit accounts.
//
// The offset advances by what the directory actually returned, not by what was
// asked for, and only an empty page ends the walk. Treating a short page as the
// end looks reasonable and is wrong: LDAP servers routinely cap how many
// entries they will return in one response, so asking for 500 and receiving 200
// is a server limit rather than the end of the directory. Stopping there loses
// everyone past the first page, silently, and the campaign goes to whoever
// happened to sort first.
func (s *Server) listDirectoryUsers(ctx context.Context, limit int) ([]campaign.DirectoryUser, bool, error) {
	out := make([]campaign.DirectoryUser, 0, min(limit, directoryPageSize))
	offset := 0

	for len(out) < limit {
		page := min(directoryPageSize, limit-len(out))
		users, err := s.directory.ListUsers(ctx, nil, page, offset)
		if err != nil {
			return nil, false, err
		}
		if len(users) == 0 {
			// Nothing left: this is the only reliable end-of-directory signal.
			return out, false, nil
		}
		for _, user := range users {
			out = append(out, campaign.DirectoryUser{
				Email:    user.Email,
				FullName: user.FullName,
				Username: user.Username,
				IsActive: user.IsActive,
			})
		}
		offset += len(users)
	}

	// Filled the cap exactly, so there may well be more we did not ask for.
	return out, true, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
