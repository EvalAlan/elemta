package mailbox

// The internal account-security API the webmail uses (see security.go).
//
// It is served on the health port, which is never published, and refuses
// clients outside lmtp_allowed_networks, the same internal networks that may
// deliver mail. Every request carries the user's own credentials as HTTP
// Basic authentication, so the webmail holds no privilege of its own here:
// it can change only the account whose password it was given, which it has
// because that user is signed in. Settings are changed only with the account
// password, never an app password, so an app password leaked from a mail app
// can't remove the protection it is part of.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

type securityAuth struct {
	account Account
	app     bool
	// session is a passkey sign-in's token rather than a password.
	session bool
	// admin is an administrator access token (admin_access.go), with the
	// administrator's name. Only the check accepts one.
	admin   string
	expires time.Time
}

// passkeyLoginRequest is either half of a passkey sign-in.
type passkeyLoginRequest struct {
	Challenge string          `json:"challenge"`
	Host      string          `json:"host"`
	Origin    string          `json:"origin"`
	Response  json.RawMessage `json:"response"`
}

func (s *Service) securityAPI(mux *http.ServeMux) {
	handle := func(pattern string, allowApp bool, fn func(http.ResponseWriter, *http.Request, securityAuth) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.internalClient(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			user, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="mailbox"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			limit := int64(4096)
			switch r.URL.Path {
			case "/v1/freebusy":
				limit = 1 << 20 // a year of busy times
			case "/v1/security/senders":
				limit = 1 << 19 // the most allowed and blocked senders a class can allow
			case "/v1/security/retention":
				limit = 1 << 16 // up to 100 folder names and their day limits
			}
			if strings.HasSuffix(r.URL.Path, "/freebusy") {
				limit = 1 << 20 // an editor publishing the owner's busy times
			}
			if strings.HasPrefix(r.URL.Path, "/v1/security/passkeys") {
				limit = 1 << 16 // an authenticator's attestation
			}
			if strings.HasPrefix(r.URL.Path, "/v1/security/pgp") {
				limit = 3 * maxPGPKey // a key pair, armored
			}
			if r.URL.Path == "/v1/scheduled" && r.Method == http.MethodPost {
				// The message itself, base64 in JSON.
				limit = s.engine.MaxBytes/3*4 + 1<<16
			}
			if r.URL.Path == "/v1/push/reminders" {
				limit = 1 << 19 // maxPushReminders of them
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			auth, err := s.securityLogin(ctx, user, password)
			if err == nil && auth.app && !allowApp {
				err = ErrCredentials
			}
			if err == nil && auth.admin != "" && pattern != "POST /v1/security/check" {
				err = ErrCredentials
			}
			if err != nil {
				writeSecurityError(w, err)
				return
			}
			out, err := fn(w, r.WithContext(ctx), auth)
			if err != nil {
				writeSecurityError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(r.Body).Decode(v); err != nil {
			return errBadRequest
		}
		return nil
	}

	// check tells the webmail how a sign-in that IMAP accepted must proceed.
	handle("POST /v1/security/check", true, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		if err != nil {
			return nil, err
		}
		kind := "password"
		if a.app {
			kind = "app"
		}
		if a.session {
			// The MTA takes this only on the webmail's own port, and DAV not
			// at all.
			kind = "session"
		}
		if a.admin != "" {
			// Neither the MTA nor DAV accepts this kind; the webmail shows
			// whose session it is.
			kind = "admin"
		}
		// The class of service's switches travel with the answer: the
		// webmail applies webmail, DAV and two-step verification, and the
		// MTA submission. A class that requires app passwords counts as the
		// user having chosen it.
		out := map[string]any{"kind": kind, "totp": st.TOTP, "app_required": st.AppRequired, "account_id": a.account.ID}
		if a.admin != "" {
			out["administrator"] = a.admin
			out["expires"] = a.expires
		}
		if p := a.account.Policy; p != nil {
			out["app_required"] = st.AppRequired || p.RequireAppPasswords
			out["protocols"] = p.Protocols
			out["require_two_factor"] = p.RequireTwoFactor
			out["filters"] = p.Filters
			out["max_forward_addresses"] = p.ForwardLimit()
			out["max_sender_rules"] = p.SenderRuleLimit()
			out["address_book"] = p.AddressBook
		}
		return out, nil
	})
	// Passkeys (passkey.go). Adding one asks for the account password whatever
	// the session signed in with.
	handle("GET /v1/security/passkeys", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.Passkeys(r.Context(), a.account.ID)
	})
	handle("POST /v1/security/passkeys/begin", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Password string `json:"password"`
			Host     string `json:"host"`
			Origin   string `json:"origin"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if _, app, err := s.authenticate(r.Context(), a.account.Address, in.Password, ""); err != nil || app {
			return nil, ErrCredentials
		}
		id, options, err := s.beginPasskeyRegistration(r.Context(), a.account, in.Host, in.Origin)
		if err != nil {
			return nil, err
		}
		return map[string]any{"challenge": id, "options": options}, nil
	})
	handle("POST /v1/security/passkeys/finish", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Challenge string          `json:"challenge"`
			Name      string          `json:"name"`
			Host      string          `json:"host"`
			Origin    string          `json:"origin"`
			Response  json.RawMessage `json:"response"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.finishPasskeyRegistration(r.Context(), a.account, in.Host, in.Origin, in.Challenge, in.Name, in.Response)
	})
	handle("POST /v1/security/passkeys/{id}/delete", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, errBadRequest
		}
		return map[string]bool{"ok": true}, s.engine.DeletePasskey(r.Context(), a.account, id)
	})
	handle("POST /v1/security/session/end", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		_, token, _ := r.BasicAuth()
		if !a.session {
			return map[string]bool{"ok": true}, nil
		}
		return map[string]bool{"ok": true}, s.engine.endSessionToken(r.Context(), token)
	})
	// PGP keys (pgp.go). The password guards replacing or removing one.
	handle("GET /v1/security/pgp", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.PGPKeyOf(r.Context(), a.account.ID)
	})
	handle("PUT /v1/security/pgp", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Password   string `json:"password"`
			PublicKey  string `json:"public_key"`
			PrivateKey string `json:"private_key"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if _, app, err := s.authenticate(r.Context(), a.account.Address, in.Password, ""); err != nil || app {
			return nil, ErrCredentials
		}
		return s.engine.PutPGPKey(r.Context(), a.account, in.PublicKey, in.PrivateKey)
	})
	handle("POST /v1/security/pgp/delete", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Password string `json:"password"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if _, app, err := s.authenticate(r.Context(), a.account.Address, in.Password, ""); err != nil || app {
			return nil, ErrCredentials
		}
		return map[string]bool{"ok": true}, s.engine.DeletePGPKey(r.Context(), a.account)
	})
	handle("POST /v1/security/pgp/publish", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Published bool `json:"published"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.SetPGPPublished(r.Context(), a.account, in.Published)
	})
	handle("POST /v1/security/pgp/lookup", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Addresses []string `json:"addresses"`
		}
		if err := decode(r, &in); err != nil || len(in.Addresses) > 100 {
			return nil, errBadRequest
		}
		return s.engine.PGPLookup(r.Context(), in.Addresses)
	})
	handle("GET /v1/security/pgp/pins", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.PGPPins(r.Context(), a.account.ID)
	})
	handle("PUT /v1/security/pgp/pins", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in PGPPin
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.PutPGPPin(r.Context(), a.account.ID, in)
	})
	// The Web Key Directory is public, and reached through the webmail.
	mux.HandleFunc("GET /v1/pgp/wkd/{domain}/{hash}", func(w http.ResponseWriter, r *http.Request) {
		if !s.internalClient(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		public, err := s.engine.WKDKey(r.Context(), r.PathValue("domain"), r.PathValue("hash"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(public))
	})
	// A passkey sign-in has no credentials yet, so these two are open to the
	// webmail, and to nothing else. It limits attempts by client, as it does for
	// passwords.
	passkeyLogin := func(pattern string, fn func(ctx context.Context, in passkeyLoginRequest) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.internalClient(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
			var in passkeyLoginRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				writeSecurityError(w, errBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			out, err := fn(ctx, in)
			if err != nil {
				writeSecurityError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	passkeyLogin("POST /v1/passkeys/login/begin", func(ctx context.Context, in passkeyLoginRequest) (any, error) {
		id, options, err := s.beginPasskeyLogin(ctx, in.Host, in.Origin)
		if err != nil {
			return nil, err
		}
		return map[string]any{"challenge": id, "options": options}, nil
	})
	passkeyLogin("POST /v1/passkeys/login/finish", func(ctx context.Context, in passkeyLoginRequest) (any, error) {
		address, token, err := s.finishPasskeyLogin(ctx, in.Host, in.Origin, in.Challenge, in.Response)
		if err != nil {
			return nil, err
		}
		return map[string]string{"address": address, "token": token}, nil
	})
	// Scheduled send and snooze (scheduled.go). Scheduling needs the
	// account's own password, as every change here does; sending later
	// doesn't, which is why it happens on this side.
	handle("POST /v1/scheduled", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			From   string    `json:"from"`
			To     []string  `json:"to"`
			SendAt time.Time `json:"send_at"`
			Raw    []byte    `json:"raw"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if s.cfg.Sieve.SubmitAddr == "" {
			return nil, errScheduleUnavailable
		}
		if err := checkScheduleTime(in.SendAt, time.Now()); err != nil {
			return nil, err
		}
		rcpts, err := checkScheduleRecipients(in.To)
		if err != nil {
			return nil, err
		}
		if len(in.Raw) == 0 {
			return nil, errBadRequest
		}
		if ok, err := s.maySendAs(r.Context(), a.account, in.From); err != nil {
			return nil, err
		} else if !ok {
			return nil, &requestError{"you can't send as " + clip(in.From, 80)}
		}
		uid, err := s.engine.ScheduleSend(r.Context(), a.account.ID, in.Raw, strings.ToLower(strings.TrimSpace(in.From)), rcpts, in.SendAt)
		if errors.Is(err, ErrQuota) {
			return nil, &requestError{"your mailbox is full"}
		}
		return map[string]any{"uid": uid, "folder": scheduledFolder}, err
	})
	handle("GET /v1/scheduled", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		list, err := s.engine.ScheduledSends(r.Context(), a.account.ID)
		return map[string]any{"folder": scheduledFolder, "scheduled": list}, err
	})
	handle("POST /v1/scheduled/reschedule", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			UID    uint32    `json:"uid"`
			SendAt time.Time `json:"send_at"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if err := checkScheduleTime(in.SendAt, time.Now()); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.RescheduleSend(r.Context(), a.account.ID, in.UID, in.SendAt)
	})
	handle("POST /v1/scheduled/cancel", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			UID uint32 `json:"uid"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		folder, uid, err := s.engine.CancelSend(r.Context(), a.account.ID, in.UID)
		return map[string]any{"folder": folder, "uid": uid}, err
	})
	handle("POST /v1/snooze", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Folder string    `json:"folder"`
			UIDs   []uint32  `json:"uids"`
			Until  time.Time `json:"until"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if in.Folder == "" || len(in.UIDs) == 0 || len(in.UIDs) > 500 {
			return nil, errBadRequest
		}
		if !in.Until.After(time.Now()) || in.Until.After(time.Now().Add(maxScheduleAhead)) {
			return nil, &requestError{"pick a time within the next year"}
		}
		uids, err := s.engine.Snooze(r.Context(), a.account.ID, in.Folder, in.UIDs, in.Until)
		return map[string]any{"folder": snoozedFolder, "uids": uids}, err
	})
	handle("GET /v1/snooze", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		list, err := s.engine.Snoozes(r.Context(), a.account.ID)
		return map[string]any{"folder": snoozedFolder, "snoozed": list}, err
	})
	handle("POST /v1/snooze/cancel", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			UIDs []uint32 `json:"uids"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if len(in.UIDs) == 0 || len(in.UIDs) > 500 {
			return nil, errBadRequest
		}
		back, err := s.engine.Unsnooze(r.Context(), a.account.ID, in.UIDs)
		return map[string]any{"back": back}, err
	})

	// Notifications to the user's browsers (push.go). Without push, the
	// webmail is told there is no key and doesn't offer them.
	handle("GET /v1/push", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		if s.push == nil {
			return map[string]any{"key": "", "devices": []PushDevice{}}, nil
		}
		key, err := s.push.PublicKey(r.Context())
		if err != nil {
			return nil, err
		}
		devices, err := s.engine.PushDevices(r.Context(), a.account.ID)
		return map[string]any{"key": key, "devices": devices}, err
	})
	handle("PUT /v1/push/subscriptions", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		if s.push == nil {
			return nil, ErrNotFound
		}
		var in PushSubscribe
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		id, err := s.engine.PutPushSubscription(r.Context(), a.account.ID, in, s.push.checkEndpoint)
		return map[string]int64{"id": id}, err
	})
	handle("POST /v1/push/subscriptions/delete", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			ID       int64  `json:"id"`
			Endpoint string `json:"endpoint"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.DeletePushSubscription(r.Context(), a.account.ID, in.ID, in.Endpoint)
	})
	handle("POST /v1/push/test", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		if s.push == nil {
			return nil, ErrNotFound
		}
		var in struct {
			Endpoint string `json:"endpoint"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.push.test(r.Context(), a.account, in.Endpoint)
	})
	handle("PUT /v1/push/reminders", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Reminders []PushReminder `json:"reminders"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if s.push == nil {
			return map[string]int{"stored": 0}, nil
		}
		n, err := s.engine.SetPushReminders(r.Context(), a.account.ID, in.Reminders)
		return map[string]int{"stored": n}, err
	})
	// The user's allowed and blocked senders (sender_rules.go).
	senderMax := func(a securityAuth) int {
		if p := a.account.Policy; p != nil {
			return p.SenderRuleLimit()
		}
		return mailpolicy.DefaultMaxSenderRules
	}
	handle("GET /v1/security/senders", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		rules, err := s.engine.SenderRules(r.Context(), a.account.ID)
		rules.Max = senderMax(a)
		return rules, err
	})
	handle("PUT /v1/security/senders", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in SenderRules
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.engine.SetSenderRules(r.Context(), a.account.ID, in.Allow, in.Block, senderMax(a))
	})
	// Senders the user put in an inbox category (categories.go). POST adds or
	// changes one, which is what moving a message to another tab does.
	handle("GET /v1/security/categories", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.CategoryRules(r.Context(), a.account.ID)
	})
	handle("PUT /v1/security/categories", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in []CategoryRule
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.engine.SetCategoryRules(r.Context(), a.account.ID, in)
	})
	handle("POST /v1/security/categories", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in CategoryRule
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.engine.PutCategoryRule(r.Context(), a.account.ID, in)
	})
	handle("GET /v1/security/retention", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.FolderRetentions(r.Context(), a.account.ID)
	})
	handle("PUT /v1/security/retention", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in []FolderRetention
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return s.engine.SetFolderRetentions(r.Context(), a.account.ID, in)
	})
	// The address book of the user's own domain, for address autocomplete.
	handle("GET /v1/directory", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		// Off unless the account's class of service turns it on.
		if p := a.account.Policy; p == nil || !p.AddressBook {
			return []DirectoryEntry{}, nil
		}
		return s.directory(r.Context(), a.account.Address)
	})
	handle("GET /v1/security/shares", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.SharesForMember(r.Context(), a.account.ID)
	})
	handle("GET /v1/security/send-as", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.sendAddresses(r.Context(), a.account)
	})
	// Calendar sharing. An app password can't change who sees the calendar:
	// it's a credential a mail app holds, and these need the real sign-in.
	handle("GET /v1/calendar-shares", true, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		granted, err := s.engine.CalendarSharesOwned(r.Context(), a.account.ID)
		if err != nil {
			return nil, err
		}
		received, err := s.engine.CalendarSharesFor(r.Context(), a.account.ID)
		if err != nil {
			return nil, err
		}
		return map[string][]mailpolicy.CalendarShare{"granted": granted, "received": received}, nil
	})
	handle("PUT /v1/calendar-shares/{member}", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var request struct {
			Level string `json:"level"`
		}
		if err := decode(r, &request); err != nil {
			return nil, err
		}
		member, err := s.directoryAccount(r.Context(), r.PathValue("member"))
		if err != nil {
			return nil, err
		}
		return s.engine.GrantCalendar(r.Context(), a.account, member, request.Level)
	})
	handle("DELETE /v1/calendar-shares/{member}", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		member, err := s.directoryIdentity(r.Context(), r.PathValue("member"))
		if err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.RevokeCalendar(r.Context(), a.account.ID, member.ID)
	})
	// An edit changes when the owner is busy, and only the webmail can work
	// that out, so an editor publishes it for them.
	handle("PUT /v1/calendar-shares/{owner}/freebusy", true, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		owner, err := s.directoryAccount(r.Context(), r.PathValue("owner"))
		if err != nil {
			return nil, err
		}
		level, err := s.engine.CalendarLevel(r.Context(), owner.ID, a.account.ID)
		if err != nil {
			return nil, err
		}
		if level != CalendarEdit && level != CalendarDelegate {
			return nil, ErrCredentials
		}
		var fb FreeBusy
		if err := decode(r, &fb); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.PublishFreeBusy(r.Context(), owner, fb)
	})
	// The rooms and equipment someone can book: those of their own domain.
	handle("GET /v1/resources", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		return s.engine.Resources(r.Context(), a.account.Address[strings.LastIndexByte(a.account.Address, '@')+1:])
	})
	// Free/busy: the webmail publishes the user's own busy times and reads
	// colleagues'.
	handle("PUT /v1/freebusy", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var fb FreeBusy
		if err := decode(r, &fb); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.PublishFreeBusy(r.Context(), a.account, fb)
	})
	handle("GET /v1/freebusy", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		q := r.URL.Query()
		from, err1 := time.Parse(time.RFC3339, q.Get("from"))
		to, err2 := time.Parse(time.RFC3339, q.Get("to"))
		if err1 != nil || err2 != nil {
			return nil, errBadFreeBusy
		}
		return s.freeBusy(r.Context(), a.account, q["address"], from, to)
	})
	handle("GET /v1/security", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		if p := a.account.Policy; err == nil && p != nil {
			st.AppRequiredByClass, st.TOTPRequired = p.RequireAppPasswords, p.RequireTwoFactor
		}
		if err != nil {
			return st, err
		}
		off, err := s.engine.ProtocolsOff(r.Context(), a.account.ID)
		for _, protocol := range userProtocols {
			allowed := a.account.Policy == nil || a.account.Policy.Allows(protocol)
			st.Protocols = append(st.Protocols, ProtocolChoice{Protocol: protocol, Allowed: allowed, On: allowed && !slices.Contains(off, protocol)})
		}
		return st, err
	})
	handle("POST /v1/security/protocols", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct {
			Protocol string `json:"protocol"`
			On       bool   `json:"on"`
		}
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		// A class's refusal isn't the owner's to lift.
		if in.On && a.account.Policy != nil && !a.account.Policy.Allows(in.Protocol) {
			return nil, errBadRequest
		}
		return map[string]bool{"ok": true}, s.engine.SetProtocol(r.Context(), a.account, in.Protocol, in.On)
	})
	handle("POST /v1/security/verify", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		recovery, err := s.engine.VerifySecondFactor(r.Context(), a.account.ID, in.Code, time.Now())
		if errors.Is(err, ErrBadCode) {
			s.failLogin(key)
		}
		if err != nil {
			return nil, err
		}
		st, err := s.engine.SecurityState(r.Context(), a.account.ID)
		return map[string]any{"recovery": recovery, "recovery_left": st.RecoveryLeft}, err
	})
	handle("POST /v1/security/totp/begin", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Issuer string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		if in.Issuer == "" || len(in.Issuer) > 64 {
			in.Issuer = "Elemta Mail"
		}
		secret, uri, err := s.engine.BeginTOTP(r.Context(), a.account.ID, a.account.Address, in.Issuer)
		return map[string]string{"secret": secret, "uri": uri}, err
	})
	handle("POST /v1/security/totp/confirm", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		codes, err := s.engine.ConfirmTOTP(r.Context(), a.account.ID, in.Code, time.Now())
		if errors.Is(err, ErrBadCode) {
			s.failLogin(key)
		}
		return map[string]any{"recovery_codes": codes}, err
	})
	handle("POST /v1/security/totp/disable", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		if p := a.account.Policy; p != nil && p.RequireTwoFactor {
			return nil, &requestError{"two-step verification is required for this account"}
		}
		var in struct{ Code string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		key := "2fa:" + a.account.Address
		if ok, err := s.allowLogin(key); err != nil || !ok {
			return nil, errLimited
		}
		if _, err := s.engine.VerifySecondFactor(r.Context(), a.account.ID, in.Code, time.Now()); err != nil {
			if errors.Is(err, ErrBadCode) {
				s.failLogin(key)
			}
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.DisableTOTP(r.Context(), a.account.ID)
	})
	handle("POST /v1/security/app-passwords", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Name string }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		p, password, err := s.engine.CreateAppPassword(r.Context(), a.account.ID, in.Name)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, &requestError{err.Error()}
		}
		return map[string]any{"app_password": p, "password": password}, nil
	})
	handle("POST /v1/security/app-passwords/{id}/delete", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, errBadRequest
		}
		return map[string]bool{"ok": true}, s.engine.DeleteAppPassword(r.Context(), a.account.ID, id)
	})
	// Not open to app passwords (allowApp false): it runs with the new
	// account password just after a change or reset.
	handle("POST /v1/security/app-passwords/revoke-all", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		n, err := s.engine.DeleteAllAppPasswords(r.Context(), a.account.ID)
		return map[string]int64{"revoked": n}, err
	})
	handle("POST /v1/security/app-required", false, func(_ http.ResponseWriter, r *http.Request, a securityAuth) (any, error) {
		var in struct{ Required bool }
		if err := decode(r, &in); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.engine.SetAppPasswordsRequired(r.Context(), a.account.ID, in.Required)
	})
}

type requestError struct{ msg string }

func (e *requestError) Error() string { return e.msg }

var (
	errBadRequest = &requestError{"bad request"}
	errLimited    = errors.New("too many attempts")
)

func writeSecurityError(w http.ResponseWriter, err error) {
	var re *requestError
	switch {
	case errors.Is(err, ErrCredentials):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, ErrBadCode):
		http.Error(w, "invalid code", http.StatusUnprocessableEntity)
	case errors.Is(err, ErrTOTPActive):
		http.Error(w, "two-step verification is already enabled", http.StatusConflict)
	case errors.Is(err, errLimited):
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.As(err, &re):
		http.Error(w, re.msg, http.StatusBadRequest)
	case errors.Is(err, mailpolicy.ErrInvalid):
		// A user's own input refused (allowed and blocked senders): the
		// reason is for them, without the package's prefix.
		http.Error(w, strings.TrimPrefix(err.Error(), mailpolicy.ErrInvalid.Error()+": "), http.StatusBadRequest)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

// internalClient admits the internal networks only. The health port is
// never published, so this is the second of two barriers.
func (s *Service) internalClient(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range s.internalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// securityLogin authenticates an API request with the shared failure limit:
// an app password first (one indexed lookup), then the account password.
func (s *Service) securityLogin(ctx context.Context, user, password string) (securityAuth, error) {
	if strings.HasPrefix(password, adminTokenPrefix) {
		a, actor, expires, err := s.adminLogin(ctx, user, password)
		return securityAuth{account: a, admin: actor, expires: expires}, err
	}
	if strings.HasPrefix(password, sessionTokenPrefix) {
		a, err := s.sessionLogin(ctx, user, password)
		return securityAuth{account: a, session: true}, err
	}
	// Internal callers only (internalClient), and they limit by the real client.
	a, app, err := s.authenticate(ctx, user, password, "")
	return securityAuth{account: a, app: app}, err
}
