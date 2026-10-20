package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/EvalAlan/elemta/internal/auth"
)

// Dashboard user management.
//
// Before this, accounts could only be managed with `elemta user` inside the
// container, and the server only noticed after a restart. These endpoints sit
// on the same users file (the file datasource now writes and re-reads it), so
// the CLI and the dashboard are two views of one list.
//
// Two rules are enforced here rather than left to the operator, because both
// end with nobody able to administer the server: you cannot remove or demote
// the last administrator, and you cannot delete the account you are using.

// validUsername keeps names safe for the users file (no colon or newline) and
// readable in the UI.
var validUsername = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// decodeJSONBody refuses anything but an application/json body before decoding
// it. A cross-site HTML form can only send form encodings or text/plain, and a
// script on another origin cannot send application/json without a CORS
// preflight this server refuses, so this stops a page elsewhere from using a
// signed-in admin's cookie to create an account.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

type userView struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
	// Domains a domain administrator manages; stored among the roles as
	// "domain:" entries, shown apart from them.
	Domains []string `json:"domains,omitempty"`
}

func viewUser(username string, groups []string, isAdmin bool) userView {
	roles := []string{}
	for _, g := range groups {
		if !strings.HasPrefix(g, auth.DomainScopePrefix) {
			roles = append(roles, g)
		}
	}
	return userView{Username: username, Roles: roles, IsAdmin: isAdmin, Domains: auth.DomainScope(groups)}
}

// groupsFor is what to store for a role: the role alone, or for a domain
// administrator the role and their domains.
func groupsFor(role string, domains []string) ([]string, error) {
	if role == "domain-admin" {
		return auth.DomainAdminGroups(domains)
	}
	return []string{role}, nil
}

type roleView struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.authSystem.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "Could not read users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, viewUser(u.Username, u.Groups, u.IsAdmin))
	}
	current := ""
	if ac := GetAuthContext(r); ac != nil {
		current = ac.Username
	}
	writeJSON(w, map[string]interface{}{
		"users":        views,
		"roles":        s.roleViews(),
		"current_user": current,
		"datasource":   s.authSystem.GetDataSourceType(),
	})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"roles": s.roleViews()})
}

func (s *Server) roleViews() []roleView {
	roles := s.rbac.ListRoles()
	views := make([]roleView, 0, len(roles))
	for _, role := range roles {
		perms := make([]string, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, string(p))
		}
		sort.Strings(perms)
		views = append(views, roleView{Name: role.Name, Description: role.Description, Permissions: perms})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     string   `json:"role"`
		Domains  []string `json:"domains"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if !validUsername.MatchString(body.Username) {
		http.Error(w, "Username must be 1-64 letters, digits, '.', '_', '@' or '-'", http.StatusBadRequest)
		return
	}
	if err := auth.ValidatePassword(body.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = "user"
	}
	if _, err := s.rbac.GetRole(body.Role); err != nil {
		http.Error(w, "Unknown role: "+body.Role, http.StatusBadRequest)
		return
	}
	groups, err := groupsFor(body.Role, body.Domains)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.authSystem.CreateUser(ctx, body.Username, body.Password, "", "", body.Role == "admin"); err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			http.Error(w, "A user with that name already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Could not create the user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.authSystem.SetUserRoles(ctx, body.Username, groups); err != nil {
		http.Error(w, "User created, but setting the role failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	view := viewUser(body.Username, groups, body.Role == "admin")
	s.provisionAudit(r, "dashboard-user-create", body.Username, roleDetail(view))
	writeJSONStatus(w, http.StatusCreated, view)
}

func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	var body struct {
		Role    string   `json:"role"`
		Domains []string `json:"domains"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if _, err := s.rbac.GetRole(body.Role); err != nil {
		http.Error(w, "Unknown role: "+body.Role, http.StatusBadRequest)
		return
	}
	groups, err := groupsFor(body.Role, body.Domains)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, err := s.authSystem.GetUser(ctx, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if user.IsAdmin && body.Role != "admin" {
		if ok, msg := s.otherAdminsRemain(r, username); !ok {
			http.Error(w, msg, http.StatusConflict)
			return
		}
	}
	if err := s.authSystem.SetUserRoles(ctx, username, groups); err != nil {
		http.Error(w, "Could not change the role: "+err.Error(), http.StatusInternalServerError)
		return
	}
	view := viewUser(username, groups, body.Role == "admin")
	s.provisionAudit(r, "dashboard-user-role", username, roleDetail(view))
	writeJSON(w, view)
}

// handleResetUserPassword sets another user's password. Their sessions end, so
// a password reset because an account was compromised actually locks it out.
func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	var body struct {
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := auth.ValidatePassword(body.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.authSystem.AdminUpdatePassword(r.Context(), username, body.Password); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Could not set the password: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if ac := GetAuthContext(r); ac == nil || ac.Username != username {
		s.sessionManager.RevokeUserSessions(username)
	}
	s.provisionAudit(r, "dashboard-user-password", username, "")
	writeJSON(w, map[string]interface{}{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if ac := GetAuthContext(r); ac != nil && ac.Username == username {
		http.Error(w, "You cannot delete the account you are signed in with", http.StatusConflict)
		return
	}

	ctx := r.Context()
	user, err := s.authSystem.GetUser(ctx, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if user.IsAdmin {
		if ok, msg := s.otherAdminsRemain(r, username); !ok {
			http.Error(w, msg, http.StatusConflict)
			return
		}
	}
	if err := s.authSystem.DeleteUser(ctx, username); err != nil {
		http.Error(w, "Could not delete the user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.sessionManager.RevokeUserSessions(username)
	s.provisionAudit(r, "dashboard-user-delete", username, "")
	writeJSON(w, map[string]interface{}{"ok": true})
}

// handleChangeOwnPassword lets any signed-in user change their own password,
// which needs the current one.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	ac := GetAuthContext(r)
	if ac == nil || ac.IsAPIKey {
		http.Error(w, "Sign in with a username and password to change it", http.StatusForbidden)
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := auth.ValidatePassword(body.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.authSystem.UpdatePassword(r.Context(), ac.Username, body.CurrentPassword, body.NewPassword); err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "Current password is incorrect", http.StatusForbidden)
			return
		}
		http.Error(w, "Could not change the password: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

// otherAdminsRemain reports whether some administrator other than username
// would be left.
func (s *Server) otherAdminsRemain(r *http.Request, username string) (bool, string) {
	users, err := s.authSystem.ListUsers(r.Context())
	if err != nil {
		return false, "Could not check for other administrators: " + err.Error()
	}
	for _, u := range users {
		if u.IsAdmin && u.Username != username {
			return true, ""
		}
	}
	return false, "This is the last administrator; make another user an admin first"
}

func roleDetail(v userView) string {
	detail := "role " + strings.Join(v.Roles, ",")
	if len(v.Domains) > 0 {
		detail += "; domains " + strings.Join(v.Domains, ",")
	}
	return detail
}
