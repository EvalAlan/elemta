package datasource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAP implements the DataSource interface for LDAP directories
type LDAP struct {
	config Config
	// mu guards conn and connected. One connection serves every SMTP
	// session at once (go-ldap multiplexes operations on it); only
	// replacing it needs the lock, and each operation takes the current
	// one (current) so a replacement never pulls it from under another.
	mu        sync.Mutex
	conn      *ldap.Conn
	connected bool
	baseDN    string
	userDN    string
	groupDN   string
}

// NewLDAP creates a new LDAP datasource
func NewLDAP(config Config) *LDAP {
	// Set default values if not provided
	if config.Port == 0 {
		config.Port = 389
		if config.Options["tls_mode"] == "ldaps" {
			config.Port = 636
		}
	}

	// Get base DNs from options or use defaults
	baseDN := "dc=example,dc=com"
	userDN := "ou=users"
	groupDN := "ou=groups"

	if config.Options != nil {
		if base, ok := config.Options["base_dn"].(string); ok && base != "" {
			baseDN = base
		}
		if user, ok := config.Options["user_dn"].(string); ok && user != "" {
			userDN = user
		}
		if group, ok := config.Options["group_dn"].(string); ok && group != "" {
			groupDN = group
		}
	}

	// Ensure userDN and groupDN are relative to baseDN if they don't contain the baseDN
	// Special case: if userDN is the same as baseDN, don't append it
	if !strings.HasSuffix(userDN, baseDN) && !strings.Contains(userDN, ",") && userDN != baseDN {
		userDN = userDN + "," + baseDN
	}
	if !strings.HasSuffix(groupDN, baseDN) && !strings.Contains(groupDN, ",") && groupDN != baseDN {
		groupDN = groupDN + "," + baseDN
	}

	return &LDAP{
		config:    config,
		connected: false,
		baseDN:    baseDN,
		userDN:    userDN,
		groupDN:   groupDN,
	}
}

// dial protects both the service bind and the separate user bind. TLS is
// mandatory unless the operator explicitly selects plaintext for a local lab.
func (l *LDAP) dial() (*ldap.Conn, error) {
	mode, _ := l.config.Options["tls_mode"].(string)
	if mode == "" {
		mode = "starttls"
	}
	if mode != "starttls" && mode != "ldaps" && mode != "plaintext" {
		return nil, fmt.Errorf("unsupported LDAP TLS mode %q", mode)
	}
	var roots *x509.CertPool
	if caFile, _ := l.config.Options["ca_file"].(string); caFile != "" {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		// #nosec G304 -- the CA path is chosen by the operator's LDAP configuration.
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("LDAP CA file has no certificates")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: l.config.Host, RootCAs: roots}
	scheme := "ldap"
	if mode == "ldaps" {
		scheme = "ldaps"
	}
	address := net.JoinHostPort(l.config.Host, strconv.Itoa(l.config.Port))
	conn, err := ldap.DialURL(scheme+"://"+address,
		ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(30 * time.Second)
	if mode == "starttls" {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("LDAP StartTLS failed: %w", err)
		}
	}
	return conn, nil
}

// Connect establishes a connection to the LDAP server
func (l *LDAP) Connect() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connectLocked()
}

func (l *LDAP) connectLocked() error {
	if l.connected {
		return nil
	}

	// Connect to LDAP server using DialURL (replaces deprecated Dial)
	conn, err := l.dial()
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Bind with service account if credentials are provided
	if l.config.Username != "" && l.config.Password != "" {
		if err := conn.Bind(l.config.Username, l.config.Password); err != nil {
			_ = conn.Close() // Ignore error on cleanup in error path
			return fmt.Errorf("failed to bind to LDAP server: %w", err)
		}
	}

	l.conn = conn
	l.connected = true
	return nil
}

// Close closes the connection to the LDAP server
func (l *LDAP) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.connected {
		return nil
	}

	l.connected = false
	if err := l.conn.Close(); err != nil {
		return fmt.Errorf("failed to close LDAP connection: %w", err)
	}
	return nil
}

// IsConnected returns true if the datasource is connected
func (l *LDAP) IsConnected() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connected
}

// current is the connection to use for one operation.
func (l *LDAP) current() *ldap.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conn
}

// lostConnection says whether err means the connection is gone, so the
// operation is worth one more try on a new one.
func lostConnection(err error) bool {
	var le *ldap.Error
	return errors.As(err, &le) && le.ResultCode == ldap.ErrorNetwork
}

// Name returns the name of the datasource
func (l *LDAP) Name() string {
	return l.config.Name
}

// Type returns the type of the datasource
func (l *LDAP) Type() string {
	return "ldap"
}

// setPassword goes through the Password Modify operation (RFC 3062), so the
// directory hashes it under its own policy. Writing userPassword directly
// would either store the password in the clear or need a hash chosen here,
// and passwords people choose need a slow hash the directory is configured for.
func (l *LDAP) setPassword(dn, password string) error {
	_, err := l.current().PasswordModify(ldap.NewPasswordModifyRequest(dn, "", password))
	return err
}

// getUserDN returns the full DN for a user
func (l *LDAP) getUserDN(username string) string {
	return fmt.Sprintf("uid=%s,%s", ldap.EscapeFilter(username), l.userDN)
}

// ensureConnection replaces the connection once it has closed (the
// directory restarted, or dropped it while idle). It used to search the
// directory before every operation to find out, doubling the load; go-ldap
// marks a connection closing as soon as its reader sees it end, and an
// operation that still meets a dead one is tried once more (lostConnection).
func (l *LDAP) ensureConnection() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil && !l.conn.IsClosing() {
		return nil
	}
	if l.conn != nil {
		_ = l.conn.Close()
	}
	l.connected = false
	return l.connectLocked()
}

// replaceConnection drops c if it is still the current connection and
// connects again, after an operation found it dead.
func (l *LDAP) replaceConnection(c *ldap.Conn) error {
	l.mu.Lock()
	if l.conn == c {
		_ = c.Close()
		l.connected = false
	}
	l.mu.Unlock()
	return l.ensureConnection()
}

// search runs one search, once more on a new connection if the first
// found it dead.
func (l *LDAP) search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c := l.current()
	if c == nil {
		return nil, ErrNotConnected
	}
	res, err := c.Search(req)
	if lostConnection(err) {
		if rerr := l.replaceConnection(c); rerr != nil {
			return nil, err
		}
		return l.current().Search(req)
	}
	return res, err
}

// Authenticate verifies credentials against the LDAP server
func (l *LDAP) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if !l.IsConnected() {
		return false, ErrNotConnected
	}

	// Check if connection is still alive, reconnect if needed
	if err := l.ensureConnection(); err != nil {
		return false, fmt.Errorf("failed to ensure LDAP connection: %w", err)
	}

	// First, search for the user by email address to get the actual DN
	var userDN string
	var searchFilter string

	// Check if username looks like an email address
	if strings.Contains(username, "@") {
		// Search by email address
		searchFilter = fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(username))
	} else {
		// Search by uid
		searchFilter = fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username))
	}

	searchFilter = "(&" + searchFilter + "(|(!(accountStatus=*))(accountStatus=active)))"
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		searchFilter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return false, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return false, nil // User not found
	}

	userDN = searchResult.Entries[0].DN

	// Try to bind with the user's credentials using DialURL (replaces deprecated Dial)
	conn, err := l.dial()
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer func() {
		if conn != nil {
			_ = conn.Close() // Ignore error in defer cleanup
		}
	}()

	// Bind with user credentials
	if err := conn.Bind(userDN, password); err != nil {
		// If bind fails, authentication failed
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, fmt.Errorf("authentication failed: %w", err)
	}

	return true, nil
}

// GetUser retrieves user information from the LDAP server
func (l *LDAP) GetUser(ctx context.Context, username string) (User, error) {
	if !l.IsConnected() {
		return User{}, ErrNotConnected
	}

	// Ensure connection is alive
	if err := l.ensureConnection(); err != nil {
		return User{}, fmt.Errorf("failed to ensure LDAP connection: %w", err)
	}

	// Search for the user
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail", "objectClass", "entryUUID", "createTimestamp", "modifyTimestamp", "shadowLastChange", "accountStatus"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return User{}, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return User{}, ErrNotFound
	}

	if len(searchResult.Entries) > 1 {
		return User{}, fmt.Errorf("multiple users found with username '%s'", username)
	}

	entry := searchResult.Entries[0]

	// Create user object
	user := User{
		Username:   entry.GetAttributeValue("uid"),
		FullName:   entry.GetAttributeValue("cn"),
		Email:      entry.GetAttributeValue("mail"),
		IsActive:   entry.GetAttributeValue("accountStatus") == "" || entry.GetAttributeValue("accountStatus") == "active",
		Attributes: make(map[string]interface{}),
	}
	if id := entry.GetAttributeValue("entryUUID"); id != "" {
		user.Attributes["entryUUID"] = id
	}

	// Parse timestamps
	if createTime := entry.GetAttributeValue("createTimestamp"); createTime != "" {
		if t, err := time.Parse("20060102150405Z", createTime); err == nil {
			user.CreatedAt = t.Unix()
		}
	}

	if modifyTime := entry.GetAttributeValue("modifyTimestamp"); modifyTime != "" {
		if t, err := time.Parse("20060102150405Z", modifyTime); err == nil {
			user.UpdatedAt = t.Unix()
		}
	}

	if lastChange := entry.GetAttributeValue("shadowLastChange"); lastChange != "" {
		if days, err := strconv.ParseInt(lastChange, 10, 64); err == nil {
			// shadowLastChange is in days since Jan 1, 1970
			user.LastLoginAt = days * 86400 // Convert days to seconds
		}
	}

	// Get user groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(entry.DN)),
		[]string{"cn"},
		nil,
	)

	groupResult, err := l.search(groupSearchRequest)
	if err != nil {
		return user, fmt.Errorf("failed to search for user groups: %w", err)
	}

	for _, groupEntry := range groupResult.Entries {
		groupName := groupEntry.GetAttributeValue("cn")
		user.Groups = append(user.Groups, groupName)

		// Check if user is admin based on group membership
		if strings.ToLower(groupName) == "admins" {
			user.IsAdmin = true
		}
	}

	// Add all attributes to the attributes map
	for _, attr := range entry.Attributes {
		if len(attr.Values) == 1 {
			user.Attributes[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			user.Attributes[attr.Name] = attr.Values
		}
	}

	return user, nil
}

// ListUsers retrieves a list of users from the LDAP server
func (l *LDAP) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	if !l.IsConnected() {
		return nil, ErrNotConnected
	}

	// Build LDAP filter
	ldapFilter := "(objectClass=posixAccount)"

	// Add filters
	for key, value := range filter {
		switch key {
		case "username":
			ldapFilter = fmt.Sprintf("(&%s(uid=%s))", ldapFilter, ldap.EscapeFilter(value.(string)))
		case "email":
			ldapFilter = fmt.Sprintf("(&%s(mail=%s))", ldapFilter, ldap.EscapeFilter(value.(string)))
		case "is_admin":
			// This is a bit tricky in LDAP, we'll handle it after the search
		}
	}

	// Search for users
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapFilter,
		[]string{"uid", "cn", "mail", "objectClass", "createTimestamp", "modifyTimestamp", "shadowLastChange", "accountStatus"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for users: %w", err)
	}

	var users []User

	// Apply pagination manually
	start := 0
	end := len(searchResult.Entries)

	if offset > 0 && offset < end {
		start = offset
	}

	if limit > 0 && start+limit < end {
		end = start + limit
	}

	// Process each user entry
	for i := start; i < end; i++ {
		entry := searchResult.Entries[i]

		// Create user object
		user := User{
			Username:   entry.GetAttributeValue("uid"),
			FullName:   entry.GetAttributeValue("cn"),
			Email:      entry.GetAttributeValue("mail"),
			IsActive:   entry.GetAttributeValue("accountStatus") == "" || entry.GetAttributeValue("accountStatus") == "active",
			Attributes: make(map[string]interface{}),
		}

		// Parse timestamps
		if createTime := entry.GetAttributeValue("createTimestamp"); createTime != "" {
			if t, err := time.Parse("20060102150405Z", createTime); err == nil {
				user.CreatedAt = t.Unix()
			}
		}

		if modifyTime := entry.GetAttributeValue("modifyTimestamp"); modifyTime != "" {
			if t, err := time.Parse("20060102150405Z", modifyTime); err == nil {
				user.UpdatedAt = t.Unix()
			}
		}

		// Get user groups
		groupSearchRequest := ldap.NewSearchRequest(
			l.groupDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(member=%s)", ldap.EscapeFilter(entry.DN)),
			[]string{"cn"},
			nil,
		)

		groupResult, err := l.search(groupSearchRequest)
		if err != nil {
			return users, fmt.Errorf("failed to search for user groups: %w", err)
		}

		for _, groupEntry := range groupResult.Entries {
			groupName := groupEntry.GetAttributeValue("cn")
			user.Groups = append(user.Groups, groupName)

			// Check if user is admin based on group membership
			if strings.ToLower(groupName) == "admins" {
				user.IsAdmin = true
			}
		}

		// Filter by admin status if requested
		if filter != nil {
			if isAdmin, ok := filter["is_admin"].(bool); ok {
				if isAdmin != user.IsAdmin {
					continue // Skip this user if admin status doesn't match
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// CreateUser creates a new user in the LDAP server
func (l *LDAP) CreateUser(ctx context.Context, user User) error {
	if !l.IsConnected() {
		return ErrNotConnected
	}

	// Check if user already exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user.Username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) > 0 {
		return ErrAlreadyExists
	}

	// Create the user entry
	now := time.Now().Unix()
	if user.CreatedAt == 0 {
		user.CreatedAt = now
	}
	if user.UpdatedAt == 0 {
		user.UpdatedAt = now
	}

	// Create add request
	addRequest := ldap.NewAddRequest(l.getUserDN(user.Username), nil)

	// Add object classes
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"})

	// Add required attributes
	addRequest.Attribute("uid", []string{user.Username})
	addRequest.Attribute("cn", []string{user.FullName})

	if user.Email != "" {
		addRequest.Attribute("mail", []string{user.Email})
	}

	// Add other attributes
	for key, value := range user.Attributes {
		if key == "objectClass" || key == "uid" || key == "cn" || key == "mail" || key == "userPassword" || key == "entryUUID" {
			continue // Skip attributes we've already set
		}

		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []string:
			values = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}

		if len(values) > 0 {
			addRequest.Attribute(key, values)
		}
	}

	// Execute the add request
	if err := l.current().Add(addRequest); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	if user.Password != "" {
		userDN := l.getUserDN(user.Username)
		if err := l.setPassword(userDN, user.Password); err != nil {
			// Not left behind without the password the caller asked for.
			return errors.Join(fmt.Errorf("failed to set password: %w", err), l.current().Del(ldap.NewDelRequest(userDN, nil)))
		}
	}

	// Add user to groups
	for _, groupName := range user.Groups {
		// Find the group
		groupSearchRequest := ldap.NewSearchRequest(
			l.groupDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName)),
			[]string{"dn"},
			nil,
		)

		groupResult, err := l.search(groupSearchRequest)
		if err != nil {
			return fmt.Errorf("failed to search for group: %w", err)
		}

		if len(groupResult.Entries) == 0 {
			// Group doesn't exist, create it
			groupDN := fmt.Sprintf("cn=%s,%s", ldap.EscapeFilter(groupName), l.groupDN)
			groupAddRequest := ldap.NewAddRequest(groupDN, nil)
			groupAddRequest.Attribute("objectClass", []string{"top", "groupOfNames"})
			groupAddRequest.Attribute("cn", []string{groupName})
			groupAddRequest.Attribute("member", []string{l.getUserDN(user.Username)})

			if err := l.current().Add(groupAddRequest); err != nil {
				return fmt.Errorf("failed to create group: %w", err)
			}
		} else {
			// Group exists, add user to it
			groupDN := groupResult.Entries[0].DN
			modifyRequest := ldap.NewModifyRequest(groupDN, nil)
			modifyRequest.Add("member", []string{l.getUserDN(user.Username)})

			if err := l.current().Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to add user to group: %w", err)
			}
		}
	}

	return nil
}

// UpdateUser updates an existing user in the LDAP server
func (l *LDAP) UpdateUser(ctx context.Context, user User) error {
	if !l.IsConnected() {
		return ErrNotConnected
	}

	// Check if user exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user.Username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return ErrNotFound
	}

	userDN := searchResult.Entries[0].DN

	// Create modify request
	modifyRequest := ldap.NewModifyRequest(userDN, nil)

	// Update attributes
	if user.FullName != "" {
		modifyRequest.Replace("cn", []string{user.FullName})
	}

	if user.Email != "" {
		modifyRequest.Replace("mail", []string{user.Email})
	}

	// Update other attributes
	for key, value := range user.Attributes {
		if key == "objectClass" || key == "uid" || key == "userPassword" || key == "entryUUID" {
			continue // Skip attributes we shouldn't modify
		}

		var values []string
		switch v := value.(type) {
		case string:
			values = []string{v}
		case []string:
			values = v
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					values = append(values, str)
				}
			}
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}

		if len(values) > 0 {
			modifyRequest.Replace(key, values)
		}
	}

	// Execute the modify request
	if len(modifyRequest.Changes) > 0 {
		if err := l.current().Modify(modifyRequest); err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
	}
	if user.Password != "" {
		if err := l.setPassword(userDN, user.Password); err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
	}

	// Update group memberships
	// First, get current groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"dn", "cn"},
		nil,
	)

	groupResult, err := l.search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user groups: %w", err)
	}

	// Create maps for current and desired groups
	currentGroups := make(map[string]string) // map[groupName]groupDN
	desiredGroups := make(map[string]bool)   // map[groupName]true

	for _, groupEntry := range groupResult.Entries {
		groupName := groupEntry.GetAttributeValue("cn")
		currentGroups[groupName] = groupEntry.DN
	}

	for _, groupName := range user.Groups {
		desiredGroups[groupName] = true
	}

	// Remove user from groups they should no longer be in
	for groupName, groupDN := range currentGroups {
		if !desiredGroups[groupName] {
			modifyRequest := ldap.NewModifyRequest(groupDN, nil)
			modifyRequest.Delete("member", []string{userDN})

			if err := l.current().Modify(modifyRequest); err != nil {
				return fmt.Errorf("failed to remove user from group: %w", err)
			}
		}
	}

	// Add user to new groups
	for groupName := range desiredGroups {
		if _, exists := currentGroups[groupName]; !exists {
			// Group doesn't exist in current groups, add user to it
			// First, check if the group exists
			groupSearchRequest := ldap.NewSearchRequest(
				l.groupDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(groupName)),
				[]string{"dn"},
				nil,
			)

			groupResult, err := l.search(groupSearchRequest)
			if err != nil {
				return fmt.Errorf("failed to search for group: %w", err)
			}

			if len(groupResult.Entries) == 0 {
				// Group doesn't exist, create it
				groupDN := fmt.Sprintf("cn=%s,%s", ldap.EscapeFilter(groupName), l.groupDN)
				groupAddRequest := ldap.NewAddRequest(groupDN, nil)
				groupAddRequest.Attribute("objectClass", []string{"top", "groupOfNames"})
				groupAddRequest.Attribute("cn", []string{groupName})
				groupAddRequest.Attribute("member", []string{userDN})

				if err := l.current().Add(groupAddRequest); err != nil {
					return fmt.Errorf("failed to create group: %w", err)
				}
			} else {
				// Group exists, add user to it
				groupDN := groupResult.Entries[0].DN
				modifyRequest := ldap.NewModifyRequest(groupDN, nil)
				modifyRequest.Add("member", []string{userDN})

				if err := l.current().Modify(modifyRequest); err != nil {
					return fmt.Errorf("failed to add user to group: %w", err)
				}
			}
		}
	}

	return nil
}

// DeleteUser deletes a user from the LDAP server
func (l *LDAP) DeleteUser(ctx context.Context, username string) error {
	if !l.IsConnected() {
		return ErrNotConnected
	}

	// Check if user exists
	searchRequest := ldap.NewSearchRequest(
		l.userDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for existing user: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return ErrNotFound
	}

	userDN := searchResult.Entries[0].DN

	// Remove user from all groups
	groupSearchRequest := ldap.NewSearchRequest(
		l.groupDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"dn"},
		nil,
	)

	groupResult, err := l.search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("failed to search for user groups: %w", err)
	}

	for _, groupEntry := range groupResult.Entries {
		modifyRequest := ldap.NewModifyRequest(groupEntry.DN, nil)
		modifyRequest.Delete("member", []string{userDN})

		if err := l.current().Modify(modifyRequest); err != nil {
			return fmt.Errorf("failed to remove user from group: %w", err)
		}
	}

	// Delete the user
	deleteRequest := ldap.NewDelRequest(userDN, nil)
	if err := l.current().Del(deleteRequest); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// Query executes a custom query against the LDAP server
func (l *LDAP) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if !l.IsConnected() {
		return nil, ErrNotConnected
	}

	// Parse the query as an LDAP search
	// The query should be in the format: "base||scope||filter||attributes"
	// where:
	// - base is the search base DN
	// - scope is one of: base, one, sub
	// - filter is the LDAP filter
	// - attributes is a comma-separated list of attributes to return
	parts := strings.Split(query, "||")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid LDAP query format, expected 'base||scope||filter||attributes'")
	}

	baseDN := parts[0]
	if baseDN == "" {
		baseDN = l.baseDN
	}

	var scope int
	switch strings.ToLower(parts[1]) {
	case "base":
		scope = ldap.ScopeBaseObject
	case "one":
		scope = ldap.ScopeSingleLevel
	case "sub":
		scope = ldap.ScopeWholeSubtree
	default:
		return nil, fmt.Errorf("invalid scope: %s, expected 'base', 'one', or 'sub'", parts[1])
	}

	filter := parts[2]

	var attributes []string
	if len(parts) > 3 && parts[3] != "" {
		attributes = strings.Split(parts[3], ",")
	}

	// Create search request
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil,
	)

	// Execute search
	searchResult, err := l.search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP query failed: %w", err)
	}

	// Convert result to a more usable format
	var result []map[string]interface{}

	for _, entry := range searchResult.Entries {
		entryMap := map[string]interface{}{
			"dn": entry.DN,
		}

		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				entryMap[attr.Name] = attr.Values[0]
			} else {
				entryMap[attr.Name] = attr.Values
			}
		}

		result = append(result, entryMap)
	}

	return result, nil
}
