package webmail

// CalDAV and CardDAV let phones and desktop clients (DAVx5, Thunderbird,
// macOS and iOS Calendar and Contacts) sync the same calendar, tasks and
// address book the webmail shows. They read and write the same objects in
// the user's hidden IMAP folders, so there is no second copy to keep in
// step: an event added on a phone appears in the webmail and the reverse.
//
// Layout, all under /dav/ (clients find it from /.well-known/caldav and
// /.well-known/carddav):
//
//	/dav/                      the signed-in user's principal
//	/dav/calendars/events/     events (VEVENT), the webmail calendar
//	/dav/calendars/tasks/      tasks (VTODO), the webmail task list
//	/dav/contacts/default/     the address book
//	/dav/calendars/shared/<owner>/  a calendar someone shared with the user
//
// Clients sign in with HTTP Basic using the mailbox address and password,
// checked against IMAP as the sign-in page does, with the same failure
// limits. Only a shared calendar's path names anyone, and it resolves only
// while that person's share with the signed-in user exists.
//
// Shared calendars apply the webmail's rules, because here the client gets the
// raw object. Private events are rewritten before view access sees them, and
// edit access can't touch guests: that needs mail, which takes delegate access.
// As on the user's own calendar, saving a meeting here sends nothing.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/emersion/go-webdav/carddav"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

const (
	davRoot          = "/dav/"
	davCalendarHome  = "/dav/calendars/"
	davSharedHome    = "/dav/calendars/shared/"
	davContactsHome  = "/dav/contacts/"
	davAddressBook   = "/dav/contacts/default/"
	davMaxObjectSize = 1 << 20
	// davIdle is how long a client's IMAP connection is kept between
	// requests. Sync clients poll every few minutes and send bursts of
	// requests when they do, so reuse within a burst saves a login per
	// request while idle connections don't pile up.
	davIdle = 5 * time.Minute
)

// davCalendar is one calendar collection and the object collection behind it.
type davCalendar struct {
	cal  caldav.Calendar
	coll Collection
	comp string // the one component type it holds
	// share is set on someone else's calendar.
	share *calendarShare
}

// sharedDAVCalendar presents a share as a collection.
func sharedDAVCalendar(share calendarShare) *davCalendar {
	return &davCalendar{
		cal: caldav.Calendar{
			Path: davSharedHome + strings.ToLower(share.Owner) + "/", Name: sharedName(share.Owner) + "'s calendar",
			Description: "Shared by " + share.Owner, MaxResourceSize: davMaxObjectSize, SupportedComponentSet: []string{ical.CompEvent},
		},
		coll: CollCalendar, comp: ical.CompEvent, share: &share,
	}
}

var davCalendars = []davCalendar{
	{cal: caldav.Calendar{Path: davCalendarHome + "events/", Name: "Calendar", Description: "Elemta calendar", MaxResourceSize: davMaxObjectSize, SupportedComponentSet: []string{ical.CompEvent}}, coll: CollCalendar, comp: ical.CompEvent},
	{cal: caldav.Calendar{Path: davCalendarHome + "tasks/", Name: "Tasks", Description: "Elemta tasks", MaxResourceSize: davMaxObjectSize, SupportedComponentSet: []string{ical.CompToDo}}, coll: CollTasks, comp: ical.CompToDo},
}

var davBook = carddav.AddressBook{
	Path:            davAddressBook,
	Name:            "Contacts",
	Description:     "Elemta contacts",
	MaxResourceSize: davMaxObjectSize,
	// The webmail writes vCard 4.0; cards from clients are kept as sent.
	SupportedAddressData: []carddav.AddressDataType{{ContentType: vcard.MIMEType, Version: "3.0"}, {ContentType: vcard.MIMEType, Version: "4.0"}},
}

// davConn is one user's mail store, shared by their DAV requests.
type davConn struct {
	mu    sync.Mutex
	user  string
	pw    string
	store Mailstore
	used  time.Time
}

// davPool keeps recently used DAV connections. Entries are keyed by an HMAC
// of the user and password under a per-process key, so a cached connection
// is only reused by a request that presents the same password, and the
// key never reveals it.
type davPool struct {
	mu    sync.Mutex
	key   []byte
	conns map[string]*davConn
}

func newDAVPool() *davPool {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand doesn't fail on supported platforms
	}
	return &davPool{key: key, conns: map[string]*davConn{}}
}

func (p *davPool) id(user, pw string) string {
	m := hmac.New(sha256.New, p.key)
	m.Write([]byte(strings.ToLower(user)))
	m.Write([]byte{0})
	m.Write([]byte(pw))
	return hex.EncodeToString(m.Sum(nil))
}

// cached returns the connection for these credentials if one is open, and
// closes connections that have sat idle.
func (p *davPool) cached(user, pw string, now time.Time) *davConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.conns {
		if now.Sub(c.used) > davIdle && c.mu.TryLock() {
			if c.store != nil {
				_ = c.store.Close()
			}
			c.mu.Unlock()
			delete(p.conns, k)
		}
	}
	c := p.conns[p.id(user, pw)]
	if c != nil {
		c.used = now
	}
	return c
}

func (p *davPool) add(user, pw string, st Mailstore, now time.Time) *davConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := p.id(user, pw)
	if c := p.conns[k]; c != nil {
		// Another request signed in at the same time; use its connection.
		_ = st.Close()
		c.used = now
		return c
	}
	c := &davConn{user: user, pw: pw, store: st, used: now}
	p.conns[k] = c
	return c
}

// withStore runs fn on the user's store, redialling once if the connection
// dropped, as SessionManager.withStore does for webmail sessions.
func (c *davConn) withStore(ctx context.Context, dial Dialer, fn func(Mailstore) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if c.store == nil {
			st, err := dial(ctx, c.user, c.pw)
			if err != nil {
				return err
			}
			c.store = st
		}
		err := fn(c.store)
		if err == nil || attempt > 0 || !isConnError(err) {
			return err
		}
		_ = c.store.Close()
		c.store = nil
	}
}

type davConnKey struct{}
type davConditionsKey struct{}
type davConditions struct{ ifMatch, ifNoneMatch webdav.ConditionalMatch }

func davFrom(ctx context.Context) *davConn {
	c, _ := ctx.Value(davConnKey{}).(*davConn)
	return c
}

// davHandler serves CalDAV and CardDAV.
func (s *Server) davHandler() http.Handler {
	calendars := &caldav.Handler{Backend: davCalBackend{s}}
	contacts := &carddav.Handler{Backend: davCardBackend{s}}
	principal := &webdav.ServePrincipalOptions{
		CurrentUserPrincipalPath: davRoot,
		HomeSets:                 []webdav.BackendSuppliedHomeSet{caldav.NewCalendarHomeSet(davCalendarHome), carddav.NewAddressBookHomeSet(davContactsHome)},
		Capabilities:             []webdav.Capability{caldav.CapabilityCalendar, carddav.CapabilityAddressBook},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, ok := s.davAuth(w, r)
		if !ok {
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), davConnKey{}, conn))
		if r.Method == http.MethodDelete {
			r = r.WithContext(context.WithValue(r.Context(), davConditionsKey{}, davConditions{
				ifMatch:     webdav.ConditionalMatch(r.Header.Get("If-Match")),
				ifNoneMatch: webdav.ConditionalMatch(r.Header.Get("If-None-Match")),
			}))
		}
		r.Body = http.MaxBytesReader(w, r.Body, davMaxObjectSize+64<<10)
		p := r.URL.Path
		switch {
		case p == davRoot || p == strings.TrimSuffix(davRoot, "/"):
			webdav.ServePrincipal(w, r, principal)
		case strings.HasPrefix(p, davCalendarHome) || p == strings.TrimSuffix(davCalendarHome, "/"):
			calendars.ServeHTTP(w, r)
		case strings.HasPrefix(p, davContactsHome) || p == strings.TrimSuffix(davContactsHome, "/"):
			contacts.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// davAuth checks HTTP Basic credentials against the mail server, with the
// sign-in page's per-IP and per-user failure limits.
func (s *Server) davAuth(w http.ResponseWriter, r *http.Request) (*davConn, bool) {
	challenge := func() {
		w.Header().Set("WWW-Authenticate", `Basic realm="Elemta Mail", charset="UTF-8"`)
		http.Error(w, "Sign in with your mailbox address and password.", http.StatusUnauthorized)
	}
	user, pw, ok := r.BasicAuth()
	user = strings.TrimSpace(user)
	if !ok || user == "" || pw == "" {
		challenge()
		return nil, false
	}
	ip := s.clientIP(r)
	userKey := loginKey(user, ip)
	if s.throttled(ip, userKey) {
		w.Header().Set("Retry-After", "300")
		http.Error(w, "Too many sign-in attempts. Wait a few minutes.", http.StatusTooManyRequests)
		return nil, false
	}
	now := s.now()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	c := s.dav.cached(user, pw, now)
	var st Mailstore
	var err error
	// The pooled connection is only a transport optimization. Without the
	// security service, reauthenticate against IMAP for every request.
	if c == nil || s.security == nil {
		st, err = s.dial(ctx, user, pw)
	}
	switch {
	case errors.Is(err, ErrAuthFailed):
		s.loginFailed(r, ip, userKey, user)
		s.log.Info("webmail: dav sign-in failed", "user", user, "ip", ip)
		challenge()
		return nil, false
	case errors.Is(err, ErrLoginRefused):
		w.Header().Set("Retry-After", "60")
		http.Error(w, "The mail server is limiting connections for this account.", http.StatusServiceUnavailable)
		return nil, false
	case err != nil:
		s.log.Warn("webmail: dav could not reach mail server", "error", err)
		http.Error(w, "The mail server didn't respond.", http.StatusBadGateway)
		return nil, false
	}
	// Sync apps are mail apps for this purpose: an account that requires
	// app passwords refuses its account password here too, as on IMAP and
	// POP3. The webmail reaches the mail server through the internal
	// listener, which accepts it, so the check is made here.
	if s.security != nil {
		check, err := s.security.check(ctx, user, pw)
		if err != nil {
			if st != nil {
				_ = st.Close()
			}
			if errors.Is(err, errSecurityAuth) {
				s.loginFailed(r, ip, userKey, user)
				challenge()
				return nil, false
			}
			s.log.Warn("webmail: dav account security check unavailable", "user", user, "error", err)
			http.Error(w, "Sign-in is temporarily unavailable.", http.StatusBadGateway)
			return nil, false
		}
		if !check.allows(mailpolicy.DAV) {
			if st != nil {
				_ = st.Close()
			}
			s.log.Info("webmail: dav refused by class of service", "user", user, "ip", ip)
			http.Error(w, "Calendar and contact sync is turned off for this account.", http.StatusForbidden)
			return nil, false
		}
		if check.Kind == "admin" {
			if st != nil {
				_ = st.Close()
			}
			challenge()
			return nil, false
		}
		if check.Kind == "password" && check.AppRequired {
			if st != nil {
				_ = st.Close()
			}
			s.limiter.fail(userKey)
			s.log.Info("webmail: dav account password refused; app password required", "user", user, "ip", ip)
			challenge()
			return nil, false
		}
	}
	if c != nil {
		if st != nil {
			_ = st.Close()
		}
		return c, true
	}
	return s.dav.add(user, pw, st, now), true
}

// davNotFound is the error the DAV handlers turn into a 404.
func davNotFound(what string) error {
	return webdav.NewHTTPError(http.StatusNotFound, fmt.Errorf("webmail: no such %s", what))
}

// davETag is a strong ETag for an object's data.
func davETag(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

// davObjectName is the resource name of an object in its collection.
func davObjectName(o Object, ext string) string {
	if o.Name != "" {
		return o.Name
	}
	if strings.ContainsAny(o.ID, "/?#%") {
		sum := sha256.Sum256([]byte(o.ID))
		return "h-" + hex.EncodeToString(sum[:16]) + ext
	}
	return o.ID + ext
}

// validDAVName reports whether a client-chosen resource name can be stored
// in an object header and round-trip through a URL path.
func validDAVName(name string) bool {
	if name == "" || len(name) > 200 || strings.ContainsAny(name, "/?#%") {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func findDAVObject(objs []Object, name, ext string) *Object {
	for i := range objs {
		if davObjectName(objs[i], ext) == name {
			return &objs[i]
		}
	}
	return nil
}

// checkPreconditions applies If-Match and If-None-Match to the object
// currently at the path (nil when there is none).
func checkPreconditions(cur *Object, ifMatch, ifNoneMatch webdav.ConditionalMatch) error {
	failed := webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("webmail: precondition failed"))
	etag := ""
	if cur != nil {
		etag = davETag(cur.Data)
	}
	if ifNoneMatch.IsSet() {
		if m, err := ifNoneMatch.MatchETag(etag); err != nil || m {
			return failed
		}
	}
	if ifMatch.IsSet() {
		if m, err := ifMatch.MatchETag(etag); err != nil || !m {
			return failed
		}
	}
	return nil
}

// ---- CalDAV ----------------------------------------------------------------

type davCalBackend struct{ s *Server }

func (davCalBackend) CurrentUserPrincipal(context.Context) (string, error) { return davRoot, nil }
func (davCalBackend) CalendarHomeSetPath(context.Context) (string, error) {
	return davCalendarHome, nil
}

func (davCalBackend) CreateCalendar(context.Context, *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("webmail: calendars can't be added"))
}

func (b davCalBackend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	out := make([]caldav.Calendar, len(davCalendars))
	for i, c := range davCalendars {
		out[i] = c.cal
	}
	shares, err := b.shares(ctx)
	if err != nil {
		// Their own calendars still sync. Every shared one disappearing from
		// a client for a moment is the lesser harm, and it logs.
		b.s.log.Warn("webmail: dav calendar shares unavailable", "user", davFrom(ctx).user, "error", err)
	}
	for _, share := range shares {
		out = append(out, sharedDAVCalendar(share).cal)
	}
	return out, nil
}

// shares is read on every request, not cached: what view access hides depends
// on the level, so a cut-back must apply at once.
func (b davCalBackend) shares(ctx context.Context) ([]calendarShare, error) {
	if b.s.security == nil {
		return nil, nil
	}
	conn := davFrom(ctx)
	var shares calendarShares
	if err := b.s.security.call(ctx, http.MethodGet, "/v1/calendar-shares", conn.user, conn.pw, nil, &shares); err != nil {
		return nil, err
	}
	return shares.Received, nil
}

// calendarAt resolves a path to a collection, one of the user's or a shared
// one, and the object name under it. A share that doesn't exist looks exactly
// like a path that doesn't.
func (b davCalBackend) calendarAt(ctx context.Context, p string) (*davCalendar, string, error) {
	if c, name := davCalendarFor(p); c != nil {
		return c, name, nil
	}
	rest, ok := strings.CutPrefix(p, davSharedHome)
	if !ok {
		return nil, "", nil
	}
	owner, name, _ := strings.Cut(rest, "/")
	if owner == "" || strings.Contains(name, "/") {
		return nil, "", nil
	}
	shares, err := b.shares(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, share := range shares {
		if strings.EqualFold(share.Owner, owner) {
			return sharedDAVCalendar(share), name, nil
		}
	}
	return nil, "", nil
}

// withCalendar runs fn on the store holding c, opened for a shared calendar
// with the user's own credentials, so a revoked share stops working at once.
func (b davCalBackend) withCalendar(ctx context.Context, c *davCalendar, fn func(Mailstore) error) error {
	conn := davFrom(ctx)
	if c.share == nil {
		return conn.withStore(ctx, b.s.dial, fn)
	}
	st, err := b.s.dial(ctx, calendarLogin(conn.user, c.share.Owner), conn.pw)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	return fn(st)
}

// checkSharedWrite applies a share to a change. cur is the stored object and
// cal the new content, either of which may be nil. The webmail's rule applies:
// a change that involves guests is mail, or should have been.
func checkSharedWrite(c *davCalendar, cur *Object, cal *ical.Calendar) error {
	if c.share == nil || c.share.CanActFor() {
		return nil
	}
	forbidden := webdav.NewHTTPError(http.StatusForbidden, errors.New("webmail: this share doesn't allow that"))
	if !c.share.CanEdit() {
		return forbidden
	}
	if cal != nil && icalHasGuests(cal) {
		return forbidden
	}
	if cur != nil {
		stored, err := ical.NewDecoder(bytes.NewReader(cur.Data)).Decode()
		if err != nil || icalHasGuests(stored) {
			return forbidden
		}
	}
	return nil
}

func icalHasGuests(cal *ical.Calendar) bool {
	for _, comp := range cal.Children {
		if comp.Name == ical.CompEvent && (comp.Props.Get(ical.PropAttendee) != nil || comp.Props.Get(ical.PropOrganizer) != nil) {
			return true
		}
	}
	return false
}

// davRedactedProps are what free/busy already tells a colleague, plus what a
// client needs to place the event on a calendar.
var davRedactedProps = map[string]bool{
	ical.PropUID: true, ical.PropDateTimeStamp: true, ical.PropDateTimeStart: true, ical.PropDateTimeEnd: true,
	ical.PropDuration: true, ical.PropRecurrenceRule: true, ical.PropRecurrenceDates: true, ical.PropExceptionDates: true,
	ical.PropRecurrenceID: true, ical.PropStatus: true, ical.PropClass: true, ical.PropTransparency: true,
}

// redactPrivateCalendar rewrites an object for view access, keeping a VEVENT's
// time and nothing else when it's private. Each VEVENT is judged alone, since
// one occurrence of a series can be private when the rest aren't. Anything
// kept is kept because it's known to be harmless, rather than removing what's
// known to be sensitive, so a property nobody thought of stays hidden.
func redactPrivateCalendar(data []byte) ([]byte, error) {
	cal, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return nil, err
	}
	changed := false
	for i, comp := range cal.Children {
		if comp.Name != ical.CompEvent {
			continue
		}
		class := ""
		if p := comp.Props.Get(ical.PropClass); p != nil {
			class = strings.ToUpper(p.Value)
		}
		if class != "PRIVATE" && class != "CONFIDENTIAL" {
			continue
		}
		bare := ical.NewComponent(ical.CompEvent)
		for name, props := range comp.Props {
			if davRedactedProps[name] {
				bare.Props[name] = props
			}
		}
		bare.Props.SetText(ical.PropSummary, "Busy")
		cal.Children[i] = bare
		changed = true
	}
	if !changed {
		return data, nil
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func davCalendarFor(p string) (*davCalendar, string) {
	dir, name := path.Split(p)
	for i := range davCalendars {
		if davCalendars[i].cal.Path == p || davCalendars[i].cal.Path == p+"/" {
			return &davCalendars[i], ""
		}
		if davCalendars[i].cal.Path == dir {
			return &davCalendars[i], name
		}
	}
	return nil, ""
}

func (b davCalBackend) GetCalendar(ctx context.Context, p string) (*caldav.Calendar, error) {
	c, name, err := b.calendarAt(ctx, p)
	if err != nil {
		return nil, err
	}
	if c == nil || name != "" {
		return nil, davNotFound("calendar")
	}
	cal := c.cal
	return &cal, nil
}

func (b davCalBackend) objects(ctx context.Context, c *davCalendar) ([]Object, error) {
	var objs []Object
	err := b.withCalendar(ctx, c, func(st Mailstore) error {
		var err error
		objs, err = st.Objects(ctx, c.coll)
		return err
	})
	return objs, err
}

func davCalendarObject(c *davCalendar, o Object) (caldav.CalendarObject, error) {
	if c.share != nil && !c.share.CanEdit() {
		// Before the ETag and the length, which would otherwise describe the
		// private original.
		data, err := redactPrivateCalendar(o.Data)
		if err != nil {
			return caldav.CalendarObject{}, err
		}
		o.Data = data
	}
	cal, err := ical.NewDecoder(bytes.NewReader(o.Data)).Decode()
	if err != nil {
		return caldav.CalendarObject{}, err
	}
	return caldav.CalendarObject{
		Path:          c.cal.Path + davObjectName(o, ".ics"),
		ModTime:       o.Modified,
		ContentLength: int64(len(o.Data)),
		ETag:          davETag(o.Data),
		Data:          cal,
	}, nil
}

func (b davCalBackend) GetCalendarObject(ctx context.Context, p string, _ *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	c, name, err := b.calendarAt(ctx, p)
	if err != nil {
		return nil, err
	}
	if c == nil || name == "" {
		return nil, davNotFound("calendar object")
	}
	objs, err := b.objects(ctx, c)
	if err != nil {
		return nil, err
	}
	o := findDAVObject(objs, name, ".ics")
	if o == nil {
		return nil, davNotFound("calendar object")
	}
	co, err := davCalendarObject(c, *o)
	if err != nil {
		return nil, err
	}
	return &co, nil
}

func (b davCalBackend) ListCalendarObjects(ctx context.Context, p string, _ *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	c, name, err := b.calendarAt(ctx, p)
	if err != nil {
		return nil, err
	}
	if c == nil || name != "" {
		return nil, davNotFound("calendar")
	}
	if c.coll == CollCalendar && c.share == nil {
		// A phone that only syncs the calendar still sees guests' answers.
		conn := davFrom(ctx)
		_ = conn.withStore(ctx, b.s.dial, func(st Mailstore) error {
			b.s.recordInboxReplies(ctx, st, conn.user, b.s.defaultLoc)
			return nil
		})
	}
	objs, err := b.objects(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]caldav.CalendarObject, 0, len(objs))
	for _, o := range objs {
		co, err := davCalendarObject(c, o)
		if err != nil {
			continue // damaged data stays in IMAP, but can't be served as iCalendar
		}
		out = append(out, co)
	}
	return out, nil
}

func (b davCalBackend) QueryCalendarObjects(ctx context.Context, p string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	all, err := b.ListCalendarObjects(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	return caldav.Filter(query, all)
}

func (b davCalBackend) PutCalendarObject(ctx context.Context, p string, cal *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	c, name, err := b.calendarAt(ctx, p)
	if err != nil {
		return nil, err
	}
	if c == nil || name == "" {
		return nil, davNotFound("calendar")
	}
	if err := checkSharedWrite(c, nil, cal); err != nil {
		return nil, err
	}
	if !validDAVName(name) {
		return nil, webdav.NewHTTPError(http.StatusBadRequest, errors.New("webmail: unsupported resource name"))
	}
	typ, uid, err := caldav.ValidateCalendarObject(cal)
	if err != nil {
		return nil, caldav.NewPreconditionError(caldav.PreconditionValidCalendarObjectResource)
	}
	if typ != c.comp {
		return nil, caldav.NewPreconditionError(caldav.PreconditionSupportedCalendarComponent)
	}
	var buf bytes.Buffer
	if err := ical.NewEncoder(&buf).Encode(cal); err != nil {
		return nil, caldav.NewPreconditionError(caldav.PreconditionValidCalendarData)
	}
	data := buf.Bytes()
	if len(data) > davMaxObjectSize {
		return nil, caldav.NewPreconditionError(caldav.PreconditionMaxResourceSize)
	}
	title := ""
	for _, comp := range cal.Children {
		if comp.Name == typ {
			if prop := comp.Props.Get(ical.PropSummary); prop != nil {
				title = prop.Value
				break
			}
		}
	}
	obj := Object{ID: objectID(uid), Title: title, ContentType: "text/calendar", Data: data}
	with := func(fn func(Mailstore) error) error { return b.withCalendar(ctx, c, fn) }
	guard := func(cur *Object) error { return checkSharedWrite(c, cur, cal) }
	if err := davPut(ctx, with, guard, c.coll, &obj, name, ".ics", opts.IfMatch, opts.IfNoneMatch, caldav.NewPreconditionError(caldav.PreconditionNoUIDConflict)); err != nil {
		return nil, err
	}
	b.davChanged(ctx, c)
	co, err := davCalendarObject(c, obj)
	if err != nil {
		return nil, err
	}
	co.ModTime = b.s.now()
	return &co, nil
}

func (b davCalBackend) DeleteCalendarObject(ctx context.Context, p string) error {
	c, name, err := b.calendarAt(ctx, p)
	if err != nil {
		return err
	}
	if c == nil || name == "" {
		return davNotFound("calendar object")
	}
	with := func(fn func(Mailstore) error) error { return b.withCalendar(ctx, c, fn) }
	guard := func(cur *Object) error { return checkSharedWrite(c, cur, nil) }
	if err := davDelete(ctx, with, guard, c.coll, name, ".ics"); err != nil {
		return err
	}
	b.davChanged(ctx, c)
	return nil
}

// davChanged republishes the busy times of whoever's calendar changed.
func (b davCalBackend) davChanged(ctx context.Context, c *davCalendar) {
	if c.share == nil {
		b.s.davCalendarChanged(ctx, c.coll)
		return
	}
	if b.s.security == nil {
		return
	}
	conn := davFrom(ctx)
	user, pw, owner := conn.user, conn.pw, c.share.Owner
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := b.s.publishSharedFreeBusy(ctx, user, pw, owner); err != nil {
			b.s.log.Warn("webmail: free/busy not published", "user", user, "owner", owner, "error", err)
		}
	}()
}

// davCalendarChanged republishes free/busy after a CalDAV client changed
// the calendar (tasks don't make anyone busy).
func (s *Server) davCalendarChanged(ctx context.Context, coll Collection) {
	if conn := davFrom(ctx); conn != nil && coll == CollCalendar {
		s.publishFreeBusy(conn.user, conn.pw, s.cfg.address(conn.user))
	}
}

// davPut stores obj under the client's resource name. The object ID stays
// the UID, which is what the webmail looks objects up by; a client name
// that differs is kept in Object.Name. One UID can't live under two names.
// davContactStore opens the user's own contacts, which are never shared.
func davContactStore(ctx context.Context, s *Server) func(func(Mailstore) error) error {
	return func(fn func(Mailstore) error) error { return davFrom(ctx).withStore(ctx, s.dial, fn) }
}

func davNoGuard(*Object) error { return nil }

func davPut(ctx context.Context, with func(func(Mailstore) error) error, guard func(*Object) error, coll Collection, obj *Object, name, ext string, ifMatch, ifNoneMatch webdav.ConditionalMatch, uidConflict error) error {
	return with(func(st Mailstore) error {
		write := func(st ObjectStore) error {
			objs, err := st.Objects(ctx, coll)
			if err != nil {
				return err
			}
			cur := findDAVObject(objs, name, ext)
			if err := guard(cur); err != nil {
				return err
			}
			if err := checkPreconditions(cur, ifMatch, ifNoneMatch); err != nil {
				return err
			}
			if cur != nil && cur.ID != obj.ID {
				return uidConflict // a resource's UID can't change (RFC 4791 5.3.2)
			}
			if cur == nil {
				for _, o := range objs {
					if o.ID == obj.ID {
						return uidConflict
					}
				}
			}
			if name != obj.ID+ext {
				obj.Name = name
			}
			return st.PutObject(ctx, coll, *obj)
		}
		if atomic, ok := st.(interface {
			DAVTransaction(context.Context, Collection, func(ObjectStore) error) error
		}); ok {
			return atomic.DAVTransaction(ctx, coll, write)
		}
		return write(st)
	})
}

func davDelete(ctx context.Context, with func(func(Mailstore) error) error, guard func(*Object) error, coll Collection, name, ext string) error {
	return with(func(st Mailstore) error {
		remove := func(st ObjectStore) error {
			objs, err := st.Objects(ctx, coll)
			if err != nil {
				return err
			}
			cur := findDAVObject(objs, name, ext)
			if err := guard(cur); err != nil {
				return err
			}
			conditions, _ := ctx.Value(davConditionsKey{}).(davConditions)
			if err := checkPreconditions(cur, conditions.ifMatch, conditions.ifNoneMatch); err != nil {
				return err
			}
			if cur == nil {
				return davNotFound("object")
			}
			return st.DeleteObject(ctx, coll, cur.ID)
		}
		if atomic, ok := st.(interface {
			DAVTransaction(context.Context, Collection, func(ObjectStore) error) error
		}); ok {
			return atomic.DAVTransaction(ctx, coll, remove)
		}
		return remove(st)
	})
}

// ---- CardDAV ---------------------------------------------------------------

type davCardBackend struct{ s *Server }

func (davCardBackend) CurrentUserPrincipal(context.Context) (string, error) { return davRoot, nil }
func (davCardBackend) AddressBookHomeSetPath(context.Context) (string, error) {
	return davContactsHome, nil
}

func (davCardBackend) ListAddressBooks(context.Context) ([]carddav.AddressBook, error) {
	return []carddav.AddressBook{davBook}, nil
}

func (davCardBackend) GetAddressBook(_ context.Context, p string) (*carddav.AddressBook, error) {
	if p != davBook.Path && p+"/" != davBook.Path {
		return nil, davNotFound("address book")
	}
	ab := davBook
	return &ab, nil
}

func (davCardBackend) CreateAddressBook(context.Context, *carddav.AddressBook) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("webmail: address books can't be added"))
}

func (davCardBackend) DeleteAddressBook(context.Context, string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("webmail: the address book can't be deleted"))
}

// davCardName returns the resource name in the address book, or "" when p
// isn't an object path in it.
func davCardName(p string) string {
	dir, name := path.Split(p)
	if dir != davBook.Path {
		return ""
	}
	return name
}

func davAddressObject(o Object) (carddav.AddressObject, error) {
	card, err := vcard.NewDecoder(bytes.NewReader(o.Data)).Decode()
	if err != nil {
		return carddav.AddressObject{}, err
	}
	return carddav.AddressObject{
		Path:          davBook.Path + davObjectName(o, ".vcf"),
		ModTime:       o.Modified,
		ContentLength: int64(len(o.Data)),
		ETag:          davETag(o.Data),
		Card:          card,
	}, nil
}

func (b davCardBackend) objects(ctx context.Context) ([]Object, error) {
	var objs []Object
	err := davFrom(ctx).withStore(ctx, b.s.dial, func(st Mailstore) error {
		var err error
		objs, err = st.Objects(ctx, CollContacts)
		return err
	})
	return objs, err
}

func (b davCardBackend) GetAddressObject(ctx context.Context, p string, _ *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	name := davCardName(p)
	if name == "" {
		return nil, davNotFound("contact")
	}
	objs, err := b.objects(ctx)
	if err != nil {
		return nil, err
	}
	o := findDAVObject(objs, name, ".vcf")
	if o == nil {
		return nil, davNotFound("contact")
	}
	ao, err := davAddressObject(*o)
	if err != nil {
		return nil, err
	}
	return &ao, nil
}

func (b davCardBackend) ListAddressObjects(ctx context.Context, p string, _ *carddav.AddressDataRequest) ([]carddav.AddressObject, error) {
	if p != davBook.Path && p+"/" != davBook.Path {
		return nil, davNotFound("address book")
	}
	objs, err := b.objects(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]carddav.AddressObject, 0, len(objs))
	for _, o := range objs {
		ao, err := davAddressObject(o)
		if err != nil {
			continue
		}
		out = append(out, ao)
	}
	return out, nil
}

func (b davCardBackend) QueryAddressObjects(ctx context.Context, p string, query *carddav.AddressBookQuery) ([]carddav.AddressObject, error) {
	all, err := b.ListAddressObjects(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	// An empty filter matches every card (RFC 6352 10.5), but the library
	// ORs zero filters to "no match", which would show clients an empty
	// address book.
	if query != nil && len(query.PropFilters) == 0 {
		if query.Limit > 0 && query.Limit < len(all) {
			all = all[:query.Limit]
		}
		return all, nil
	}
	return carddav.Filter(query, all)
}

func (b davCardBackend) PutAddressObject(ctx context.Context, p string, card vcard.Card, opts *carddav.PutAddressObjectOptions) (*carddav.AddressObject, error) {
	name := davCardName(p)
	if name == "" {
		return nil, davNotFound("address book")
	}
	if !validDAVName(name) {
		return nil, webdav.NewHTTPError(http.StatusBadRequest, errors.New("webmail: unsupported resource name"))
	}
	uid := strings.TrimSpace(card.Value(vcard.FieldUID))
	if uid == "" {
		return nil, carddav.NewPreconditionError(carddav.PreconditionValidAddressData)
	}
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(card); err != nil {
		return nil, carddav.NewPreconditionError(carddav.PreconditionValidAddressData)
	}
	data := buf.Bytes()
	if len(data) > davMaxObjectSize {
		return nil, carddav.NewPreconditionError(carddav.PreconditionMaxResourceSize)
	}
	obj := Object{ID: objectID(uid), Title: card.PreferredValue(vcard.FieldFormattedName), ContentType: "text/vcard", Data: data}
	if err := davPut(ctx, davContactStore(ctx, b.s), davNoGuard, CollContacts, &obj, name, ".vcf", opts.IfMatch, opts.IfNoneMatch, carddav.NewPreconditionError(carddav.PreconditionNoUIDConflict)); err != nil {
		return nil, err
	}
	ao, err := davAddressObject(obj)
	if err != nil {
		return nil, err
	}
	ao.ModTime = b.s.now()
	return &ao, nil
}

func (b davCardBackend) DeleteAddressObject(ctx context.Context, p string) error {
	name := davCardName(p)
	if name == "" {
		return davNotFound("contact")
	}
	return davDelete(ctx, davContactStore(ctx, b.s), davNoGuard, CollContacts, name, ".vcf")
}
