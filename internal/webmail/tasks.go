package webmail

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

// Task is a to-do item, stored as an iCalendar VTODO, the format every
// task app that syncs with a calendar server uses.
type Task struct {
	UID       string
	Summary   string
	Notes     string
	Due       time.Time // a day; zero for no due date
	Priority  string    // high, normal or low
	Done      bool
	Completed time.Time
	List      string
	Created   time.Time
}

const defaultTaskList = "Tasks"

// Overdue reports whether an open task's due day has passed.
func (t Task) Overdue(today time.Time) bool {
	return !t.Done && !t.Due.IsZero() && t.Due.Before(today)
}

// iCalendar priorities: 1-4 high, 5 normal, 6-9 low, 0 undefined.
func priorityToICal(p string) string {
	switch p {
	case "high":
		return "1"
	case "low":
		return "9"
	}
	return "5"
}

func priorityFromICal(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	switch {
	case err != nil || n == 0 || n == 5:
		return "normal"
	case n < 5:
		return "high"
	default:
		return "low"
	}
}

func (t Task) toComponent(now time.Time) *ical.Component {
	c := ical.NewComponent(ical.CompToDo)
	p := c.Props
	p.SetText(ical.PropUID, t.UID)
	p.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	if !t.Created.IsZero() {
		p.SetDateTime(ical.PropCreated, t.Created.UTC())
	}
	p.SetText(ical.PropSummary, t.Summary)
	if t.Notes != "" {
		p.SetText(ical.PropDescription, t.Notes)
	}
	if !t.Due.IsZero() {
		p.SetDate(ical.PropDue, t.Due)
	}
	p.SetText(ical.PropPriority, priorityToICal(t.Priority))
	if t.Done {
		p.SetText(ical.PropStatus, "COMPLETED")
		p.SetText(ical.PropPercentComplete, "100")
		if !t.Completed.IsZero() {
			p.SetDateTime(ical.PropCompleted, t.Completed.UTC())
		}
	} else {
		p.SetText(ical.PropStatus, "NEEDS-ACTION")
	}
	if t.List != "" && t.List != defaultTaskList {
		p.SetText("X-ELEMTA-LIST", t.List)
	}
	return c
}

func taskFromComponent(c *ical.Component, loc *time.Location) (Task, bool) {
	t := Task{Priority: "normal", List: defaultTaskList}
	text := func(name string) string {
		if p := c.Props.Get(name); p != nil {
			if s, err := p.Text(); err == nil {
				return s
			}
			return p.Value
		}
		return ""
	}
	t.UID = text(ical.PropUID)
	if t.UID == "" {
		return t, false
	}
	t.Summary = text(ical.PropSummary)
	t.Notes = text(ical.PropDescription)
	if p := c.Props.Get(ical.PropDue); p != nil {
		if d, _, err := propTime(p, loc); err == nil {
			t.Due = dayStart(d.In(loc))
		}
	}
	if p := c.Props.Get(ical.PropPriority); p != nil {
		t.Priority = priorityFromICal(p.Value)
	}
	t.Done = strings.EqualFold(text(ical.PropStatus), "COMPLETED") || c.Props.Get(ical.PropCompleted) != nil
	if p := c.Props.Get(ical.PropCompleted); p != nil {
		t.Completed, _, _ = propTime(p, time.UTC)
	}
	if p := c.Props.Get(ical.PropCreated); p != nil {
		t.Created, _, _ = propTime(p, time.UTC)
	}
	if l := text("X-ELEMTA-LIST"); l != "" {
		t.List = l
	} else if p := c.Props.Get(ical.PropCategories); p != nil {
		if l, err := p.TextList(); err == nil && len(l) > 0 && l[0] != "" {
			t.List = l[0]
		}
	}
	return t, true
}

func (s *Server) tasks(ctx context.Context, sess *Session, loc *time.Location) ([]Task, error) {
	var out []Task
	err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		objs, err := st.Objects(ctx, CollTasks)
		if err != nil {
			return err
		}
		for _, o := range objs {
			cal, err := ical.NewDecoder(bytes.NewReader(o.Data)).Decode()
			if err != nil {
				continue
			}
			for _, c := range cal.Children {
				if c.Name != ical.CompToDo {
					continue
				}
				if t, ok := taskFromComponent(c, loc); ok {
					out = append(out, t)
				}
			}
		}
		return nil
	})
	return out, err
}

func (s *Server) putTask(ctx context.Context, sess *Session, t Task) error {
	data, err := encodeCalendar("", s.now(), t.toComponent(s.now()))
	if err != nil {
		return err
	}
	return s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
		return st.PutObject(ctx, CollTasks, Object{ID: t.UID, Title: t.Summary, ContentType: "text/calendar", Data: data})
	})
}

type tasksView struct {
	All      []Task
	Shown    []Task
	Lists    []string
	List     string
	Show     string // open, done or all
	Today    time.Time
	Selected *Task
	Edit     bool
	Counts   map[string]int
}

// sortTasks puts open tasks first, then by due day (undated last), then
// priority, then title.
func sortTasks(list []Task) {
	rank := map[string]int{"high": 0, "normal": 1, "low": 2}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Done != b.Done {
			return !a.Done
		}
		if a.Done {
			return a.Completed.After(b.Completed)
		}
		if a.Due.IsZero() != b.Due.IsZero() {
			return !a.Due.IsZero()
		}
		if !a.Due.Equal(b.Due) {
			return a.Due.Before(b.Due)
		}
		if rank[a.Priority] != rank[b.Priority] {
			return rank[a.Priority] < rank[b.Priority]
		}
		return strings.ToLower(a.Summary) < strings.ToLower(b.Summary)
	})
}

func tasksURL(list, show, id string, extra ...string) string {
	v := url.Values{}
	if list != "" {
		v.Set("list", list)
	}
	if show != "" && show != "open" {
		v.Set("show", show)
	}
	if id != "" {
		v.Set("id", id)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	if len(v) == 0 {
		return "/tasks"
	}
	return "/tasks?" + v.Encode()
}

func (s *Server) tasksPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	loc := s.loc(sess)
	q := r.URL.Query()
	all, err := s.tasks(r.Context(), sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	sortTasks(all)
	tv := &tasksView{All: all, List: q.Get("list"), Show: q.Get("show"), Today: dayStart(s.now().In(loc)), Counts: map[string]int{}}
	if tv.Show != "done" && tv.Show != "all" {
		tv.Show = "open"
	}
	lists := map[string]bool{defaultTaskList: true}
	for _, t := range all {
		lists[t.List] = true
		if !t.Done {
			tv.Counts[t.List]++
			tv.Counts[""]++
		}
		if tv.List != "" && t.List != tv.List {
			continue
		}
		if (tv.Show == "open" && t.Done) || (tv.Show == "done" && !t.Done) {
			continue
		}
		tv.Shown = append(tv.Shown, t)
	}
	for l := range lists {
		tv.Lists = append(tv.Lists, l)
	}
	sort.Strings(tv.Lists)
	for i := range all {
		if all[i].UID == q.Get("id") {
			tv.Selected = &all[i]
		}
	}
	tv.Edit = q.Get("edit") == "1" && tv.Selected != nil
	v := view{Title: "Tasks", Session: sess, App: "tasks", Tasks: tv, Notice: notices[q.Get("n")]}
	s.render(w, "tasks.html", http.StatusOK, v)
}

func (s *Server) tasksSubmit(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx := r.Context()
	loc := s.loc(sess)
	op := r.PostFormValue("op")
	list := r.PostFormValue("list_filter")
	show := r.PostFormValue("show")
	all, err := s.tasks(ctx, sess, loc)
	if err != nil {
		s.fail(w, r, sess, err)
		return
	}
	var cur *Task
	for i := range all {
		if all[i].UID == r.PostFormValue("id") {
			cur = &all[i]
		}
	}
	notice := "task-saved"
	switch op {
	case "add", "save":
		t := Task{UID: newObjectID() + "@" + domainOf(sess.Address), Priority: "normal", List: defaultTaskList, Created: s.now()}
		if op == "save" {
			if cur == nil {
				s.fail(w, r, sess, ErrNotFound)
				return
			}
			t = *cur
		}
		t.Summary = strings.TrimSpace(r.PostFormValue("summary"))
		if t.Summary == "" {
			s.renderProblem(w, r, sess, http.StatusBadRequest, "Give the task a title.")
			return
		}
		if len(t.Summary) > 500 {
			t.Summary = t.Summary[:500]
		}
		if op == "save" || r.PostFormValue("notes") != "" {
			t.Notes = strings.TrimSpace(normaliseText(r.PostFormValue("notes")))
		}
		t.Due = time.Time{}
		if d, err := time.ParseInLocation("2006-01-02", r.PostFormValue("due"), loc); err == nil {
			t.Due = d
		}
		switch p := r.PostFormValue("priority"); p {
		case "high", "normal", "low":
			t.Priority = p
		}
		if l := strings.TrimSpace(r.PostFormValue("list")); l != "" && len(l) <= 60 {
			t.List = l
		} else if op == "add" && list != "" {
			t.List = list
		}
		if err := s.putTask(ctx, sess, t); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		cur = &t
	case "toggle":
		if cur == nil {
			s.fail(w, r, sess, ErrNotFound)
			return
		}
		cur.Done = !cur.Done
		cur.Completed = time.Time{}
		if cur.Done {
			cur.Completed = s.now()
		}
		if err := s.putTask(ctx, sess, *cur); err != nil {
			s.fail(w, r, sess, err)
			return
		}
		http.Redirect(w, r, tasksURL(list, show, ""), http.StatusSeeOther)
		return
	case "delete":
		if cur != nil {
			if err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
				return st.DeleteObject(ctx, CollTasks, cur.UID)
			}); err != nil {
				s.fail(w, r, sess, err)
				return
			}
		}
		http.Redirect(w, r, tasksURL(list, show, "", "n", "task-deleted"), http.StatusSeeOther)
		return
	case "clear-done":
		err := s.sessions.withStore(ctx, sess, s.dial, func(st Mailstore) error {
			for _, t := range all {
				if t.Done && (list == "" || t.List == list) {
					if err := st.DeleteObject(ctx, CollTasks, t.UID); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			s.fail(w, r, sess, err)
			return
		}
		notice = "task-deleted"
	default:
		s.fail(w, r, sess, ErrNotFound)
		return
	}
	id := ""
	if op == "save" && cur != nil {
		id = cur.UID
	}
	http.Redirect(w, r, tasksURL(list, show, id, "n", notice), http.StatusSeeOther)
}
