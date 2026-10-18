package webmail

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
)

const phoneCard = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card-9\r\nFN:Ana Lima\r\nN:Lima;Ana;;;\r\n" +
	"EMAIL;TYPE=INTERNET,WORK,pref:ana@work.example\r\n" +
	"ADR;TYPE=HOME:;;1 Rua Augusta;Lisboa;;1100-048;Portugal\r\n" +
	"PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQ==\r\n" +
	"X-SOCIALPROFILE;TYPE=mastodon:https://social.example/@ana\r\nEND:VCARD\r\n"

func TestEditContactKeepsWhatTheWebmailDoesntShow(t *testing.T) {
	old, err := vcard.NewDecoder(strings.NewReader(phoneCard)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	c := cardToContact(old)
	c.ID = "card-9"
	c.Notes = "Met at the conference"
	var buf bytes.Buffer
	if err := vcard.NewEncoder(&buf).Encode(mergeCard(old, c)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"VERSION:3.0", "PHOTO", "X-SOCIALPROFILE", "1 Rua Augusta;Lisboa", "pref", "NOTE:Met at the conference"} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q:\n%s", want, out)
		}
	}
	// A field the user changed is written from the webmail's model.
	c.Address = "2 Praça do Comércio"
	buf.Reset()
	_ = vcard.NewEncoder(&buf).Encode(mergeCard(old, c))
	if out := buf.String(); strings.Contains(out, "Rua Augusta") || !strings.Contains(out, "Praça do Comércio") {
		t.Errorf("changed address not written:\n%s", out)
	}
}

const phoneTask = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Phone//EN\r\nBEGIN:VTODO\r\nUID:todo-9\r\nDTSTAMP:20261001T000000Z\r\n" +
	"SUMMARY:Pay rent\r\nDUE:20261101T170000Z\r\nRRULE:FREQ=MONTHLY\r\nCATEGORIES:Home\r\n" +
	"BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Pay rent\r\nTRIGGER:-PT1H\r\nEND:VALARM\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"

func TestEditTaskKeepsWhatTheWebmailDoesntShow(t *testing.T) {
	cal, err := ical.NewDecoder(strings.NewReader(phoneTask)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	task, ok := taskFromComponent(cal.Children[0], time.UTC)
	if !ok {
		t.Fatal("task not read")
	}
	task.Done = true
	data, err := mergeTask(cal, task, time.UTC, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, want := range []string{"STATUS:COMPLETED", "RRULE:FREQ=MONTHLY", "BEGIN:VALARM", "DUE:20261101T170000Z", "CATEGORIES:Home"} {
		if !strings.Contains(out, want) {
			t.Errorf("lost %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "BEGIN:VTODO") != 1 {
		t.Errorf("task duplicated:\n%s", out)
	}
}
