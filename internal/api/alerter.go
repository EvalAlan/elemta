package api

import "time"

// alerter decides which changes in a problem's level are worth an email:
// getting worse at once, again each day it lasts, and once when it clears.
// It is in-memory, so a restart during a problem sends one more alert, which
// is a reminder rather than noise.
type alerter struct {
	level int // 0 none, 1 warning, 2 critical
	sent  time.Time
}

const alertRepeat = 24 * time.Hour

func (a *alerter) observe(level int, now time.Time) (send, recovered bool) {
	switch {
	case level == 0 && a.level > 0:
		a.level, a.sent = 0, time.Time{}
		return true, true
	case level == 0:
		return false, false
	case level > a.level || now.Sub(a.sent) >= alertRepeat:
		a.level, a.sent = level, now
		return true, false
	}
	// Better than before but still bad: remember the lower level so a
	// relapse is reported, without sending anything now.
	a.level = level
	return false, false
}
