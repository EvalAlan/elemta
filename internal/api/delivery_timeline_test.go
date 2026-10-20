package api

import (
	"testing"
	"time"
)

func TestGroupDaysIntoWeeksAndMonths(t *testing.T) {
	var days []HourlyStatsData
	start := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC) // a Monday
	for i := 0; i < 21; i++ {
		days = append(days, HourlyStatsData{Hour: start.AddDate(0, 0, i).Format("2006-01-02"), Delivered: 1, Failed: int64(i % 2)})
	}
	monday := func(d time.Time) time.Time { return d.AddDate(0, 0, -((int(d.Weekday()) + 6) % 7)) }
	weeks := groupDays(days, monday, 2)
	if len(weeks) != 2 || weeks[0].Label != "2026-10-05" || weeks[1].Label != "2026-10-12" || weeks[1].Delivered != 7 {
		t.Fatalf("weeks = %+v", weeks)
	}
	month := func(d time.Time) time.Time { return time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC) }
	months := groupDays(days, month, 12)
	if len(months) != 2 || months[0].Label != "2026-09-01" || months[0].Delivered != 3 || months[1].Label != "2026-10-01" || months[1].Delivered != 18 {
		t.Fatalf("months = %+v", months)
	}
}
