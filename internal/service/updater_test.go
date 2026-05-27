package service

import (
	"strings"
	"testing"
	"time"
)

func TestParseInterval(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"hours", "24h", 24 * time.Hour, false},
		{"minutes", "30m", 30 * time.Minute, false},
		{"seconds", "90s", 90 * time.Second, false},
		{"days", "7d", 7 * 24 * time.Hour, false},
		{"one day", "1d", 24 * time.Hour, false},
		{"fractional hours", "1h30m", 90 * time.Minute, false},

		{"empty string", "", 0, true},
		{"zero duration", "0h", 0, true},
		{"negative", "-1h", 0, true},
		{"zero days", "0d", 0, true},
		{"negative days", "-3d", 0, true},
		{"invalid suffix", "5w", 0, true},
		{"not a number + d", "abcd", 0, true},
		{"bare number", "60", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseInterval(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFormatDurationForSystemd(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{24 * time.Hour, "1d"},
		{time.Hour, "1h"},
		{30 * time.Minute, "30min"},
		{time.Minute, "1min"},
		{90 * time.Second, "90s"},
		{7 * 24 * time.Hour, "7d"},
	}

	for _, tc := range tests {
		t.Run(tc.input.String(), func(t *testing.T) {
			got := FormatDurationForSystemd(tc.input)
			if got != tc.want {
				t.Errorf("FormatDurationForSystemd(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFormatDurationForSystemdPanicsOnSubSecond(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for sub-second duration, but did not panic")
		}
	}()
	FormatDurationForSystemd(500 * time.Millisecond)
}

// TestUpdateTimerTemplatePlaceholder ensures the {interval} placeholder is
// present so that updater.Setup can replace it at runtime. If the placeholder
// is accidentally removed or renamed, this test will catch it.
func TestUpdateTimerTemplatePlaceholder(t *testing.T) {
	if !strings.Contains(UpdateTimerTemplate, "{interval}") {
		t.Error("UpdateTimerTemplate does not contain {interval} placeholder; updater.Setup will write a broken timer file")
	}
}
