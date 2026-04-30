package service

import (
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
		{24 * time.Hour, "24h"},
		{time.Hour, "1h"},
		{30 * time.Minute, "30min"},
		{time.Minute, "1min"},
		{90 * time.Second, "90s"},
		{7 * 24 * time.Hour, "168h"},
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
