package state

import (
	"errors"
	"testing"
	"time"
)

// setDir overrides configDir for the duration of a test.
func setDir(t *testing.T, dir string) {
	t.Helper()
	orig := configDir
	configDir = dir
	t.Cleanup(func() { configDir = orig })
}

func TestLoadNotFound(t *testing.T) {
	setDir(t, t.TempDir())

	_, err := Load()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	setDir(t, t.TempDir())

	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	in := &Config{
		URLs:           []string{"https://example.com/list1.txt", "https://example.com/list2.txt"},
		EnableLogging:  true,
		AutoUpdate:     true,
		UpdateInterval: "12h",
		LastUpdate:     ts,
	}

	if err := Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(out.URLs) != len(in.URLs) {
		t.Errorf("URLs len: got %d, want %d", len(out.URLs), len(in.URLs))
	}
	for i, u := range in.URLs {
		if out.URLs[i] != u {
			t.Errorf("URLs[%d]: got %q, want %q", i, out.URLs[i], u)
		}
	}
	if out.EnableLogging != in.EnableLogging {
		t.Errorf("EnableLogging: got %v, want %v", out.EnableLogging, in.EnableLogging)
	}
	if out.AutoUpdate != in.AutoUpdate {
		t.Errorf("AutoUpdate: got %v, want %v", out.AutoUpdate, in.AutoUpdate)
	}
	if out.UpdateInterval != in.UpdateInterval {
		t.Errorf("UpdateInterval: got %q, want %q", out.UpdateInterval, in.UpdateInterval)
	}
	if !out.LastUpdate.Equal(in.LastUpdate) {
		t.Errorf("LastUpdate: got %v, want %v", out.LastUpdate, in.LastUpdate)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	// Save twice: second write must not corrupt the file.
	setDir(t, t.TempDir())

	first := &Config{URLs: []string{"https://first.example.com"}}
	if err := Save(first); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	second := &Config{URLs: []string{"https://second.example.com"}, AutoUpdate: true}
	if err := Save(second); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.URLs) == 0 || got.URLs[0] != "https://second.example.com" {
		t.Errorf("expected second config, got URLs=%v", got.URLs)
	}
}

func TestRemove(t *testing.T) {
	setDir(t, t.TempDir())

	if err := Save(&Config{URLs: []string{"https://example.com"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err := Load()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after Remove, got %v", err)
	}
}

func TestRemoveIdempotent(t *testing.T) {
	setDir(t, t.TempDir())

	// Remove on non-existent file must not return error.
	if err := Remove(); err != nil {
		t.Fatalf("Remove on missing file: %v", err)
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	setDir(t, dir)
	want := dir + "/config.json"
	if got := Path(); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}
