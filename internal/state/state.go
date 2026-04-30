// Package state provides persistent storage for traffic-guard configuration.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	configFile = "config.json"
	dirMode    = 0755
	fileMode   = 0644
)

// configDir is the directory for the state file.
// Exposed as a variable so tests can override it with t.TempDir().
var configDir = "/etc/traffic-guard"

// ErrNotFound indicates the state file does not exist.
var ErrNotFound = errors.New("state file not found")

// Config is the persisted traffic-guard configuration.
type Config struct {
	URLs           []string  `json:"urls"`
	EnableLogging  bool      `json:"enable_logging"`
	AutoUpdate     bool      `json:"auto_update"`
	UpdateInterval string    `json:"update_interval,omitempty"`
	LastUpdate     time.Time `json:"last_update,omitempty"`
}

// Path returns the absolute path to the state file.
func Path() string {
	return filepath.Join(configDir, configFile)
}

// Load reads the state file. Returns ErrNotFound if the file does not exist.
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read state: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return &cfg, nil
}

// Save atomically writes the configuration to the state file.
func Save(cfg *Config) error {
	if err := os.MkdirAll(configDir, dirMode); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := Path()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, fileMode); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// Remove deletes the state file. Returns nil if the file does not exist.
func Remove() error {
	if err := os.Remove(Path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RemoveDir removes the state directory if it is empty.
func RemoveDir() error {
	if err := os.Remove(configDir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
