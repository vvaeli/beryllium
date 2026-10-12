// Package store persists daemon state as a versioned JSON file with atomic
// writes and owner-only permissions.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Migration upgrades the "data" payload from schema version i to i+1, where
// i is the migration's index in the slice passed to Open.
type Migration func(data json.RawMessage) (json.RawMessage, error)

// Store reads and writes one JSON file holding a value of type T.
type Store[T any] struct {
	path       string
	migrations []Migration
	mu         sync.Mutex
}

type envelope struct {
	SchemaVersion int             `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
}

// Open returns a store for path. The current schema version is
// len(migrations). The file is not touched until Load or Save.
func Open[T any](path string, migrations ...Migration) *Store[T] {
	return &Store[T]{path: path, migrations: migrations}
}

// Load reads the file, migrating and rewriting it if its schema is older.
// A missing file yields the zero value of T.
func (s *Store[T]) Load() (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var v T
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return v, fmt.Errorf("store %s: %w", filepath.Base(s.path), err)
	}
	current := len(s.migrations)
	if env.SchemaVersion > current {
		return v, fmt.Errorf("store %s: schema version %d is newer than supported %d (downgrade?)",
			filepath.Base(s.path), env.SchemaVersion, current)
	}
	data := env.Data
	for i := env.SchemaVersion; i < current; i++ {
		if data, err = s.migrations[i](data); err != nil {
			return v, fmt.Errorf("store %s: migration %d→%d: %w", filepath.Base(s.path), i, i+1, err)
		}
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &v); err != nil {
			return v, fmt.Errorf("store %s: %w", filepath.Base(s.path), err)
		}
	}
	if env.SchemaVersion < current {
		if err := s.write(data); err != nil {
			return v, err
		}
	}
	return v, nil
}

// Save atomically replaces the file with v.
func (s *Store[T]) Save(v T) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(data)
}

func (s *Store[T]) write(data json.RawMessage) error {
	raw, err := json.MarshalIndent(envelope{SchemaVersion: len(s.migrations), Data: data}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
