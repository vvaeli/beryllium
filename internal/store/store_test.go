package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type stateV1 struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestMissingFileYieldsZero(t *testing.T) {
	s := Open[stateV1](filepath.Join(t.TempDir(), "state.json"))
	v, err := s.Load()
	if err != nil || v != (stateV1{}) {
		t.Fatalf("Load() = %+v, %v; want zero value, nil", v, err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	s := Open[stateV1](path)
	want := stateV1{Name: "a", Count: 3}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := Open[stateV1](path).Load()
	if err != nil || got != want {
		t.Fatalf("Load() = %+v, %v; want %+v", got, err, want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file mode = %o, want 600", perm)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	// Version 0 stored "title" instead of "name".
	old := `{"schema_version":0,"data":{"title":"x","count":1}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	renameTitle := func(data json.RawMessage) (json.RawMessage, error) {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		m["name"] = m["title"]
		delete(m, "title")
		return json.Marshal(m)
	}

	got, err := Open[stateV1](path, renameTitle).Load()
	if err != nil || got != (stateV1{Name: "x", Count: 1}) {
		t.Fatalf("Load() = %+v, %v", got, err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("file was not rewritten at the new schema version:\n%s", raw)
	}
}

func TestNewerSchemaRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":5,"data":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open[stateV1](path).Load(); err == nil {
		t.Fatal("Load() of a newer schema succeeded; want error")
	}
}
