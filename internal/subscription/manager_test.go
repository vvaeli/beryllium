package subscription

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vvaeli/beryllium/internal/store"
)

type fakePanel struct {
	*httptest.Server
	body   atomic.Value // string
	status atomic.Int32
	hits   atomic.Int32
}

func newPanel(t *testing.T, body string) *fakePanel {
	p := &fakePanel{}
	p.body.Store(body)
	p.status.Store(200)
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.hits.Add(1)
		if s := int(p.status.Load()); s != 200 {
			http.Error(w, "down", s)
			return
		}
		w.Header().Set("Profile-Title", "Panel")
		w.Header().Set("Profile-Update-Interval", "1")
		w.Write([]byte(p.body.Load().(string)))
	}))
	t.Cleanup(p.Close)
	return p
}

func newManager(t *testing.T, dir string) *Manager {
	f := NewFetcher("test")
	f.Retries = 0
	m, err := NewManager(store.Open[State](filepath.Join(dir, "subscriptions.json")), f,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const twoServers = "trojan://a@a.example.com:443#A\ntrojan://b@b.example.com:443#B\n"

func TestManagerLifecycle(t *testing.T) {
	panel := newPanel(t, twoServers)
	dir := t.TempDir()
	m := newManager(t, dir)
	ctx := context.Background()

	rec, err := m.Add(ctx, "  "+panel.URL+"/sub/token\n", "")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "Panel" || len(rec.Servers) != 2 || rec.Interval() != time.Hour {
		t.Fatalf("rec = %+v", rec)
	}
	if _, err := m.Add(ctx, panel.URL+"/sub/token", ""); err == nil {
		t.Fatal("duplicate URL accepted")
	}
	ids := []string{rec.Servers[0].ID, rec.Servers[1].ID}

	// Refresh keeps IDs of unchanged servers and picks up new ones.
	panel.body.Store(twoServers + "trojan://c@c.example.com:443#C\n")
	rec, err = m.Refresh(ctx, rec.ID)
	if err != nil || len(rec.Servers) != 3 || rec.Servers[0].ID != ids[0] || rec.Servers[1].ID != ids[1] {
		t.Fatalf("refresh = %+v, %v", rec, err)
	}

	// A failing refresh keeps the last good servers.
	panel.status.Store(502)
	rec, err = m.Refresh(ctx, rec.ID)
	if err == nil || len(rec.Servers) != 3 || rec.LastError == "" {
		t.Fatalf("failed refresh = %+v, %v", rec, err)
	}

	// State survives a restart.
	m2 := newManager(t, dir)
	srv, subID, err := m2.Server(ids[0])
	if err != nil || subID != rec.ID || srv.Address != "a.example.com" {
		t.Fatalf("after reload: %+v %s %v", srv, subID, err)
	}

	zero := time.Duration(0)
	newName := "Mine"
	if rec, err = m2.Update(rec.ID, &newName, &zero); err != nil || rec.Name != "Mine" || rec.Interval() != 0 {
		t.Fatalf("update = %+v, %v", rec, err)
	}
	if err := m2.Remove(rec.ID); err != nil || len(m2.List()) != 0 {
		t.Fatalf("remove: %v", err)
	}
}

func TestManagerAddFailureStoresNothing(t *testing.T) {
	panel := newPanel(t, "not a subscription")
	m := newManager(t, t.TempDir())
	if _, err := m.Add(context.Background(), panel.URL, ""); err == nil {
		t.Fatal("garbage subscription accepted")
	}
	if len(m.List()) != 0 {
		t.Fatal("failed add was stored")
	}
}

func TestManagerAutoUpdate(t *testing.T) {
	panel := newPanel(t, twoServers)
	m := newManager(t, t.TempDir())
	now := time.Now()
	m.now = func() time.Time { return now }
	rec, err := m.Add(context.Background(), panel.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.due(); len(got) != 0 {
		t.Fatalf("due right after add: %v", got)
	}
	now = now.Add(2 * time.Hour) // provider interval is 1h
	if got := m.due(); len(got) != 1 || got[0] != rec.ID {
		t.Fatalf("due = %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	before := panel.hits.Load()
	done := make(chan struct{})
	go func() { m.Run(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for panel.hits.Load() == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if panel.hits.Load() == before {
		t.Fatal("auto-update did not refresh a due subscription")
	}
}

func TestImportLocal(t *testing.T) {
	m := newManager(t, t.TempDir())
	rec, err := m.Import([]byte("hy2://p@h.example.com:443#Solo"), "", "")
	if err != nil || rec.Kind != KindLocal || rec.Name != "Solo" || rec.Interval() != 0 {
		t.Fatalf("import = %+v, %v", rec, err)
	}
	if _, err := m.Refresh(context.Background(), rec.ID); err == nil {
		t.Fatal("refresh of a local subscription succeeded")
	}
}
