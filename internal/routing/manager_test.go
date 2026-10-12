package routing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vvaeli/beryllium/internal/store"
)

// geoServer serves /geosite.dat and /geoip.dat, optionally with .sha256.
type geoServer struct {
	*httptest.Server
	mu        sync.Mutex
	files     map[string][]byte
	sums      bool
	downloads atomic.Int32
	gate      chan struct{} // when set, .dat downloads wait on it
}

func newGeoServer(t *testing.T) *geoServer {
	g := &geoServer{files: map[string][]byte{
		"/geosite.dat": geoSiteDat(testSites),
		"/geoip.dat":   geoIPDat(testIPs),
	}}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		name, sum := strings.CutSuffix(r.URL.Path, ".sha256")
		data, ok := g.files[name]
		sums, gate := g.sums, g.gate
		g.mu.Unlock()
		switch {
		case !ok || (sum && !sums):
			http.NotFound(w, r)
		case sum:
			h := sha256.Sum256(data)
			io.WriteString(w, hex.EncodeToString(h[:])+"  "+name+"\n")
		default:
			if gate != nil {
				<-gate
			}
			g.downloads.Add(1)
			w.Write(data)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func TestGeoCache(t *testing.T) {
	g := newGeoServer(t)
	c := &GeoCache{Dir: t.TempDir()}
	ctx := context.Background()
	u := g.URL + "/geosite.dat"
	t0 := time.Unix(1000, 0)

	// No .sha256: download when missing, then only when LastUpdated is newer or forced.
	if changed, err := c.Ensure(ctx, u, t0, false); err != nil || !changed || !c.Cached(u) {
		t.Fatalf("first: %v %v", changed, err)
	}
	if _, err := c.Ensure(ctx, u, t0, false); err != nil || g.downloads.Load() != 1 {
		t.Fatalf("second: %v, downloads %d", err, g.downloads.Load())
	}
	if _, err := c.Ensure(ctx, u, time.Now().Add(time.Hour), false); err != nil || g.downloads.Load() != 2 {
		t.Fatalf("newer: %v, downloads %d", err, g.downloads.Load())
	}
	if changed, err := c.Ensure(ctx, u, t0, true); err != nil || changed || g.downloads.Load() != 3 {
		t.Fatalf("forced: changed=%v %v, downloads %d", changed, err, g.downloads.Load())
	}

	// With .sha256: an unchanged file is never downloaded, even when forced.
	g.mu.Lock()
	g.sums = true
	g.mu.Unlock()
	if _, err := c.Ensure(ctx, u, time.Now().Add(time.Hour), true); err != nil || g.downloads.Load() != 3 {
		t.Fatalf("sha match: %v, downloads %d", err, g.downloads.Load())
	}
	g.mu.Lock()
	g.files["/geosite.dat"] = geoSiteDat(map[string][]siteFixture{"x": {{domainFull, "x.example", nil}}})
	g.mu.Unlock()
	if changed, err := c.Ensure(ctx, u, t0, false); err != nil || !changed || g.downloads.Load() != 4 {
		t.Fatalf("sha changed: %v %v, downloads %d", changed, err, g.downloads.Load())
	}

	if _, err := c.Ensure(ctx, g.URL+"/missing.dat", t0, false); err == nil || strings.Contains(err.Error(), "/missing") {
		t.Errorf("missing file error: %v", err)
	}
	if _, err := c.Ensure(ctx, "file:///etc/passwd", t0, false); err == nil {
		t.Error("file:// accepted")
	}
}

func newManager(t *testing.T) (*Manager, *geoServer) {
	t.Helper()
	g := newGeoServer(t)
	dir := t.TempDir()
	m, err := NewManager(store.Open[State](filepath.Join(dir, "routing.json")),
		&GeoCache{Dir: filepath.Join(dir, "geo")}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return m, g
}

func link(action, js string) string {
	return "happ://routing/" + action + "/" + base64.StdEncoding.EncodeToString([]byte(js))
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestManager(t *testing.T) {
	m, g := newManager(t)
	ctx := context.Background()
	var changes atomic.Int32
	m.OnChange = func() { changes.Add(1) }

	list, active := m.List()
	if len(list) != 3 || active != BuiltinProxyAll {
		t.Fatalf("builtins: %d, active %s", len(list), active)
	}
	if err := m.Remove(BuiltinProxyAll); err == nil {
		t.Error("builtin removed")
	}

	// onadd without geo: active at once.
	r, err := m.Import(ctx, link("onadd", `{"Name":"Plain","DirectSites":["domain:ru"],"LastUpdated":"100"}`), nil, SourceImported, "")
	if err != nil || r.GeoState != GeoNotNeeded {
		t.Fatalf("import: %+v %v", r, err)
	}
	if _, active := m.List(); active != r.ID || changes.Load() != 1 {
		t.Fatalf("active %s, changes %d", active, changes.Load())
	}
	// Same name, not newer: unchanged.
	if _, err := m.Import(ctx, link("onadd", `{"Name":"plain","DirectSites":["domain:by"],"LastUpdated":"100"}`), nil, SourceImported, ""); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := m.Get(r.ID); got.Profile.DirectSites[0] != "domain:ru" {
		t.Errorf("older profile replaced: %v", got.Profile.DirectSites)
	}
	// Newer: replaced.
	if _, err := m.Import(ctx, link("onadd", `{"Name":"Plain","DirectSites":["domain:by"],"LastUpdated":"200"}`), nil, SourceImported, ""); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := m.Get(r.ID); got.Profile.DirectSites[0] != "domain:by" {
		t.Errorf("newer profile not applied: %v", got.Profile.DirectSites)
	}

	// add with geo: becomes active only after the download.
	gate := make(chan struct{})
	g.mu.Lock()
	g.gate = gate
	g.mu.Unlock()
	geoJS := `{"Name":"Geo","DirectSites":["geosite:category-ru"],"DirectIp":["geoip:ru"],"Geositeurl":"` + g.URL + `/geosite.dat","Geoipurl":"` + g.URL + `/geoip.dat"}`
	r2, err := m.Import(ctx, link("add", geoJS), nil, SourceSubscription, "sub1")
	if err != nil || !r2.PendingActivate || r2.GeoState != GeoDownloading {
		t.Fatalf("add: %+v %v", r2, err)
	}
	if _, active := m.List(); active != r.ID {
		t.Fatal("activated before geo download")
	}
	close(gate)
	waitFor(t, func() bool { _, a := m.List(); return a == r2.ID })
	got, site, ip := m.Active()
	if got.GeoState != GeoReady || site == "" || ip == "" || got.SubscriptionID != "sub1" {
		t.Fatalf("active: %+v %q %q", got, site, ip)
	}

	// A failed refresh keeps the old files usable but records the error.
	g.mu.Lock()
	g.gate = nil
	delete(g.files, "/geoip.dat")
	g.mu.Unlock()
	got, err = m.RefreshGeo(ctx, r2.ID)
	if err == nil || got.GeoState != GeoReady || got.LastError == "" {
		t.Fatalf("refresh: %+v %v", got, err)
	}

	// Removing the active profile falls back to proxying everything.
	if err := m.Remove(r2.ID); err != nil {
		t.Fatal(err)
	}
	if _, active := m.List(); active != BuiltinProxyAll {
		t.Errorf("active after remove: %s", active)
	}

	// State survives a restart.
	m2, err := NewManager(m.store, m.geo, m.log)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := m2.List(); len(l) != 4 {
		t.Errorf("reloaded %d profiles", len(l))
	}

	if _, err := m.Import(ctx, "happ://routing/onadd/!!!", nil, SourceImported, ""); err == nil {
		t.Error("bad link imported")
	}
	if _, err := m.Activate("nope"); err == nil {
		t.Error("unknown id activated")
	}
}

func TestImportFromURL(t *testing.T) {
	m, _ := newManager(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, link("onadd", `{"Name":"Remote"}`)+"\n")
	}))
	defer srv.Close()
	r, err := m.Import(context.Background(), srv.URL+"/profile", nil, SourceImported, "")
	if err != nil || r.Profile.Name != "Remote" {
		t.Fatalf("%+v %v", r, err)
	}
}
