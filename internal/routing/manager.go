package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vvaeli/beryllium/internal/store"
)

// Source of a profile.
type Source string

// Profile sources.
const (
	SourceBuiltin      Source = "builtin"
	SourceSubscription Source = "subscription"
	SourceImported     Source = "imported"
)

// GeoState of a profile's geo files.
type GeoState string

// Geo states.
const (
	GeoNotNeeded   GeoState = "not_needed"
	GeoDownloading GeoState = "downloading"
	GeoReady       GeoState = "ready"
	GeoFailed      GeoState = "failed"
)

// ErrNotFound is returned for unknown profile IDs.
var ErrNotFound = errors.New("routing profile not found")

// Record is a stored profile.
type Record struct {
	ID             string   `json:"id"`
	Source         Source   `json:"source"`
	SubscriptionID string   `json:"subscription_id,omitempty"`
	Profile        Profile  `json:"profile"`
	GeoState       GeoState `json:"geo_state"`
	LastError      string   `json:"last_error,omitempty"`
	// PendingActivate: activate once the geo files are downloaded.
	PendingActivate bool `json:"pending_activate,omitempty"`
}

// State is the persisted profile list. Builtin profiles are stored too so
// their geo state survives restarts; their content always comes from code.
type State struct {
	Profiles []*Record `json:"profiles"`
	Active   string    `json:"active"`
}

// Manager owns routing profiles and their geo files.
type Manager struct {
	store *store.Store[State]
	geo   *GeoCache
	log   *slog.Logger
	// OnChange is called (outside the lock) when the active profile or its
	// geo data changes, so a running connection can be reconfigured.
	OnChange func()

	mu      sync.Mutex
	state   State
	bg      context.Context
	running map[string]bool // profile IDs with a geo download in flight
}

// NewManager loads profiles and adds the builtin ones.
func NewManager(st *store.Store[State], geo *GeoCache, log *slog.Logger) (*Manager, error) {
	state, err := st.Load()
	if err != nil {
		return nil, err
	}
	m := &Manager{store: st, geo: geo, log: log, state: state, bg: context.Background(), running: map[string]bool{}}
	for _, b := range Builtins() {
		if r := m.find(b.ID); r != nil {
			r.Profile, r.Source = b.Profile, SourceBuiltin
		} else {
			b.GeoState = m.initialGeoState(&b.Profile)
			m.state.Profiles = append(m.state.Profiles, &b)
		}
	}
	if m.find(m.state.Active) == nil {
		m.state.Active = BuiltinProxyAll
	}
	for _, r := range m.state.Profiles {
		if r.GeoState == GeoDownloading || (r.GeoState == GeoReady && !m.geoCached(&r.Profile)) {
			r.GeoState = m.initialGeoState(&r.Profile)
		}
	}
	return m, m.save()
}

func (m *Manager) initialGeoState(p *Profile) GeoState {
	switch {
	case !needsGeo(p):
		return GeoNotNeeded
	case m.geoCached(p):
		return GeoReady
	default:
		return GeoFailed // not downloaded yet; Run or Activate fetches it
	}
}

func needsGeo(p *Profile) bool {
	s, i := p.GeoTags()
	return (len(s) > 0 && p.GeoSiteURL != "") || (len(i) > 0 && p.GeoIPURL != "")
}

func (m *Manager) geoCached(p *Profile) bool {
	s, i := p.GeoTags()
	if len(s) > 0 && p.GeoSiteURL != "" && !m.geo.Cached(p.GeoSiteURL) {
		return false
	}
	if len(i) > 0 && p.GeoIPURL != "" && !m.geo.Cached(p.GeoIPURL) {
		return false
	}
	return true
}

// Run downloads missing geo files for the active profile and checks all
// geo files daily, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.bg = ctx
	for _, r := range m.state.Profiles {
		if (r.ID == m.state.Active && r.GeoState == GeoFailed) || r.PendingActivate {
			m.startGeo(r, false)
		}
	}
	m.mu.Unlock()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			for _, r := range m.state.Profiles {
				if r.GeoState != GeoNotNeeded && (r.ID == m.state.Active || r.GeoState == GeoReady) {
					m.startGeo(r, false)
				}
			}
			m.mu.Unlock()
		}
	}
}

// List returns copies of all profiles and the active ID.
func (m *Manager) List() ([]Record, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.state.Profiles))
	for i, r := range m.state.Profiles {
		out[i] = *r
	}
	return out, m.state.Active
}

// Get returns one profile and whether it is active.
func (m *Manager) Get(id string) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(id)
	if r == nil {
		return Record{}, false, ErrNotFound
	}
	return *r, m.state.Active == r.ID, nil
}

// ProfileID is stable for a name, so updates replace the stored profile.
func ProfileID(name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return hex.EncodeToString(h[:5])
}

// Import adds or updates a profile from a deeplink, base64, JSON or an
// http(s) URL serving one of those. It is activated per the link (onadd at
// once, add after the geo download) unless activate is false.
// A profile with the same name is replaced only if its LastUpdated is
// newer (or either has none).
func (m *Manager) Import(ctx context.Context, src string, activate *bool, source Source, subID string) (Record, error) {
	src = strings.TrimSpace(src)
	if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
		body, err := m.fetchProfile(ctx, src)
		if err != nil {
			return Record{}, err
		}
		src = strings.TrimSpace(string(body))
	}
	dec, err := Decode(src)
	if err != nil {
		return Record{}, err
	}
	act := activate == nil || *activate
	p := dec.Profile

	m.mu.Lock()
	id := ProfileID(p.Name)
	r := m.find(id)
	changed := true
	switch {
	case r == nil:
		r = &Record{ID: id}
		m.state.Profiles = append(m.state.Profiles, r)
	case !p.LastUpdated.IsZero() && !r.Profile.LastUpdated.IsZero() && !p.LastUpdated.After(r.Profile.LastUpdated):
		changed = false
	}
	if changed {
		r.Profile, r.Source, r.SubscriptionID, r.LastError = *p, source, subID, ""
		r.GeoState = m.initialGeoState(p)
	}
	var wasActive bool
	if changed {
		if r.GeoState != GeoNotNeeded {
			m.startGeo(r, !p.LastUpdated.IsZero())
		}
		if act {
			wasActive = m.activate(r, dec.Immediate)
		}
	}
	if err := m.save(); err != nil {
		m.mu.Unlock()
		return Record{}, err
	}
	out := *r
	active := m.state.Active == r.ID
	m.mu.Unlock()
	if changed {
		m.log.Info("routing profile imported", "id", id, "name", p.Name, "source", source, "active", active)
	}
	if changed && (active || wasActive) {
		m.changed()
	}
	return out, nil
}

// ImportFromSubscription applies the provider's profile (the `routing`
// header or a routing line); errors are only logged.
func (m *Manager) ImportFromSubscription(ctx context.Context, subID, raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	if _, err := m.Import(ctx, raw, nil, SourceSubscription, subID); err != nil {
		m.log.Warn("provider routing profile rejected", "subscription", subID, "err", err)
	}
}

// Activate makes id the active profile. If its geo files are not ready it
// becomes active once they are downloaded.
func (m *Manager) Activate(id string) (Record, error) {
	m.mu.Lock()
	r := m.find(id)
	if r == nil {
		m.mu.Unlock()
		return Record{}, ErrNotFound
	}
	now := m.activate(r, false)
	err := m.save()
	out := *r
	m.mu.Unlock()
	if now {
		m.changed()
	}
	return out, err
}

// activate switches now when no download is needed or immediate is set,
// otherwise marks the profile pending and starts the download. Reports
// whether the active profile changed now.
func (m *Manager) activate(r *Record, immediate bool) bool {
	if immediate || r.GeoState == GeoNotNeeded || r.GeoState == GeoReady {
		r.PendingActivate = false
		changed := m.state.Active != r.ID
		m.state.Active = r.ID
		return changed
	}
	r.PendingActivate = true
	m.startGeo(r, false)
	return false
}

// Remove deletes an imported or provider profile. Removing the active one
// falls back to proxying everything.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	i := slices.IndexFunc(m.state.Profiles, func(r *Record) bool { return r.ID == id })
	if i < 0 {
		m.mu.Unlock()
		return ErrNotFound
	}
	if m.state.Profiles[i].Source == SourceBuiltin {
		m.mu.Unlock()
		return errors.New("builtin profiles can't be removed")
	}
	m.state.Profiles = slices.Delete(m.state.Profiles, i, i+1)
	wasActive := m.state.Active == id
	if wasActive {
		m.state.Active = BuiltinProxyAll
	}
	err := m.save()
	m.mu.Unlock()
	if wasActive {
		m.changed()
	}
	return err
}

// RefreshGeo re-checks the profile's geo files now and waits for the result.
func (m *Manager) RefreshGeo(ctx context.Context, id string) (Record, error) {
	m.mu.Lock()
	r := m.find(id)
	if r == nil {
		m.mu.Unlock()
		return Record{}, ErrNotFound
	}
	p := r.Profile
	m.mu.Unlock()
	if !needsGeo(&p) {
		return m.getRecord(id)
	}
	err := m.downloadGeo(ctx, id, p, true)
	rec, gerr := m.getRecord(id)
	if gerr != nil {
		return rec, gerr
	}
	return rec, err
}

func (m *Manager) getRecord(id string) (Record, error) {
	r, _, err := m.Get(id)
	return r, err
}

// startGeo downloads in the background; m.mu must be held.
func (m *Manager) startGeo(r *Record, force bool) {
	if m.running[r.ID] || !needsGeo(&r.Profile) {
		return
	}
	m.running[r.ID] = true
	r.GeoState = GeoDownloading
	id, p, ctx := r.ID, r.Profile, m.bg
	go func() {
		_ = m.downloadGeo(ctx, id, p, force)
	}()
}

// downloadGeo fetches both files of p and records the outcome on id.
func (m *Manager) downloadGeo(ctx context.Context, id string, p Profile, force bool) error {
	m.mu.Lock()
	m.running[id] = true
	if r := m.find(id); r != nil {
		r.GeoState = GeoDownloading
	}
	m.mu.Unlock()

	sites, ips := p.GeoTags()
	var changed bool
	var errs []error
	for _, f := range []struct {
		url  string
		used bool
	}{{p.GeoSiteURL, len(sites) > 0}, {p.GeoIPURL, len(ips) > 0}} {
		if !f.used || f.url == "" {
			continue
		}
		c, err := m.geo.Ensure(ctx, f.url, p.LastUpdated, force)
		changed = changed || c
		if err != nil {
			errs = append(errs, err)
		}
	}
	err := errors.Join(errs...)

	m.mu.Lock()
	delete(m.running, id)
	r := m.find(id)
	if r == nil || r.Profile.Name != p.Name {
		m.mu.Unlock()
		return err
	}
	notify := false
	switch {
	case err == nil:
		r.GeoState, r.LastError = GeoReady, ""
		if r.PendingActivate {
			notify = m.activate(r, false)
		}
		notify = notify || (changed && m.state.Active == id)
	case m.geoCached(&r.Profile):
		// Keep working with the previous files, but show the error.
		r.GeoState, r.LastError = GeoReady, err.Error()
	default:
		r.GeoState, r.LastError = GeoFailed, err.Error()
	}
	_ = m.save()
	m.mu.Unlock()
	if err != nil {
		m.log.Warn("geo data download failed", "profile", p.Name, "err", err)
	} else if changed {
		m.log.Info("geo data updated", "profile", p.Name)
	}
	if notify {
		m.changed()
	}
	return err
}

// Active returns the active profile with the local paths of its geo files
// (empty when not downloaded).
func (m *Manager) Active() (Record, string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(m.state.Active)
	if r == nil {
		return Record{}, "", ""
	}
	var site, ip string
	if u := r.Profile.GeoSiteURL; u != "" && m.geo.Cached(u) {
		site = m.geo.Path(u)
	}
	if u := r.Profile.GeoIPURL; u != "" && m.geo.Cached(u) {
		ip = m.geo.Path(u)
	}
	return *r, site, ip
}

func (m *Manager) fetchProfile(ctx context.Context, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := m.geo.get(ctx, rawURL, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("download routing profile from %s: %w", host(rawURL), unwrapURL(err))
	}
	return body, nil
}

func unwrapURL(err error) error {
	if u := errors.Unwrap(err); u != nil && strings.HasPrefix(err.Error(), "Get ") {
		return u
	}
	return err
}

func (m *Manager) changed() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

func (m *Manager) find(id string) *Record {
	for _, r := range m.state.Profiles {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (m *Manager) save() error { return m.store.Save(m.state) }
