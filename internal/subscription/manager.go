package subscription

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/vvaeli/beryllium/internal/model"
	"github.com/vvaeli/beryllium/internal/store"
)

// Kind distinguishes fetched subscriptions from imported configs.
type Kind string

// Subscription kinds.
const (
	KindRemote Kind = "remote"
	KindLocal  Kind = "local"
)

// DefaultUpdateInterval applies when neither the user nor the provider set one.
const DefaultUpdateInterval = 12 * time.Hour

// ErrNotFound is returned for unknown subscription or server IDs.
var ErrNotFound = errors.New("not found")

// Record is a stored subscription. It holds secrets (URL, credentials).
type Record struct {
	ID            string    `json:"id"`
	Kind          Kind      `json:"kind"`
	Name          string    `json:"name"`
	URL           string    `json:"url,omitempty"`
	ProviderTitle string    `json:"provider_title,omitempty"`
	SupportURL    string    `json:"support_url,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
	// UserInterval overrides the provider's interval; 0 disables auto-update.
	UserInterval     *time.Duration  `json:"user_interval,omitempty"`
	ProviderInterval time.Duration   `json:"provider_interval,omitempty"`
	LastError        string          `json:"last_error,omitempty"`
	Quota            *Quota          `json:"quota,omitempty"`
	Routing          string          `json:"routing,omitempty"`
	Servers          []*model.Server `json:"servers"`
}

// Interval is the effective auto-update interval (0 = disabled).
func (r *Record) Interval() time.Duration {
	switch {
	case r.Kind != KindRemote:
		return 0
	case r.UserInterval != nil:
		return *r.UserInterval
	case r.ProviderInterval > 0:
		return r.ProviderInterval
	default:
		return DefaultUpdateInterval
	}
}

// State is the persisted subscription list.
type State struct {
	Subscriptions []*Record `json:"subscriptions"`
}

// Manager owns subscriptions: CRUD, refresh and auto-update.
type Manager struct {
	store   *store.Store[State]
	fetcher *Fetcher
	log     *slog.Logger
	now     func() time.Time

	mu    sync.Mutex
	state State
	// refreshing serializes refreshes per subscription.
	refreshing map[string]*sync.Mutex
}

// NewManager loads state from st.
func NewManager(st *store.Store[State], f *Fetcher, log *slog.Logger) (*Manager, error) {
	state, err := st.Load()
	if err != nil {
		return nil, err
	}
	return &Manager{store: st, fetcher: f, log: log, now: time.Now, state: state, refreshing: map[string]*sync.Mutex{}}, nil
}

// List returns copies of all subscriptions.
func (m *Manager) List() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.state.Subscriptions))
	for i, r := range m.state.Subscriptions {
		out[i] = *r
	}
	return out
}

// Get returns a copy of one subscription.
func (m *Manager) Get(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(id)
	if r == nil {
		return Record{}, fmt.Errorf("subscription %q: %w", id, ErrNotFound)
	}
	return *r, nil
}

// Add fetches and stores a new remote subscription. Nothing is stored if
// the first fetch or parse fails.
func (m *Manager) Add(ctx context.Context, rawURL, name string) (Record, error) {
	u, err := NormalizeURL(rawURL)
	if err != nil {
		return Record{}, err
	}
	m.mu.Lock()
	for _, r := range m.state.Subscriptions {
		if r.URL == u {
			m.mu.Unlock()
			return Record{}, fmt.Errorf("subscription already added as %q (%s)", r.Name, r.ID)
		}
	}
	m.mu.Unlock()

	res, err := m.fetcher.Fetch(ctx, u)
	if err != nil {
		return Record{}, err
	}
	parsed, err := ParseBody(res.Body)
	if err != nil {
		return Record{}, err
	}
	rec := &Record{ID: newID(), Kind: KindRemote, URL: u, Name: name}
	m.apply(rec, res.Meta, parsed)
	if rec.Name == "" {
		rec.Name = rec.ProviderTitle
	}
	if rec.Name == "" {
		rec.Name = hostOf(u)
	}
	m.log.Info("subscription added", "id", rec.ID, "servers", len(rec.Servers), "skipped", len(parsed.Warnings))
	return m.insert(rec)
}

// Import stores a standalone config or link as a local subscription.
func (m *Manager) Import(content []byte, fileName, name string) (Record, error) {
	parsed, err := ParseConfig(content, fileName, name)
	if err != nil {
		return Record{}, err
	}
	if len(parsed.Servers) == 0 {
		return Record{}, ErrNoServers
	}
	rec := &Record{ID: newID(), Kind: KindLocal, Name: name}
	m.apply(rec, Meta{}, parsed)
	if rec.Name == "" {
		rec.Name = rec.Servers[0].Name
	}
	if rec.Name == "" {
		rec.Name = "Imported"
	}
	return m.insert(rec)
}

func (m *Manager) insert(rec *Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Subscriptions = append(m.state.Subscriptions, rec)
	if err := m.save(); err != nil {
		m.state.Subscriptions = m.state.Subscriptions[:len(m.state.Subscriptions)-1]
		return Record{}, err
	}
	return *rec, nil
}

// Remove deletes a subscription and its servers.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.state.Subscriptions, func(r *Record) bool { return r.ID == id })
	if i < 0 {
		return fmt.Errorf("subscription %q: %w", id, ErrNotFound)
	}
	m.state.Subscriptions = slices.Delete(m.state.Subscriptions, i, i+1)
	return m.save()
}

// Update changes the name and/or the auto-update interval (nil = keep;
// a negative interval resets to the provider's/default interval).
func (m *Manager) Update(id string, name *string, interval *time.Duration) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(id)
	if r == nil {
		return Record{}, fmt.Errorf("subscription %q: %w", id, ErrNotFound)
	}
	if name != nil && *name != "" {
		r.Name = *name
	}
	if interval != nil {
		if *interval < 0 {
			r.UserInterval = nil
		} else {
			iv := *interval
			r.UserInterval = &iv
		}
	}
	return *r, m.save()
}

// Refresh re-fetches a remote subscription. On failure the previous servers
// are kept and LastError is set.
func (m *Manager) Refresh(ctx context.Context, id string) (Record, error) {
	lock := m.refreshLock(id)
	lock.Lock()
	defer lock.Unlock()

	rec, err := m.Get(id)
	if err != nil {
		return Record{}, err
	}
	if rec.Kind != KindRemote {
		return rec, errors.New("imported configs have no URL to refresh")
	}
	res, err := m.fetcher.Fetch(ctx, rec.URL)
	var parsed Parsed
	if err == nil {
		parsed, err = ParseBody(res.Body)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.find(id)
	if r == nil { // removed meanwhile
		return Record{}, fmt.Errorf("subscription %q: %w", id, ErrNotFound)
	}
	if err != nil {
		r.LastError = err.Error()
		r.UpdatedAt = m.now() // retry after the interval, not in a tight loop
		m.log.Warn("subscription refresh failed", "id", id, "err", err)
		if serr := m.save(); serr != nil {
			return *r, serr
		}
		return *r, err
	}
	m.apply(r, res.Meta, parsed)
	m.log.Info("subscription refreshed", "id", id, "servers", len(r.Servers), "skipped", len(parsed.Warnings))
	return *r, m.save()
}

// RefreshAll refreshes every remote subscription and joins the errors.
func (m *Manager) RefreshAll(ctx context.Context) ([]Record, error) {
	var errs []error
	for _, r := range m.List() {
		if r.Kind != KindRemote {
			continue
		}
		if _, err := m.Refresh(ctx, r.ID); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.Name, err))
		}
	}
	return m.List(), errors.Join(errs...)
}

// Servers returns the servers of one subscription, or of all if subID is "".
func (m *Manager) Servers(subID string) ([]model.Server, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Server
	found := subID == ""
	for _, r := range m.state.Subscriptions {
		if subID != "" && r.ID != subID {
			continue
		}
		found = true
		for _, s := range r.Servers {
			out = append(out, *s)
		}
	}
	if !found {
		return nil, fmt.Errorf("subscription %q: %w", subID, ErrNotFound)
	}
	return out, nil
}

// Server returns one server and the ID of its subscription.
func (m *Manager) Server(id string) (model.Server, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.Subscriptions {
		for _, s := range r.Servers {
			if s.ID == id {
				return *s, r.ID, nil
			}
		}
	}
	return model.Server{}, "", fmt.Errorf("server %q: %w", id, ErrNotFound)
}

// Run auto-updates due subscriptions until ctx is canceled.
func (m *Manager) Run(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		for _, r := range m.due() {
			if ctx.Err() != nil {
				return
			}
			_, _ = m.Refresh(ctx, r) // errors are recorded in LastError
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) due() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	now := m.now()
	for _, r := range m.state.Subscriptions {
		if iv := r.Interval(); iv > 0 && now.Sub(r.UpdatedAt) >= iv {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// apply stores fetched content into r, assigning stable server IDs.
func (m *Manager) apply(r *Record, meta Meta, p Parsed) {
	r.UpdatedAt = m.now()
	r.LastError = ""
	r.ProviderTitle = meta.Title
	r.SupportURL = meta.SupportURL
	r.ProviderInterval = meta.UpdateInterval
	r.Quota = meta.Quota
	r.Routing = meta.Routing
	if r.Routing == "" && len(p.Routing) > 0 {
		r.Routing = p.Routing[0]
	}
	seen := map[string]int{}
	for _, s := range p.Servers {
		id := serverID(r.ID, s.Key())
		if n := seen[id]; n > 0 {
			seen[id]++
			id += "-" + strconv.Itoa(n+1)
		} else {
			seen[id] = 1
		}
		s.ID = id
	}
	r.Servers = p.Servers
}

func (m *Manager) find(id string) *Record {
	for _, r := range m.state.Subscriptions {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (m *Manager) refreshLock(id string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.refreshing[id]
	if !ok {
		l = &sync.Mutex{}
		m.refreshing[id] = l
	}
	return l
}

func (m *Manager) save() error {
	return m.store.Save(m.state)
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// serverID is stable across refreshes as long as the endpoint and
// credentials stay the same.
func serverID(subID, key string) string {
	sum := sha256.Sum256([]byte(subID + "\x00" + key))
	return hex.EncodeToString(sum[:5])
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Hostname() != "" {
		return p.Hostname()
	}
	return "subscription"
}
