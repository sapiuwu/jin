package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache is the two-layer TTL cache shared by the adapters that talk to
// rate-limited external sources (NVD, crt.sh):
//
//  1. an in-memory layer that deduplicates repeated queries within a run,
//     so the same technology+version (or domain) is fetched exactly once
//     no matter how many workers ask for it concurrently;
//  2. an on-disk JSON store (by default ~/.jin/cache/<name>.json) that
//     makes subsequent runs cheap within the entry's TTL.
//
// The disk layer is only active when a directory and a positive TTL are
// configured; the memory layer is always active. All disk failures are
// swallowed — a broken cache must never break a scan.
type Cache struct {
	path string // JSON store; "" disables the disk layer
	ttl  time.Duration
	now  func() time.Time // injectable clock for tests

	mu     sync.Mutex
	mem    map[string]cacheEntry
	disk   map[string]cacheEntry
	loaded bool
}

type cacheEntry struct {
	ExpiresAt time.Time       `json:"expires_at,omitempty"`
	Value     json.RawMessage `json:"value"`
}

// NewCache builds a cache persisted as <dir>/<name>.json. An empty dir
// yields a memory-only cache; a ttl <= 0 keeps the memory layer (whose
// entries then never expire — irrelevant beyond a single run) but disables
// the disk layer.
func NewCache(dir, name string, ttl time.Duration) *Cache {
	c := &Cache{
		ttl:  ttl,
		now:  time.Now,
		mem:  make(map[string]cacheEntry),
		disk: make(map[string]cacheEntry),
	}
	if dir != "" && ttl > 0 {
		c.path = filepath.Join(dir, name+".json")
	}
	return c
}

// Get returns the cached value for key, consulting the memory layer first
// and falling back to disk. Expired entries are dropped, not returned.
// The value must be valid JSON — it is embedded verbatim in the JSON store.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if e, ok := c.mem[key]; ok {
		if c.expired(e, now) {
			delete(c.mem, key)
		} else {
			return e.Value, true
		}
	}
	if c.path == "" {
		return nil, false
	}
	c.loadLocked()
	if e, ok := c.disk[key]; ok {
		if c.expired(e, now) {
			delete(c.disk, key)
			c.flushLocked()
			return nil, false
		}
		c.mem[key] = e
		return e.Value, true
	}
	return nil, false
}

// Set stores value under key in both layers, flushing the disk layer
// immediately. value must be valid JSON (that is what callers cache and
// what the store is made of); writes are best-effort — a failure here
// never breaks the surrounding scan.
func (c *Cache) Set(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var exp time.Time
	if c.ttl > 0 {
		exp = c.now().Add(c.ttl)
	}
	c.mem[key] = cacheEntry{ExpiresAt: exp, Value: append([]byte(nil), value...)}
	if c.path == "" {
		return
	}
	c.loadLocked()
	c.disk[key] = cacheEntry{ExpiresAt: exp, Value: append([]byte(nil), value...)}
	c.flushLocked()
}

// expired reports whether e is past its TTL. Entries without an expiry
// (ttl disabled) live forever.
func (c *Cache) expired(e cacheEntry, now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}

// loadLocked reads the disk store once per instance, discarding entries
// that have expired since they were written.
func (c *Cache) loadLocked() {
	if c.loaded {
		return
	}
	c.loaded = true

	data, err := os.ReadFile(c.path)
	if err != nil {
		return // no store yet, unreadable, or permissions wrong: start empty
	}
	var store struct {
		Entries map[string]cacheEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return
	}
	now := c.now()
	for k, e := range store.Entries {
		if !c.expired(e, now) {
			c.disk[k] = e
		}
	}
}

// flushLocked rewrites the disk store atomically (write to a temp file,
// then rename) so a crash mid-write cannot corrupt previously cached data.
func (c *Cache) flushLocked() {
	if c.path == "" {
		return
	}
	store := struct {
		Entries map[string]cacheEntry `json:"entries"`
	}{Entries: c.disk}
	if len(store.Entries) == 0 {
		store.Entries = map[string]cacheEntry{}
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}
