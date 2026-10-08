package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheMemoryLayerRoundTrip(t *testing.T) {
	c := NewCache("", "nvd", time.Hour)
	c.Set("k", []byte(`[{"id":"CVE-1"}]`))

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("Get() miss, want hit from the memory layer")
	}
	if string(got) != `[{"id":"CVE-1"}]` {
		t.Errorf("Get() = %s, want the stored value", got)
	}

	if _, ok := c.Get("missing"); ok {
		t.Error("Get(missing) hit, want miss")
	}
}

func TestCacheEntriesExpire(t *testing.T) {
	c := NewCache("", "nvd", time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	c.Set("k", []byte(`"v"`))
	if _, ok := c.Get("k"); !ok {
		t.Fatal("Get() miss before expiry, want hit")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Error("Get() hit after TTL expiry, want miss")
	}
}

func TestCachePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()

	c1 := NewCache(dir, "nvd", time.Hour)
	c1.Set("k", []byte(`"v"`))

	c2 := NewCache(dir, "nvd", time.Hour)
	got, ok := c2.Get("k")
	if !ok {
		t.Fatal("fresh cache instance missed a value persisted by another instance")
	}
	if string(got) != `"v"` {
		t.Errorf("Get() = %s, want \"v\"", got)
	}
}

func TestCacheSkipsExpiredDiskEntries(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	c1 := NewCache(dir, "nvd", time.Minute)
	c1.now = func() time.Time { return now }
	c1.Set("k", []byte(`"v"`))

	c2 := NewCache(dir, "nvd", time.Minute)
	c2.now = func() time.Time { return now.Add(time.Hour) }
	if _, ok := c2.Get("k"); ok {
		t.Error("Get() hit an entry whose TTL lapsed on disk, want miss")
	}
}

func TestCacheDiskLayerDisabledWithoutDirOrTTL(t *testing.T) {
	dir := t.TempDir()

	// No directory: memory-only, nothing written.
	c1 := NewCache("", "nvd", time.Hour)
	c1.Set("k", []byte(`"v"`))
	if _, ok := c1.Get("k"); !ok {
		t.Fatal("memory layer should stay active without a directory")
	}

	// Non-positive TTL: disk layer off, memory layer on.
	c2 := NewCache(dir, "nvd", 0)
	c2.Set("k", []byte(`"v"`))
	if _, ok := c2.Get("k"); !ok {
		t.Fatal("memory layer should stay active with ttl <= 0")
	}
	if _, err := os.Stat(filepath.Join(dir, "nvd.json")); err == nil {
		t.Error("disk store written despite ttl <= 0, want no file")
	}

	// A later full cache must not see anything from the disabled disk layer.
	c3 := NewCache(dir, "nvd", time.Hour)
	if _, ok := c3.Get("k"); ok {
		t.Error("fresh cache saw a value that was never persisted, want miss")
	}
}
