package alerts

import (
	"strconv"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type DedupCache struct {
	mu      sync.RWMutex
	window  time.Duration
	entries map[string]*dedupEntry
	done    chan struct{}
	wg      sync.WaitGroup
}

type dedupEntry struct {
	EventKey  string
	RuleName  string
	Timestamp time.Time
	Count     int
}

func NewDedupCache(window time.Duration) *DedupCache {
	c := &DedupCache{
		window:  window,
		entries: make(map[string]*dedupEntry),
		done:    make(chan struct{}),
	}

	c.wg.Add(1)
	go c.cleanupLoop()
	return c
}

func (c *DedupCache) IsDuplicate(ruleName string, event *types.Event) bool {
	key := c.generateKey(ruleName, event)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return false
	}

	if time.Since(entry.Timestamp) > c.window {
		return false
	}

	return true
}

func (c *DedupCache) Mark(ruleName string, event *types.Event) {
	key := c.generateKey(ruleName, event)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if exists {
		entry.Count++
		entry.Timestamp = time.Now()
	} else {
		c.entries[key] = &dedupEntry{
			EventKey:  key,
			RuleName:  ruleName,
			Timestamp: time.Now(),
			Count:     1,
		}
	}
}

func (c *DedupCache) GetCount(ruleName string, event *types.Event) int {
	key := c.generateKey(ruleName, event)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return 0
	}

	if time.Since(entry.Timestamp) > c.window {
		return 0
	}

	return entry.Count
}

func (c *DedupCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*dedupEntry)
}

func (c *DedupCache) cleanupLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.window / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			select {
			case <-c.done:
				return
			default:
				c.cleanup()
			}
		case <-c.done:
			return
		}
	}
}

func (c *DedupCache) Close() {
	close(c.done)
	c.wg.Wait()
}

func (c *DedupCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window)
	for key, entry := range c.entries {
		if entry.Timestamp.Before(cutoff) {
			delete(c.entries, key)
		}
	}
}

func (c *DedupCache) generateKey(ruleName string, event *types.Event) string {
	userStr := ""
	if event.UserSID != nil && *event.UserSID != "" {
		userStr = *event.UserSID
	} else if event.User != nil && *event.User != "" {
		userStr = *event.User
	}

	ipStr := ""
	if event.IPAddress != nil && *event.IPAddress != "" {
		ipStr = *event.IPAddress
	}

	windowShard := c.getWindowShard(event.Timestamp)

	return ruleName + "|" +
		strconv.FormatInt(int64(event.EventID), 10) + "|" +
		event.Computer + "|" +
		event.Source + "|" +
		userStr + "|" +
		ipStr + "|" +
		windowShard
}

func (c *DedupCache) getWindowShard(t time.Time) string {
	if c.window <= 0 {
		return "0"
	}
	windowMinutes := int(c.window.Minutes())
	if windowMinutes <= 0 {
		windowMinutes = 1
	}
	shard := t.Unix() / int64(windowMinutes*60)
	return strconv.FormatInt(shard, 10)
}

func (c *DedupCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
