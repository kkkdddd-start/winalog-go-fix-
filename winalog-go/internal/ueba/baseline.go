package ueba

import (
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type BaselineManager struct {
	mu           sync.RWMutex
	userActivity map[string]*UserBaseline
	entityStats  map[string]*EntityStats
	window       time.Duration
	maxAge       time.Duration
	lastCleanup  time.Time
	cleanupMu    sync.Mutex
}

type UserBaseline struct {
	User             string
	LoginCount       int
	TypicalHours     map[int]bool
	TypicalComputers map[string]int
	TypicalSources   map[string]int
	AvgEventsPerDay  float64
	LastUpdated      time.Time
}

type EntityStats struct {
	EntityType string
	EntityID   string
	EventCount int
	FirstSeen  time.Time
	LastSeen   time.Time
	RiskScore  float64
}

func NewBaselineManager() *BaselineManager {
	return &BaselineManager{
		userActivity: make(map[string]*UserBaseline),
		entityStats:  make(map[string]*EntityStats),
		window:       7 * 24 * time.Hour,
		maxAge:       30 * 24 * time.Hour,
		lastCleanup:  time.Now(),
	}
}

func (m *BaselineManager) Update(events []*types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupMu.Lock()
	if time.Since(m.lastCleanup) > time.Hour {
		m.cleanupExpired()
		m.lastCleanup = time.Now()
	}
	m.cleanupMu.Unlock()

	for _, event := range events {
		if event.User != nil {
			m.updateUserBaseline(*event.User, event)
		}
		m.updateEntityStats(event)
	}

	return nil
}

func (m *BaselineManager) cleanupExpired() {
	cutoff := time.Now().Add(-m.maxAge)

	for user, baseline := range m.userActivity {
		if baseline.LastUpdated.Before(cutoff) {
			delete(m.userActivity, user)
		}
	}

	for key, stats := range m.entityStats {
		if stats.LastSeen.Before(cutoff) {
			delete(m.entityStats, key)
		}
	}
}

func (m *BaselineManager) SetMaxAge(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxAge = maxAge
}

func (m *BaselineManager) updateUserBaseline(user string, event *types.Event) {
	baseline, exists := m.userActivity[user]
	if !exists {
		baseline = &UserBaseline{
			User:             user,
			TypicalHours:     make(map[int]bool),
			TypicalComputers: make(map[string]int),
			TypicalSources:   make(map[string]int),
		}
		m.userActivity[user] = baseline
	}

	baseline.LoginCount++
	hour := event.Timestamp.Hour()
	baseline.TypicalHours[hour] = true
	baseline.TypicalComputers[event.Computer]++
	if event.Source != "" {
		baseline.TypicalSources[event.Source]++
	}
	baseline.LastUpdated = time.Now()
}

func (m *BaselineManager) updateEntityStats(event *types.Event) {
	entityKey := event.Computer + ":" + event.Source

	stats, exists := m.entityStats[entityKey]
	if !exists {
		stats = &EntityStats{
			EntityType: "computer_source",
			EntityID:   entityKey,
			FirstSeen:  event.Timestamp,
		}
		m.entityStats[entityKey] = stats
	}

	stats.EventCount++
	stats.LastSeen = event.Timestamp
}

func (m *BaselineManager) GetUserBaseline(user string) (*UserBaseline, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	baseline, exists := m.userActivity[user]
	return baseline, exists
}

func (m *BaselineManager) GetUserActivity() map[string]*UserBaseline {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*UserBaseline)
	for k, v := range m.userActivity {
		result[k] = v
	}
	return result
}

func (m *BaselineManager) GetEntityStats(entityID string) (*EntityStats, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.entityStats[entityID]
	return stats, exists
}

func (m *BaselineManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.userActivity = make(map[string]*UserBaseline)
	m.entityStats = make(map[string]*EntityStats)
}

func (m *BaselineManager) SetWindow(window time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.window = window
}
