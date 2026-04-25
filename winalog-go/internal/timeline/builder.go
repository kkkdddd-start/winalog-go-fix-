package timeline

import (
	"fmt"
	"sort"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type TimelineBuilder struct {
	events       []*types.Event
	filter       *TimelineFilter
	attackChains []*AttackChain
	categories   map[string][]*types.Event
}

type TimelineFilter struct {
	StartTime  time.Time
	EndTime    time.Time
	EventIDs   map[int32]bool
	Levels     map[types.EventLevel]bool
	LogNames   map[string]bool
	Sources    map[string]bool
	Computers  map[string]bool
	Users      map[string]bool
	Keywords   string
	MITREIDs   []string
	IncludeRaw bool
}

type TimelineEntry struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	EventID     int32     `json:"event_id"`
	Level       string    `json:"level"`
	Category    string    `json:"category"`
	Source      string    `json:"source"`
	LogName     string    `json:"log_name"`
	Computer    string    `json:"computer"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message"`
	MITREAttack []string  `json:"mitre_attack,omitempty"`
	AttackChain string    `json:"attack_chain,omitempty"`
	RawXML      string    `json:"raw_xml,omitempty"`
}

type Timeline struct {
	Entries    []*TimelineEntry `json:"entries"`
	TotalCount int              `json:"total_count"`
	StartTime  time.Time        `json:"start_time"`
	EndTime    time.Time        `json:"end_time"`
	Duration   time.Duration    `json:"duration"`
}

type AttackChain struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Technique   string         `json:"technique"`
	Tactic      string         `json:"tactic"`
	Severity    string         `json:"severity"`
	Events      []*types.Event `json:"events"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     time.Time      `json:"end_time"`
	Duration    time.Duration  `json:"duration"`
}

type Category string

const (
	CategoryAuthentication Category = "Authentication"
	CategoryAuthorization  Category = "Authorization"
	CategoryProcess        Category = "Process"
	CategoryNetwork        Category = "Network"
	CategoryFile           Category = "File"
	CategoryRegistry       Category = "Registry"
	CategoryScheduledTask  Category = "Scheduled Task"
	CategoryService        Category = "Service"
	CategoryPowerShell     Category = "PowerShell"
	CategoryRemoteAccess   Category = "Remote Access"
	CategoryAccount        Category = "Account"
	CategoryUnknown        Category = "Unknown"
)

func NewTimelineBuilder() *TimelineBuilder {
	return &TimelineBuilder{
		events:       make([]*types.Event, 0),
		filter:       &TimelineFilter{},
		attackChains: make([]*AttackChain, 0),
		categories:   make(map[string][]*types.Event),
	}
}

func (b *TimelineBuilder) SetEvents(events []*types.Event) {
	b.events = events
}

func (b *TimelineBuilder) SetFilter(filter *TimelineFilter) {
	b.filter = filter
}

func (b *TimelineBuilder) Build() (*Timeline, error) {
	entries := make([]*TimelineEntry, 0)

	for _, event := range b.events {
		if !b.matchesFilter(event) {
			continue
		}

		entry := &TimelineEntry{
			ID:        event.ID,
			Timestamp: event.Timestamp,
			EventID:   event.EventID,
			Level:     event.Level.String(),
			Category:  b.categorizeEvent(event),
			Source:    event.Source,
			LogName:   event.LogName,
			Computer:  event.Computer,
			Message:   event.Message,
		}

		if event.User != nil {
			entry.User = *event.User
		}
		if event.RawXML != nil && b.filter.IncludeRaw {
			entry.RawXML = *event.RawXML
		}

		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	timeline := &Timeline{
		Entries:    entries,
		TotalCount: len(entries),
	}

	if len(entries) > 0 {
		timeline.StartTime = entries[0].Timestamp
		timeline.EndTime = entries[len(entries)-1].Timestamp
		timeline.Duration = timeline.EndTime.Sub(timeline.StartTime)
	}

	b.linkAttackChains(timeline)

	return timeline, nil
}

func (b *TimelineBuilder) matchesFilter(event *types.Event) bool {
	if !b.filter.StartTime.IsZero() && event.Timestamp.Before(b.filter.StartTime) {
		return false
	}
	if !b.filter.EndTime.IsZero() && event.Timestamp.After(b.filter.EndTime) {
		return false
	}

	if len(b.filter.EventIDs) > 0 {
		if !b.filter.EventIDs[event.EventID] {
			return false
		}
	}

	if len(b.filter.Levels) > 0 {
		if !b.filter.Levels[event.Level] {
			return false
		}
	}

	if len(b.filter.LogNames) > 0 {
		if !b.filter.LogNames[event.LogName] {
			return false
		}
	}

	if len(b.filter.Computers) > 0 {
		if !b.filter.Computers[event.Computer] {
			return false
		}
	}

	if len(b.filter.Sources) > 0 {
		if !b.filter.Sources[event.Source] {
			return false
		}
	}

	if len(b.filter.Users) > 0 {
		if event.User == nil || !b.filter.Users[*event.User] {
			return false
		}
	}

	return true
}

func (b *TimelineBuilder) categorizeEvent(event *types.Event) string {
	switch {
	case isAuthEvent(event.EventID):
		return string(CategoryAuthentication)
	case isAuthzEvent(event.EventID):
		return string(CategoryAuthorization)
	case isProcessEvent(event.EventID):
		return string(CategoryProcess)
	case isNetworkEvent(event.EventID):
		return string(CategoryNetwork)
	case isFileEvent(event.EventID):
		return string(CategoryFile)
	case isRegistryEvent(event.EventID):
		return string(CategoryRegistry)
	case isScheduledTaskEvent(event.EventID):
		return string(CategoryScheduledTask)
	case isServiceEvent(event.EventID):
		return string(CategoryService)
	case isPowerShellEvent(event.EventID):
		return string(CategoryPowerShell)
	case isRemoteAccessEvent(event.EventID):
		return string(CategoryRemoteAccess)
	case isAccountEvent(event.EventID):
		return string(CategoryAccount)
	default:
		return string(CategoryUnknown)
	}
}

var authEventsMap = map[int32]bool{
	4624: true, 4625: true, 4634: true, 4647: true,
	4648: true, 4670: true, 4768: true, 4769: true,
	4776: true,
}

var authzEventsMap = map[int32]bool{
	4672: true, 4673: true, 4674: true, 4702: true,
}

var processEventsMap = map[int32]bool{
	4688: true, 4689: true, 4696: true, 4697: true,
}

var networkEventsMap = map[int32]bool{
	3: true, 4000: true, 4001: true, 4002: true,
	5156: true, 5157: true, 5158: true, 5159: true,
}

var fileEventsMap = map[int32]bool{
	4656: true, 4658: true,
	4663: true, 4664: true,
}

var registryEventsMap = map[int32]bool{
	4657: true, 4660: true,
}

var scheduledTaskEventsMap = map[int32]bool{
	4698: true, 4699: true, 4700: true, 4701: true,
	4702: true,
}

var serviceEventsMap = map[int32]bool{
	4697: true,
	7000: true, 7001: true, 7002: true, 7009: true,
}

var powershellEventsMap = map[int32]bool{
	400: true, 600: true, 800: true,
	4100: true, 4103: true, 4104: true,
}

var remoteAccessEventsMap = map[int32]bool{
	4624: true, 4625: true, 4648: true, 4672: true,
}

var accountEventsMap = map[int32]bool{
	4720: true, 4721: true, 4722: true, 4723: true,
	4724: true, 4725: true, 4726: true, 4738: true,
	4740: true, 4767: true, 4768: true, 4769: true,
}

func isAuthEvent(eventID int32) bool {
	return authEventsMap[eventID]
}

func isAuthzEvent(eventID int32) bool {
	return authzEventsMap[eventID]
}

func isProcessEvent(eventID int32) bool {
	return processEventsMap[eventID]
}

func isNetworkEvent(eventID int32) bool {
	return networkEventsMap[eventID]
}

func isFileEvent(eventID int32) bool {
	return fileEventsMap[eventID]
}

func isRegistryEvent(eventID int32) bool {
	return registryEventsMap[eventID]
}

func isScheduledTaskEvent(eventID int32) bool {
	return scheduledTaskEventsMap[eventID]
}

func isServiceEvent(eventID int32) bool {
	return serviceEventsMap[eventID]
}

func isPowerShellEvent(eventID int32) bool {
	return powershellEventsMap[eventID]
}

func isRemoteAccessEvent(eventID int32) bool {
	return remoteAccessEventsMap[eventID]
}

func isAccountEvent(eventID int32) bool {
	return accountEventsMap[eventID]
}

func (b *TimelineBuilder) linkAttackChains(timeline *Timeline) {
	chains := b.detectAttackChains(b.events)

	for i, chain := range chains {
		chainID := fmt.Sprintf("chain-%d", i+1)
		for _, event := range chain.Events {
			for _, entry := range timeline.Entries {
				if entry.ID == event.ID {
					entry.AttackChain = chainID
					entry.MITREAttack = []string{chain.Technique}
					break
				}
			}
		}
	}
}

func (b *TimelineBuilder) detectAttackChains(events []*types.Event) []*AttackChain {
	chains := make([]*AttackChain, 0)

	bruteForce := b.detectBruteForce(events)
	if len(bruteForce) > 0 {
		chains = append(chains, bruteForce...)
	}

	lateralMovement := b.detectLateralMovement(events)
	if len(lateralMovement) > 0 {
		chains = append(chains, lateralMovement...)
	}

	persistence := b.detectPersistence(events)
	if len(persistence) > 0 {
		chains = append(chains, persistence...)
	}

	return chains
}

type AttackChainConfig struct {
	BruteForceThreshold      int
	LateralMovementThreshold int
	PersistenceThreshold     int
	TimeWindow               time.Duration
}

func DefaultAttackChainConfig() *AttackChainConfig {
	return &AttackChainConfig{
		BruteForceThreshold:      10,
		LateralMovementThreshold: 3,
		PersistenceThreshold:     1,
		TimeWindow:               24 * time.Hour,
	}
}

func (b *TimelineBuilder) detectBruteForce(events []*types.Event) []*AttackChain {
	return b.detectBruteForceWithConfig(events, nil)
}

func (b *TimelineBuilder) detectBruteForceWithConfig(events []*types.Event, cfg *AttackChainConfig) []*AttackChain {
	chains := make([]*AttackChain, 0)

	if cfg == nil {
		cfg = DefaultAttackChainConfig()
	}

	var failedLogins []*types.Event
	windowStart := time.Now().Add(-cfg.TimeWindow)

	for _, event := range events {
		if event.EventID == 4625 {
			if event.Timestamp.After(windowStart) {
				failedLogins = append(failedLogins, event)
			}
		}
	}

	if len(failedLogins) >= cfg.BruteForceThreshold {
		sort.Slice(failedLogins, func(i, j int) bool {
			return failedLogins[i].Timestamp.Before(failedLogins[j].Timestamp)
		})
		chains = append(chains, &AttackChain{
			ID:          "brute-force-detected",
			Name:        "Brute Force Attack Detected",
			Description: fmt.Sprintf("Detected %d failed login attempts within %v", len(failedLogins), cfg.TimeWindow),
			Technique:   "T1110",
			Tactic:      "Credential Access",
			Severity:    "high",
			Events:      failedLogins,
			StartTime:   failedLogins[0].Timestamp,
			EndTime:     failedLogins[len(failedLogins)-1].Timestamp,
		})
	}

	return chains
}

func (b *TimelineBuilder) detectLateralMovement(events []*types.Event) []*AttackChain {
	return b.detectLateralMovementWithConfig(events, nil)
}

func (b *TimelineBuilder) detectLateralMovementWithConfig(events []*types.Event, cfg *AttackChainConfig) []*AttackChain {
	chains := make([]*AttackChain, 0)

	if cfg == nil {
		cfg = DefaultAttackChainConfig()
	}

	windowStart := time.Now().Add(-cfg.TimeWindow)
	var remoteLogins []*types.Event

	for _, event := range events {
		if (event.EventID == 4624 || event.EventID == 4648) && event.Timestamp.After(windowStart) {
			logonType := event.GetLogonType()
			if event.User != nil && *event.User != "" {
				if logonType == 3 || logonType == 10 {
					remoteLogins = append(remoteLogins, event)
				}
			}
		}
	}

	if len(remoteLogins) >= cfg.LateralMovementThreshold {
		sort.Slice(remoteLogins, func(i, j int) bool {
			return remoteLogins[i].Timestamp.Before(remoteLogins[j].Timestamp)
		})
		chains = append(chains, &AttackChain{
			ID:          "lateral-movement-detected",
			Name:        "Lateral Movement Detected",
			Description: fmt.Sprintf("Detected %d remote login events (LogonType 3/10) within %v", len(remoteLogins), cfg.TimeWindow),
			Technique:   "T1021",
			Tactic:      "Lateral Movement",
			Severity:    "high",
			Events:      remoteLogins,
			StartTime:   remoteLogins[0].Timestamp,
			EndTime:     remoteLogins[len(remoteLogins)-1].Timestamp,
		})
	}

	return chains
}

func (b *TimelineBuilder) detectPersistence(events []*types.Event) []*AttackChain {
	return b.detectPersistenceWithConfig(events, nil)
}

func (b *TimelineBuilder) detectPersistenceWithConfig(events []*types.Event, cfg *AttackChainConfig) []*AttackChain {
	chains := make([]*AttackChain, 0)

	if cfg == nil {
		cfg = DefaultAttackChainConfig()
	}

	var persistenceEvents []*types.Event

	for _, event := range events {
		if event.EventID == 4698 || event.EventID == 4702 {
			persistenceEvents = append(persistenceEvents, event)
		}
	}

	if len(persistenceEvents) >= cfg.PersistenceThreshold {
		chains = append(chains, &AttackChain{
			ID:          "persistence-detected",
			Name:        "Persistence Mechanism Detected",
			Description: fmt.Sprintf("Detected %d scheduled task/Service creation events", len(persistenceEvents)),
			Technique:   "T1053",
			Tactic:      "Persistence",
			Severity:    "medium",
			Events:      persistenceEvents,
			StartTime:   persistenceEvents[0].Timestamp,
			EndTime:     persistenceEvents[len(persistenceEvents)-1].Timestamp,
		})
	}

	return chains
}

func (b *TimelineBuilder) GroupByComputer() map[string]*Timeline {
	result := make(map[string]*Timeline)

	computerEvents := make(map[string][]*types.Event)

	for _, event := range b.events {
		if !b.matchesFilter(event) {
			continue
		}

		computer := event.Computer
		if computer == "" {
			computer = "Unknown"
		}

		computerEvents[computer] = append(computerEvents[computer], event)
	}

	for computer, events := range computerEvents {
		builder := NewTimelineBuilder()
		builder.SetEvents(events)
		builder.SetFilter(b.filter)
		timeline, _ := builder.Build()
		result[computer] = timeline
	}

	return result
}

func (b *TimelineBuilder) GroupByCategory() map[string]*Timeline {
	result := make(map[string]*Timeline)

	categoryEvents := make(map[string][]*types.Event)

	for _, event := range b.events {
		if !b.matchesFilter(event) {
			continue
		}

		category := b.categorizeEvent(event)

		categoryEvents[category] = append(categoryEvents[category], event)
	}

	for category, events := range categoryEvents {
		builder := NewTimelineBuilder()
		builder.SetEvents(events)
		builder.SetFilter(b.filter)
		timeline, _ := builder.Build()
		result[category] = timeline
	}

	return result
}

func (b *TimelineBuilder) GetAttackChains() []*AttackChain {
	chains := b.detectAttackChains(b.events)
	for i, chain := range chains {
		chain.Duration = chain.EndTime.Sub(chain.StartTime)
		if chain.Duration == 0 {
			chain.Duration = time.Second
		}
		chains[i] = chain
	}
	return chains
}
