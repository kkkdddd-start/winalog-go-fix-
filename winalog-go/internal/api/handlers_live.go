package api

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/collectors/live"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type LiveHandler struct {
	db              *storage.DB
	startTime       time.Time
	lastCount       int64
	mu              sync.RWMutex
	lastStatsUpdate time.Time
	pollCollector   *livePollCollectorWrapper

	stateMu       sync.RWMutex
	collectorState int32
	stateTransitionLog []string
}

type livePollCollectorWrapper struct {
	collector interface {
		Start(ctx context.Context) error
		Stop()
		IsRunning() bool
		GetLastRecordID() uint64
		SetChannels(channels []live.ChannelConfig)
	}
	buffer interface {
		Size() int
		Flush()
	}
}

const (
	stateIdle      int32 = 0
	stateStarting  int32 = 1
	stateRunning   int32 = 2
	stateStopping  int32 = 3
)

func stateToString(s int32) string {
	switch s {
	case stateIdle:
		return "idle"
	case stateStarting:
		return "starting"
	case stateRunning:
		return "running"
	case stateStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

type duration time.Duration

func (d duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

type LiveStats struct {
	TotalEvents  int64     `json:"total_events"`
	EventsPerSec float64   `json:"events_per_sec"`
	Alerts       int64     `json:"alerts"`
	Uptime       duration  `json:"uptime"`
	Timestamp    time.Time `json:"timestamp"`
}

type LiveEvent struct {
	ID           int64   `json:"id"`
	EventID      int     `json:"event_id"`
	Timestamp    string  `json:"timestamp"`
	Level        int     `json:"level"`
	LevelName    string  `json:"level_name"`
	Source       string  `json:"source"`
	LogName      string  `json:"log_name"`
	Computer     string  `json:"computer"`
	User         string  `json:"user"`
	Message      string  `json:"message"`
	ProviderName string  `json:"provider_name"`
}

type LiveEventsResponse struct {
	Events    []LiveEvent `json:"events"`
	SinceID   int64      `json:"since_id"`
	NextID    int64      `json:"next_id"`
	Total     int64      `json:"total"`
	Timestamp string     `json:"timestamp"`
}

type LiveChannelConfig struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	EventIDs    string `json:"event_ids"`
	Enabled     bool   `json:"enabled"`
}

type LiveChannelsResponse struct {
	Channels []LiveChannelConfig `json:"channels"`
}

type LiveStatsResponse struct {
	TotalEvents  int64    `json:"total_events"`
	BufferSize   int      `json:"buffer_size"`
	IsCollecting bool     `json:"is_collecting"`
	LastEventID  int64    `json:"last_event_id"`
	Channels     []string `json:"channels"`
	State        string   `json:"state"`
}

type UpdateChannelsRequest struct {
	Channels []LiveChannelConfig `json:"channels"`
}

type ClearResponse struct {
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

func NewLiveHandler(db *storage.DB) *LiveHandler {
	log.Println("[LIVE] [INIT] Creating LiveHandler...")

	h := &LiveHandler{
		db:              db,
		startTime:       time.Now(),
		collectorState:  stateIdle,
		stateTransitionLog: make([]string, 0, 100),
	}

	channels, err := db.GetLiveChannels()
	if err != nil || len(channels) == 0 {
		log.Printf("[LIVE] [INIT] No saved channels, using defaults: %v", err)
		channels = live.DefaultChannels()
	}

	log.Printf("[LIVE] [INIT] Initializing event buffer...")
	buffer := live.NewEventBuffer(100, 5*time.Second, func(events []*types.Event) {
		if len(events) == 0 {
			return
		}
		interfaceEvents := make([]interface{}, len(events))
		for i, e := range events {
			interfaceEvents[i] = e
		}
		if err := db.InsertLiveEvents(interfaceEvents); err != nil {
			log.Printf("[LIVE] [ERROR] Failed to insert live events: %v", err)
		} else {
			log.Printf("[LIVE] [BUFFER] Flushed %d events to database", len(events))
		}
	})

	log.Printf("[LIVE] [INIT] Creating poll collector with %d channels...", len(channels))
	collector := live.NewEvtPollCollector(channels, buffer, 2*time.Second)

	h.pollCollector = &livePollCollectorWrapper{
		collector: collector,
		buffer:    buffer,
	}

	h.logStateTransition("initialized", "idle")
	log.Printf("[LIVE] [INIT] LiveHandler created successfully, initial state: idle")
	return h
}

func (h *LiveHandler) logStateTransition(action string, newState string) {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	entry := fmt.Sprintf("[%s] %s -> %s", time.Now().Format("15:04:05.000"), action, newState)
	h.stateTransitionLog = append(h.stateTransitionLog, entry)
	if len(h.stateTransitionLog) > 50 {
		h.stateTransitionLog = h.stateTransitionLog[len(h.stateTransitionLog)-50:]
	}
	log.Printf("[LIVE] [STATE] %s", entry)
}

func (h *LiveHandler) getState() int32 {
	return atomic.LoadInt32(&h.collectorState)
}

func (h *LiveHandler) setState(expected int32, newState int32) bool {
	return atomic.CompareAndSwapInt32(&h.collectorState, expected, newState)
}

func (h *LiveHandler) GetLiveStats(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] GET /api/live/stats - client=%s", c.ClientIP())

	h.mu.Lock()
	defer h.mu.Unlock()

	var totalEvents int64
	var alertCount int64
	if h.db != nil {
		stats, err := h.db.GetStats()
		if err != nil {
			log.Printf("[LIVE] [WARN] GetStats failed: %v", err)
		} else {
			totalEvents = stats.EventCount
			alertCount = stats.AlertCount
		}
	}

	now := time.Now()
	uptime := now.Sub(h.startTime)

	if h.lastStatsUpdate.IsZero() {
		h.lastStatsUpdate = now
		h.lastCount = totalEvents
	}

	elapsed := now.Sub(h.lastStatsUpdate).Seconds()
	eventsPerSec := 0.0
	if elapsed > 1 {
		eventsPerSec = float64(totalEvents-h.lastCount) / elapsed
		if eventsPerSec < 0 {
			eventsPerSec = 0
		}
		h.lastCount = totalEvents
		h.lastStatsUpdate = now
	}

	stats := &LiveStats{
		TotalEvents:  totalEvents,
		EventsPerSec: eventsPerSec,
		Alerts:       alertCount,
		Uptime:       duration(uptime),
		Timestamp:    now,
	}

	log.Printf("[LIVE] [HTTP] GET /api/live/stats - total=%d, eps=%.2f, alerts=%d, uptime=%v",
		totalEvents, eventsPerSec, alertCount, uptime)

	c.JSON(200, stats)
}

func (h *LiveHandler) GetLiveEvents(c *gin.Context) {
	sinceID, _ := strconv.ParseInt(c.DefaultQuery("since_id", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

	log.Printf("[LIVE] [HTTP] GET /api/live/events - sinceID=%d, limit=%d, client=%s",
		sinceID, limit, c.ClientIP())

	if limit > 500 {
		limit = 500
	}

	filter := &storage.LiveEventFilter{
		Channel:   c.Query("channel"),
		EventID:   c.Query("event_id"),
		Level:     c.Query("level"),
		StartTime: c.Query("start_time"),
		EndTime:   c.Query("end_time"),
		Keyword:   c.Query("keyword"),
	}

	rows, total, nextID, err := h.db.QueryLiveEvents(sinceID, limit, filter)
	if err != nil {
		log.Printf("[LIVE] [ERROR] GetLiveEvents failed: sinceID=%d, limit=%d, error=%v", sinceID, limit, err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	events := make([]LiveEvent, len(rows))
	for i, r := range rows {
		events[i] = LiveEvent{
			ID:           r.ID,
			EventID:      r.EventID,
			Timestamp:    r.Timestamp,
			Level:        r.Level,
			LevelName:    r.LevelName,
			Source:       r.Source,
			LogName:      r.LogName,
			Computer:     r.Computer,
			User:         r.User,
			Message:      r.Message,
			ProviderName: r.ProviderName,
		}
	}

	log.Printf("[LIVE] [HTTP] GET /api/live/events - sinceID=%d, limit=%d, returned=%d events, total=%d, nextID=%d",
		sinceID, limit, len(events), total, nextID)

	c.JSON(200, LiveEventsResponse{
		Events:    events,
		SinceID:   sinceID,
		NextID:    nextID,
		Total:     total,
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (h *LiveHandler) GetLiveChannels(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] GET /api/live/channels - client=%s", c.ClientIP())

	channels, err := h.db.GetLiveChannels()
	if err != nil {
		log.Printf("[LIVE] [WARN] GetLiveChannels failed: %v, using default channels", err)
		channels = live.DefaultChannels()
	}

	response := make([]LiveChannelConfig, len(channels))
	for i, ch := range channels {
		response[i] = LiveChannelConfig{
			Name:        ch.Name,
			Description: ch.Description,
			EventIDs:    ch.EventIDs,
			Enabled:     ch.Enabled,
		}
	}

	log.Printf("[LIVE] [HTTP] GET /api/live/channels - returned %d channels", len(channels))

	c.JSON(200, LiveChannelsResponse{Channels: response})
}

type AvailableChannelsResponse struct {
	Channels []string `json:"channels"`
}

func (h *LiveHandler) GetAvailableChannels(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] GET /api/live/channels/available - client=%s", c.ClientIP())

	channels, err := live.ListAvailableChannels()
	if err != nil {
		log.Printf("[LIVE] [ERROR] GetAvailableChannels failed: %v", err)
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to enumerate channels: %v", err)})
		return
	}

	log.Printf("[LIVE] [HTTP] GET /api/live/channels/available - returned %d channels: %v", len(channels), channels)
	c.JSON(200, AvailableChannelsResponse{Channels: channels})
}

func (h *LiveHandler) UpdateLiveChannels(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] POST /api/live/channels - client=%s", c.ClientIP())

	var req UpdateChannelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[LIVE] [ERROR] UpdateLiveChannels invalid request: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[LIVE] [CONFIG] Updating channels: %d channels received", len(req.Channels))

	channels := make([]live.ChannelConfig, len(req.Channels))
	for i, ch := range req.Channels {
		channels[i] = live.ChannelConfig{
			Name:     ch.Name,
			EventIDs: ch.EventIDs,
			Enabled:  ch.Enabled,
		}
		log.Printf("[LIVE] [CONFIG] Channel: name=%s, enabled=%v, eventIDs=%s",
			ch.Name, ch.Enabled, ch.EventIDs)
	}

	if err := h.db.SaveLiveChannels(channels); err != nil {
		log.Printf("[LIVE] [ERROR] UpdateLiveChannels SaveLiveChannels failed: %v", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if h.pollCollector != nil && h.pollCollector.collector != nil {
		h.pollCollector.collector.SetChannels(channels)
		log.Printf("[LIVE] [CONFIG] Collector channels updated successfully")
	}

	log.Printf("[LIVE] [CONFIG] All channels updated successfully")
	c.JSON(200, gin.H{"message": "channels updated"})
}

func (h *LiveHandler) ClearLiveEvents(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] DELETE /api/live/events - client=%s", c.ClientIP())

	count, err := h.db.ClearLiveEvents()
	if err != nil {
		log.Printf("[LIVE] [ERROR] ClearLiveEvents failed: %v", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[LIVE] [EVENTS] Cleared %d events from buffer", count)

	c.JSON(200, ClearResponse{
		Message: "cleared",
		Count:   count,
	})
}

func (h *LiveHandler) GetLiveMonitoringStats(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] GET /api/live/monitoring-stats - client=%s", c.ClientIP())

	currentState := h.getState()
	isRunning := false

	total, err := h.db.GetLiveEventsCount()
	if err != nil {
		log.Printf("[LIVE] [WARN] GetLiveEventsCount failed: %v, setting total=0", err)
		total = 0
	}

	bufferSize := 0
	lastEventID := int64(0)

	if h.pollCollector != nil && h.pollCollector.buffer != nil {
		bufferSize = h.pollCollector.buffer.Size()
	}

	if h.pollCollector != nil && h.pollCollector.collector != nil {
		isRunning = h.pollCollector.collector.IsRunning()
		lastEventID = int64(h.pollCollector.collector.GetLastRecordID())
	}

	channels, _ := h.db.GetLiveChannels()
	channelNames := make([]string, 0)
	for _, ch := range channels {
		if ch.Enabled {
			channelNames = append(channelNames, ch.Name)
		}
	}

	log.Printf("[LIVE] [HTTP] GET /api/live/monitoring-stats - state=%s, isRunning=%v, total=%d, bufferSize=%d, lastEventID=%d, channels=%v",
		stateToString(currentState), isRunning, total, bufferSize, lastEventID, channelNames)

	c.JSON(200, LiveStatsResponse{
		TotalEvents:  total,
		BufferSize:   bufferSize,
		IsCollecting: isRunning,
		LastEventID:  lastEventID,
		Channels:     channelNames,
		State:        stateToString(currentState),
	})
}

func (h *LiveHandler) ExportLiveEvents(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] GET /api/live/events/export - client=%s, format=%s", c.ClientIP(), c.DefaultQuery("format", "csv"))

	sinceID, _ := strconv.ParseInt(c.DefaultQuery("since_id", "0"), 10, 64)
	format := c.DefaultQuery("format", "csv")

	filter := &storage.LiveEventFilter{
		Channel:   c.Query("channel"),
		EventID:   c.Query("event_id"),
		Level:     c.Query("level"),
		StartTime: c.Query("start_time"),
		EndTime:   c.Query("end_time"),
		Keyword:   c.Query("keyword"),
	}

	log.Printf("[LIVE] [EXPORT] Querying events: sinceID=%d, limit=10000, channel=%s, eventID=%s, level=%s",
		sinceID, filter.Channel, filter.EventID, filter.Level)

	events, _, _, err := h.db.QueryLiveEvents(sinceID, 10000, filter)
	if err != nil {
		log.Printf("[LIVE] [ERROR] ExportLiveEvents QueryLiveEvents failed: %v", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[LIVE] [EXPORT] Exported %d events, format=%s", len(events), format)

	if format == "json" {
		c.JSON(200, events)
		return
	}

	csv := "ID,EventID,Timestamp,Level,LevelName,Source,LogName,Computer,User,Message,ProviderName\n"
	for _, e := range events {
		csv += fmt.Sprintf("%d,%d,%s,%d,%s,%s,%s,%s,%s,%s,%s\n",
			e.ID, e.EventID, e.Timestamp, e.Level, e.LevelName,
			e.Source, e.LogName, e.Computer, e.User, e.Message, e.ProviderName)
	}

	filename := fmt.Sprintf("live_events_%s.csv", time.Now().Format("20060102_150405"))
	log.Printf("[LIVE] [EXPORT] Sending CSV file: %s, size=%d bytes", filename, len(csv))
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.String(200, csv)
}

func (h *LiveHandler) StartLiveMonitoring(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] POST /api/live/start - client=%s, current state=%s", c.ClientIP(), stateToString(h.getState()))

	if h.pollCollector == nil || h.pollCollector.collector == nil {
		log.Printf("[LIVE] [ERROR] pollCollector not initialized")
		c.JSON(500, gin.H{"error": "collector not initialized"})
		return
	}

	currentState := h.getState()

	if currentState == stateRunning {
		log.Printf("[LIVE] [STATE] Already running, returning success without action")
		c.JSON(200, gin.H{"message": "already running", "state": "running"})
		return
	}

	if currentState == stateStarting {
		log.Printf("[LIVE] [STATE] Already in starting process, wait for it")
		c.JSON(200, gin.H{"message": "already starting", "state": "starting"})
		return
	}

	if currentState == stateStopping {
		log.Printf("[LIVE] [STATE] Currently stopping, cannot start until idle")
		c.JSON(200, gin.H{"message": "currently stopping, try again later", "state": "stopping"})
		return
	}

	if !h.setState(stateIdle, stateStarting) {
		log.Printf("[LIVE] [STATE] Failed to transition from %s to starting", stateToString(currentState))
		c.JSON(200, gin.H{"message": "state transition failed", "state": stateToString(h.getState())})
		return
	}

	h.logStateTransition("start requested", "starting")

	if h.pollCollector.collector.IsRunning() {
		log.Printf("[LIVE] [WARN] Collector already running at Start(), stopping first")
		h.pollCollector.collector.Stop()
	}

	ctx := context.Background()
	if err := h.pollCollector.collector.Start(ctx); err != nil {
		log.Printf("[LIVE] [ERROR] Failed to start pollCollector: %v", err)
		h.setState(stateStarting, stateIdle)
		h.logStateTransition("start failed", "idle")
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	h.setState(stateStarting, stateRunning)
	h.logStateTransition("start completed", "running")
	log.Printf("[LIVE] [INFO] Live monitoring started successfully, state=running")
	c.JSON(200, gin.H{"message": "monitoring started", "state": "running"})
}

func (h *LiveHandler) StopLiveMonitoring(c *gin.Context) {
	log.Printf("[LIVE] [HTTP] POST /api/live/stop - client=%s, current state=%s", c.ClientIP(), stateToString(h.getState()))

	if h.pollCollector == nil || h.pollCollector.collector == nil {
		log.Printf("[LIVE] [ERROR] pollCollector not initialized")
		c.JSON(500, gin.H{"error": "collector not initialized"})
		return
	}

	currentState := h.getState()

	if currentState == stateIdle {
		log.Printf("[LIVE] [STATE] Already idle, nothing to stop")
		c.JSON(200, gin.H{"message": "already idle", "state": "idle"})
		return
	}

	if currentState == stateStopping {
		log.Printf("[LIVE] [STATE] Already in stopping process")
		c.JSON(200, gin.H{"message": "already stopping", "state": "stopping"})
		return
	}

	if currentState == stateStarting {
		log.Printf("[LIVE] [STATE] Currently starting, cannot stop until running")
		c.JSON(200, gin.H{"message": "currently starting, try again later", "state": "starting"})
		return
	}

	if !h.setState(stateRunning, stateStopping) {
		log.Printf("[LIVE] [STATE] Failed to transition from %s to stopping", stateToString(currentState))
		c.JSON(200, gin.H{"message": "state transition failed", "state": stateToString(h.getState())})
		return
	}

	h.logStateTransition("stop requested", "stopping")

	h.pollCollector.collector.Stop()

	h.setState(stateStopping, stateIdle)
	h.logStateTransition("stop completed", "idle")
	log.Printf("[LIVE] [INFO] Live monitoring stopped, state=idle")
	c.JSON(200, gin.H{"message": "monitoring stopped", "state": "idle"})
}

func (h *LiveHandler) GetStateTransitionLog(c *gin.Context) {
	h.stateMu.RLock()
	logs := make([]string, len(h.stateTransitionLog))
	copy(logs, h.stateTransitionLog)
	h.stateMu.RUnlock()

	c.JSON(200, gin.H{
		"current_state": stateToString(h.getState()),
		"logs":          logs,
	})
}
