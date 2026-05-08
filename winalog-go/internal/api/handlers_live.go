package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/collectors/live"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"go.uber.org/zap"
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
	observability.Info("Creating LiveHandler", zap.String("module", "handlers_live"))

	h := &LiveHandler{
		db:              db,
		startTime:       time.Now(),
		collectorState:  stateIdle,
		stateTransitionLog: make([]string, 0, 100),
	}

	channels, err := db.GetLiveChannels()
	if err != nil || len(channels) == 0 {
		observability.Warn("No saved channels, using defaults", zap.String("module", "handlers_live"), zap.Error(err))
		channels = live.DefaultChannels()
	}

	observability.Info("Initializing event buffer", zap.String("module", "handlers_live"))
	buffer := live.NewEventBuffer(100, 5*time.Second, func(events []*types.Event) {
		if len(events) == 0 {
			return
		}
		interfaceEvents := make([]interface{}, len(events))
		for i, e := range events {
			interfaceEvents[i] = e
		}
		if err := db.InsertLiveEvents(interfaceEvents); err != nil {
			observability.Error("Failed to insert live events", zap.String("module", "handlers_live"), zap.Error(err))
		} else {
			observability.Info("Flushed events to database", zap.String("module", "handlers_live"), zap.Int("count", len(events)))
		}
	})

	observability.Info("Creating poll collector", zap.String("module", "handlers_live"), zap.Int("channels", len(channels)))
	collector := live.NewEvtPollCollector(channels, buffer, 2*time.Second)

	h.pollCollector = &livePollCollectorWrapper{
		collector: collector,
		buffer:    buffer,
	}

	h.logStateTransition("initialized", "idle")
	observability.Info("LiveHandler created successfully, initial state: idle", zap.String("module", "handlers_live"))
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
	observability.Info("State transition", zap.String("module", "handlers_live"), zap.String("detail", entry))
}

func (h *LiveHandler) getState() int32 {
	return atomic.LoadInt32(&h.collectorState)
}

func (h *LiveHandler) setState(expected int32, newState int32) bool {
	return atomic.CompareAndSwapInt32(&h.collectorState, expected, newState)
}

func (h *LiveHandler) GetLiveStats(c *gin.Context) {
	observability.Info("GET /api/live/stats", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	h.mu.Lock()
	defer h.mu.Unlock()

	var totalEvents int64
	var alertCount int64
	if h.db != nil {
		stats, err := h.db.GetStats()
		if err != nil {
			observability.Warn("GetStats failed", zap.String("module", "handlers_live"), zap.Error(err))
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

	observability.Info("GET /api/live/stats result", zap.String("module", "handlers_live"),
		zap.Int64("total", totalEvents), zap.Float64("eps", eventsPerSec), zap.Int64("alerts", alertCount), zap.Duration("uptime", uptime))

	c.JSON(200, stats)
}

func (h *LiveHandler) GetLiveEvents(c *gin.Context) {
	sinceID, _ := strconv.ParseInt(c.DefaultQuery("since_id", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

	observability.Info("GET /api/live/events", zap.String("module", "handlers_live"),
		zap.Int64("sinceID", sinceID), zap.Int("limit", limit), zap.String("client", c.ClientIP()))

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
		observability.Error("GetLiveEvents failed", zap.String("module", "handlers_live"),
			zap.Int64("sinceID", sinceID), zap.Int("limit", limit), zap.Error(err))
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

	observability.Info("GET /api/live/events result", zap.String("module", "handlers_live"),
		zap.Int64("sinceID", sinceID), zap.Int("limit", limit), zap.Int("returned", len(events)), zap.Int64("total", total), zap.Int64("nextID", nextID))

	c.JSON(200, LiveEventsResponse{
		Events:    events,
		SinceID:   sinceID,
		NextID:    nextID,
		Total:     total,
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (h *LiveHandler) GetLiveChannels(c *gin.Context) {
	observability.Info("GET /api/live/channels", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	channels, err := h.db.GetLiveChannels()
	if err != nil {
		observability.Warn("GetLiveChannels failed, using defaults", zap.String("module", "handlers_live"), zap.Error(err))
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

	observability.Info("GET /api/live/channels result", zap.String("module", "handlers_live"), zap.Int("count", len(channels)))

	c.JSON(200, LiveChannelsResponse{Channels: response})
}

type AvailableChannelsResponse struct {
	Channels []string `json:"channels"`
}

func (h *LiveHandler) GetAvailableChannels(c *gin.Context) {
	observability.Info("GET /api/live/channels/available", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	channels, err := live.ListAvailableChannels()
	if err != nil {
		observability.Error("GetAvailableChannels failed", zap.String("module", "handlers_live"), zap.Error(err))
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to enumerate channels: %v", err)})
		return
	}

	observability.Info("GET /api/live/channels/available result", zap.String("module", "handlers_live"),
		zap.Int("count", len(channels)), zap.Any("channels", channels))
	c.JSON(200, AvailableChannelsResponse{Channels: channels})
}

func (h *LiveHandler) UpdateLiveChannels(c *gin.Context) {
	observability.Info("POST /api/live/channels", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	var req UpdateChannelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		observability.Error("UpdateLiveChannels invalid request", zap.String("module", "handlers_live"), zap.Error(err))
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	observability.Info("Updating channels config", zap.String("module", "handlers_live"), zap.Int("count", len(req.Channels)))

	channels := make([]live.ChannelConfig, len(req.Channels))
	for i, ch := range req.Channels {
		channels[i] = live.ChannelConfig{
			Name:     ch.Name,
			EventIDs: ch.EventIDs,
			Enabled:  ch.Enabled,
		}
		observability.Info("Channel config", zap.String("module", "handlers_live"),
			zap.String("name", ch.Name), zap.Bool("enabled", ch.Enabled), zap.String("eventIDs", ch.EventIDs))
	}

	if err := h.db.SaveLiveChannels(channels); err != nil {
		observability.Error("UpdateLiveChannels SaveLiveChannels failed", zap.String("module", "handlers_live"), zap.Error(err))
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if h.pollCollector != nil && h.pollCollector.collector != nil {
		h.pollCollector.collector.SetChannels(channels)
		observability.Info("Collector channels updated successfully", zap.String("module", "handlers_live"))
	}

	observability.Info("All channels updated successfully", zap.String("module", "handlers_live"))
	c.JSON(200, gin.H{"message": "channels updated"})
}

func (h *LiveHandler) ClearLiveEvents(c *gin.Context) {
	observability.Info("DELETE /api/live/events", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	count, err := h.db.ClearLiveEvents()
	if err != nil {
		observability.Error("ClearLiveEvents failed", zap.String("module", "handlers_live"), zap.Error(err))
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	observability.Info("Cleared events from buffer", zap.String("module", "handlers_live"), zap.Int64("count", count))

	c.JSON(200, ClearResponse{
		Message: "cleared",
		Count:   count,
	})
}

func (h *LiveHandler) GetLiveMonitoringStats(c *gin.Context) {
	observability.Info("GET /api/live/monitoring-stats", zap.String("module", "handlers_live"), zap.String("client", c.ClientIP()))

	currentState := h.getState()
	isRunning := false

	total, err := h.db.GetLiveEventsCount()
	if err != nil {
		observability.Warn("GetLiveEventsCount failed", zap.String("module", "handlers_live"), zap.Error(err))
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

	observability.Info("GET /api/live/monitoring-stats result", zap.String("module", "handlers_live"),
		zap.String("state", stateToString(currentState)), zap.Bool("isRunning", isRunning),
		zap.Int64("total", total), zap.Int("bufferSize", bufferSize), zap.Int64("lastEventID", lastEventID), zap.Any("channels", channelNames))

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
	observability.Info("GET /api/live/events/export", zap.String("module", "handlers_live"),
		zap.String("client", c.ClientIP()), zap.String("format", c.DefaultQuery("format", "csv")))

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

	observability.Info("Querying events for export", zap.String("module", "handlers_live"),
		zap.Int64("sinceID", sinceID), zap.Int("limit", 10000),
		zap.String("channel", filter.Channel), zap.String("eventID", filter.EventID), zap.String("level", filter.Level))

	events, _, _, err := h.db.QueryLiveEvents(sinceID, 10000, filter)
	if err != nil {
		observability.Error("ExportLiveEvents QueryLiveEvents failed", zap.String("module", "handlers_live"), zap.Error(err))
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	observability.Info("Exported events", zap.String("module", "handlers_live"), zap.Int("count", len(events)), zap.String("format", format))

	if format == "json" {
		c.JSON(200, events)
		return
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	writer.Write([]string{"ID", "EventID", "Timestamp", "Level", "LevelName", "Source", "LogName", "Computer", "User", "Message", "ProviderName"})
	for _, e := range events {
		writer.Write([]string{
			fmt.Sprintf("%d", e.ID),
			fmt.Sprintf("%d", e.EventID),
			e.Timestamp,
			fmt.Sprintf("%d", e.Level),
			e.LevelName,
			e.Source,
			e.LogName,
			e.Computer,
			e.User,
			e.Message,
			e.ProviderName,
		})
	}
	writer.Flush()
	csvData := buf.String()

	filename := fmt.Sprintf("live_events_%s.csv", time.Now().Format("20060102_150405"))
	observability.Info("Sending CSV file", zap.String("module", "handlers_live"), zap.String("filename", filename), zap.Int("size", len(csvData)))
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.String(200, csvData)
}

func (h *LiveHandler) StartLiveMonitoring(c *gin.Context) {
	observability.Info("POST /api/live/start", zap.String("module", "handlers_live"),
		zap.String("client", c.ClientIP()), zap.String("currentState", stateToString(h.getState())))

	if h.pollCollector == nil || h.pollCollector.collector == nil {
		observability.Error("pollCollector not initialized", zap.String("module", "handlers_live"))
		c.JSON(500, gin.H{"error": "collector not initialized"})
		return
	}

	currentState := h.getState()

	if currentState == stateRunning {
		observability.Info("Already running, returning success", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "already running", "state": "running"})
		return
	}

	if currentState == stateStarting {
		observability.Info("Already in starting process", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "already starting", "state": "starting"})
		return
	}

	if currentState == stateStopping {
		observability.Info("Currently stopping, cannot start", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "currently stopping, try again later", "state": "stopping"})
		return
	}

	if !h.setState(stateIdle, stateStarting) {
		observability.Warn("Failed state transition to starting", zap.String("module", "handlers_live"),
			zap.String("fromState", stateToString(currentState)))
		c.JSON(200, gin.H{"message": "state transition failed", "state": stateToString(h.getState())})
		return
	}

	h.logStateTransition("start requested", "starting")

	if h.pollCollector.collector.IsRunning() {
		observability.Warn("Collector already running at Start, stopping first", zap.String("module", "handlers_live"))
		h.pollCollector.collector.Stop()
	}

	ctx := context.Background()
	if err := h.pollCollector.collector.Start(ctx); err != nil {
		observability.Error("Failed to start pollCollector", zap.String("module", "handlers_live"), zap.Error(err))
		h.setState(stateStarting, stateIdle)
		h.logStateTransition("start failed", "idle")
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	h.setState(stateStarting, stateRunning)
	h.logStateTransition("start completed", "running")
	observability.Info("Live monitoring started successfully", zap.String("module", "handlers_live"))
	c.JSON(200, gin.H{"message": "monitoring started", "state": "running"})
}

func (h *LiveHandler) StopLiveMonitoring(c *gin.Context) {
	observability.Info("POST /api/live/stop", zap.String("module", "handlers_live"),
		zap.String("client", c.ClientIP()), zap.String("currentState", stateToString(h.getState())))

	if h.pollCollector == nil || h.pollCollector.collector == nil {
		observability.Error("pollCollector not initialized", zap.String("module", "handlers_live"))
		c.JSON(500, gin.H{"error": "collector not initialized"})
		return
	}

	currentState := h.getState()

	if currentState == stateIdle {
		observability.Info("Already idle, nothing to stop", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "already idle", "state": "idle"})
		return
	}

	if currentState == stateStopping {
		observability.Info("Already in stopping process", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "already stopping", "state": "stopping"})
		return
	}

	if currentState == stateStarting {
		observability.Info("Currently starting, cannot stop", zap.String("module", "handlers_live"))
		c.JSON(200, gin.H{"message": "currently starting, try again later", "state": "starting"})
		return
	}

	if !h.setState(stateRunning, stateStopping) {
		observability.Warn("Failed state transition to stopping", zap.String("module", "handlers_live"),
			zap.String("fromState", stateToString(currentState)))
		c.JSON(200, gin.H{"message": "state transition failed", "state": stateToString(h.getState())})
		return
	}

	h.logStateTransition("stop requested", "stopping")

	h.pollCollector.collector.Stop()

	h.setState(stateStopping, stateIdle)
	h.logStateTransition("stop completed", "idle")
	observability.Info("Live monitoring stopped", zap.String("module", "handlers_live"))
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
