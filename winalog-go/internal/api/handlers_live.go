package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kkkdddd-start/winalog-go/internal/collectors/live"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		// 允许的跨域来源（根据实际部署环境配置）
		allowedOrigins := map[string]bool{
			"http://localhost":        true,
			"http://localhost:8080":   true,
			"http://localhost:3000":   true,
			"https://winalog.local":   true,
		}
		// 如果 Origin 为空（同源请求），允许
		if origin == "" {
			return true
		}
		return allowedOrigins[origin]
	},
}

type LiveHandler struct {
	db            *storage.DB
	manager       *LiveStreamManager
	startTime     time.Time
	lastCount     int64
	mu            sync.RWMutex
	lastStatsUpdate time.Time
	pollCollector *livePollCollectorWrapper
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
}

type UpdateChannelsRequest struct {
	Channels []LiveChannelConfig `json:"channels"`
}

type ClearResponse struct {
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

type WSClient struct {
	ID        string
	Conn      *websocket.Conn
	Send      chan []byte
	Subs      map[string]bool
	CreatedAt time.Time
}

type LiveStreamManager struct {
	mu          sync.RWMutex
	clients     map[string]*WSClient
	subscribers map[string]map[string]*WSClient
	collectors  map[string]live.EventCollector
}

type WSMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type ClientMessage struct {
	Action   string   `json:"action"`
	Channels []string `json:"channels,omitempty"`
	Query    string   `json:"query,omitempty"`
}

type ServerMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Code    string      `json:"code,omitempty"`
}

type ChannelInfo struct {
	Name     string `json:"name"`
	LogName  string `json:"log_name"`
	Enabled  bool   `json:"enabled"`
}

type ChannelsResponse struct {
	Channels []ChannelInfo `json:"channels"`
	Total    int           `json:"total"`
}

func NewLiveHandler(db *storage.DB) *LiveHandler {
	return &LiveHandler{
		db:        db,
		manager:   NewLiveStreamManager(),
		startTime: time.Now(),
	}
}

func NewLiveStreamManager() *LiveStreamManager {
	return &LiveStreamManager{
		clients:     make(map[string]*WSClient),
		subscribers: make(map[string]map[string]*WSClient),
		collectors:  make(map[string]live.EventCollector),
	}
}

func (m *LiveStreamManager) AddClient(client *WSClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.ID] = client
}

func (m *LiveStreamManager) RemoveClient(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[clientID]
	if !exists {
		return
	}

	for channel := range client.Subs {
		if subs, ok := m.subscribers[channel]; ok {
			delete(subs, clientID)
		}
	}

	close(client.Send)
	delete(m.clients, clientID)
}

func (m *LiveStreamManager) Subscribe(clientID string, channels []string, query string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[clientID]
	if !exists {
		return fmt.Errorf("client not found")
	}

	log.Printf("[INFO] [Live] Subscribe request: clientID=%s, channels=%v, query=%s", clientID, channels, query)

	for _, channel := range channels {
		log.Printf("[DEBUG] [Live] Processing channel: %s", channel)
		if !validChannel(channel) {
			log.Printf("[WARN] [Live] Invalid channel skipped: %s", channel)
			continue
		}

		client.Subs[channel] = true

		if _, ok := m.subscribers[channel]; !ok {
			m.subscribers[channel] = make(map[string]*WSClient)
		}
		m.subscribers[channel][clientID] = client

		if _, ok := m.collectors[channel]; !ok {
			log.Printf("[INFO] [Live] Creating new collector for channel: %s", channel)
			collector := live.NewEventCollector(channel, query)
			if collector == nil {
				log.Printf("[WARN] Event collector not available for channel %s (Windows only)", channel)
				continue
			}
			log.Printf("[DEBUG] [Live] Starting collector for channel: %s", channel)
			if err := collector.Start(context.Background()); err != nil {
				log.Printf("[ERROR] [Live] Failed to start collector for channel %s: %v", channel, err)
				continue
			}
			m.collectors[channel] = collector
			go m.dispatchEvents(channel, collector)
			log.Printf("[INFO] [Live] Collector started successfully for channel: %s", channel)
		}
	}

	return nil
}

func (m *LiveStreamManager) Unsubscribe(clientID string, channels []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[clientID]
	if !exists {
		return
	}

	for _, channel := range channels {
		delete(client.Subs, channel)
		if subs, ok := m.subscribers[channel]; ok {
			delete(subs, clientID)
		}
	}
}

func (m *LiveStreamManager) dispatchEvents(channel string, collector live.EventCollector) {
	for event := range collector.Events() {
		data, err := json.Marshal(event)
		if err != nil {
			continue
		}

		msg := WSMessage{
			Type: "event",
			Data: data,
		}
		msgBytes, _ := json.Marshal(msg)

		m.mu.RLock()
		for _, client := range m.subscribers[channel] {
			select {
			case client.Send <- msgBytes:
			default:
			}
		}
		m.mu.RUnlock()
	}
}

func (m *LiveStreamManager) GetChannels() []ChannelInfo {
	defaultChannels := []string{"Security", "System", "Application", "Setup", "ForwardedEvents"}
	channels := make([]ChannelInfo, 0, len(defaultChannels))

	for _, name := range defaultChannels {
		channels = append(channels, ChannelInfo{
			Name:    name,
			LogName: name,
			Enabled: true,
		})
	}

	return channels
}

func validChannel(channel string) bool {
	validChannels := map[string]bool{
		"Security":          true,
		"System":            true,
		"Application":       true,
		"Setup":             true,
		"ForwardedEvents":   true,
	}
	isValid := validChannels[channel]
	log.Printf("[DEBUG] [Live] validChannel check: channel=%s, isValid=%v", channel, isValid)
	return isValid
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			hb := ServerMessage{Type: "heartbeat", Data: map[string]string{"timestamp": time.Now().Format(time.RFC3339)}}
			if err := c.Conn.WriteJSON(hb); err != nil {
				return
			}
		}
	}
}

func (c *WSClient) readPump(handler *LiveHandler) {
	defer func() {
		handler.manager.RemoveClient(c.ID)
	}()

	// 设置读超时时间（60秒无消息则断开连接）
	readTimeout := 60 * time.Second

	for {
		// 设置读超时
		c.Conn.SetReadDeadline(time.Now().Add(readTimeout))

		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			// 检查是否为超时错误
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[INFO] WebSocket client %s read timeout", c.ID)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
				log.Printf("[INFO] WebSocket client %s read error: %v", c.ID, err)
			}
			return
		}

		var msg ClientMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.Send <- []byte(`{"type":"error","code":"invalid_message","message":"Failed to parse message"}`)
			continue
		}

		switch msg.Action {
		case "subscribe":
			if err := handler.manager.Subscribe(c.ID, msg.Channels, msg.Query); err != nil {
				c.Send <- []byte(fmt.Sprintf(`{"type":"error","code":"subscribe_failed","message":"%v"}`, err))
			} else {
				resp := ServerMessage{
					Type:    "subscribed",
					Data:    map[string]interface{}{"channels": msg.Channels},
				}
				respBytes, _ := json.Marshal(resp)
				c.Send <- respBytes
			}
		case "unsubscribe":
			handler.manager.Unsubscribe(c.ID, msg.Channels)
			resp := ServerMessage{Type: "unsubscribed", Data: map[string][]string{"channels": msg.Channels}}
			respBytes, _ := json.Marshal(resp)
			c.Send <- respBytes
		case "close":
			c.Conn.Close()
		}
	}
}

func (h *LiveHandler) Stream(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[WARN] WebSocket upgrade failed: %v", err)
		return
	}

	clientID := uuid.New().String()
	client := &WSClient{
		ID:        clientID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
		Subs:      make(map[string]bool),
		CreatedAt: time.Now(),
	}

	h.manager.AddClient(client)

	welcome := ServerMessage{
		Type: "connected",
		Data: map[string]interface{}{
			"client_id":   clientID,
			"server_time": time.Now().Format(time.RFC3339),
		},
	}
	welcomeBytes, _ := json.Marshal(welcome)
	client.Send <- welcomeBytes

	go client.writePump()
	go client.readPump(h)
}

func (h *LiveHandler) GetChannels(c *gin.Context) {
	channels := h.manager.GetChannels()
	c.JSON(200, ChannelsResponse{
		Channels: channels,
		Total:    len(channels),
	})
}

func (h *LiveHandler) GetLiveStats(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var totalEvents int64
	var alertCount int64
	if h.db != nil {
		stats, err := h.db.GetStats()
		if err == nil {
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

	c.JSON(200, stats)
}

func (h *LiveHandler) GetLiveEvents(c *gin.Context) {
	sinceID, _ := strconv.ParseInt(c.DefaultQuery("since_id", "0"), 10, 64)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

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
		log.Printf("[ERROR] GetLiveEvents failed: sinceID=%d, limit=%d, error=%v", sinceID, limit, err)
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

	c.JSON(200, LiveEventsResponse{
		Events:    events,
		SinceID:   sinceID,
		NextID:    nextID,
		Total:     total,
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (h *LiveHandler) GetLiveChannels(c *gin.Context) {
	channels, err := h.db.GetLiveChannels()
	if err != nil {
		log.Printf("[ERROR] GetLiveChannels failed: %v", err)
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

	c.JSON(200, LiveChannelsResponse{Channels: response})
}

type AvailableChannelsResponse struct {
	Channels []string `json:"channels"`
}

func (h *LiveHandler) GetAvailableChannels(c *gin.Context) {
	channels, err := live.ListAvailableChannels()
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("failed to enumerate channels: %v", err)})
		return
	}
	c.JSON(200, AvailableChannelsResponse{Channels: channels})
}

func (h *LiveHandler) UpdateLiveChannels(c *gin.Context) {
	var req UpdateChannelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ERROR] UpdateLiveChannels invalid request: %v", err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	channels := make([]live.ChannelConfig, len(req.Channels))
	for i, ch := range req.Channels {
		channels[i] = live.ChannelConfig{
			Name:     ch.Name,
			EventIDs: ch.EventIDs,
			Enabled:  ch.Enabled,
		}
	}

	if err := h.db.SaveLiveChannels(channels); err != nil {
		log.Printf("[ERROR] UpdateLiveChannels SaveLiveChannels failed: %v", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if h.pollCollector != nil && h.pollCollector.collector != nil {
		h.pollCollector.collector.SetChannels(channels)
	}

	c.JSON(200, gin.H{"message": "channels updated"})
}

func (h *LiveHandler) ClearLiveEvents(c *gin.Context) {
	count, err := h.db.ClearLiveEvents()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, ClearResponse{
		Message: "cleared",
		Count:   count,
	})
}

func (h *LiveHandler) GetLiveMonitoringStats(c *gin.Context) {
	total, err := h.db.GetLiveEventsCount()
	if err != nil {
		total = 0
	}

	bufferSize := 0
	if h.pollCollector != nil && h.pollCollector.buffer != nil {
		bufferSize = h.pollCollector.buffer.Size()
	}

	isCollecting := false
	lastEventID := int64(0)
	if h.pollCollector != nil && h.pollCollector.collector != nil {
		isCollecting = h.pollCollector.collector.IsRunning()
		lastEventID = int64(h.pollCollector.collector.GetLastRecordID())
	}

	channels, _ := h.db.GetLiveChannels()
	channelNames := make([]string, 0)
	for _, ch := range channels {
		if ch.Enabled {
			channelNames = append(channelNames, ch.Name)
		}
	}

	c.JSON(200, LiveStatsResponse{
		TotalEvents:  total,
		BufferSize:   bufferSize,
		IsCollecting: isCollecting,
		LastEventID:  lastEventID,
		Channels:     channelNames,
	})
}

func (h *LiveHandler) ExportLiveEvents(c *gin.Context) {
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

	events, _, _, err := h.db.QueryLiveEvents(sinceID, 10000, filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

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
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.String(200, csv)
}
