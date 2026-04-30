//go:build windows

package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/monitor"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
)

type MonitorHandler struct {
	engine interface {
		Start(ctx context.Context) error
		Stop() error
		UpdateConfig(req *monitor.MonitorConfigRequest) error
		GetStats() *types.MonitorStats
		GetEvents(filter *monitor.EventFilter) ([]*types.MonitorEvent, int64)
		Subscribe(ch chan *types.MonitorEvent) func()
		IsRunning() bool
	}
	ctx    context.Context
	cancel context.CancelFunc
}

func NewMonitorHandler(engine *monitor.MonitorEngine) *MonitorHandler {
	log.Println("[MONITOR] [INIT] Creating new MonitorHandler")
	handler := &MonitorHandler{
		engine: engine,
	}
	log.Println("[MONITOR] [INIT] MonitorHandler created successfully")
	return handler
}

func (h *MonitorHandler) GetStats(c *gin.Context) {
	clientIP := c.ClientIP()
	log.Printf("[MONITOR] [HTTP] GET /api/monitor/stats - client=%s", clientIP)

	if h.engine == nil {
		log.Printf("[MONITOR] [ERROR] GetStats: engine is nil (not available on this platform)")
		c.JSON(http.StatusServiceUnavailable, gin.H{"stats": &types.MonitorStats{IsCollecting: false}})
		return
	}

	stats := h.engine.GetStats()

	log.Printf("[MONITOR] [HTTP] GET /api/monitor/stats - is_collecting=%v, process_enabled=%v, network_enabled=%v, process_count=%d, network_count=%d, alert_count=%d",
		stats.IsCollecting, stats.ProcessEnabled, stats.NetworkEnabled,
		stats.ProcessCount, stats.NetworkCount, stats.AlertCount)

	c.JSON(http.StatusOK, gin.H{
		"stats": stats,
	})
}

func (h *MonitorHandler) ListEvents(c *gin.Context) {
	clientIP := c.ClientIP()
	eventType := c.Query("type")
	severity := c.Query("severity")
	limit := c.DefaultQuery("limit", "50")
	offset := c.DefaultQuery("offset", "0")

	log.Printf("[MONITOR] [HTTP] GET /api/monitor/events - client=%s, type=%s, severity=%s, limit=%s, offset=%s",
		clientIP, eventType, severity, limit, offset)

	if h.engine == nil {
		log.Printf("[MONITOR] [ERROR] ListEvents: engine is nil")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"events": []*types.MonitorEvent{},
			"total":  0,
			"limit":  50,
			"offset": 0,
		})
		return
	}

	filter := &monitor.EventFilter{}

	if eventType != "" {
		filter.Type = types.EventType(eventType)
	}

	if severity != "" {
		filter.Severity = types.Severity(severity)
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	} else {
		filter.Limit = 50
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = startTime
		}
	}

	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = endTime
		}
	}

	events, total := h.engine.GetEvents(filter)

	log.Printf("[MONITOR] [HTTP] GET /api/monitor/events - returned %d events, total=%d", len(events), total)

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

func (h *MonitorHandler) UpdateConfig(c *gin.Context) {
	clientIP := c.ClientIP()
	log.Printf("[MONITOR] [HTTP] POST /api/monitor/config - client=%s", clientIP)

	if h.engine == nil {
		log.Printf("[MONITOR] [ERROR] UpdateConfig: engine is nil")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Monitor engine not available"})
		return
	}

	var req monitor.MonitorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[MONITOR] [ERROR] UpdateConfig: invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[MONITOR] [CONFIG] UpdateConfig: process_enabled=%v, network_enabled=%v, poll_interval=%d",
		req.ProcessEnabled, req.NetworkEnabled, req.PollInterval)

	if err := h.engine.UpdateConfig(&req); err != nil {
		log.Printf("[MONITOR] [ERROR] UpdateConfig failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats := h.engine.GetStats()
	log.Printf("[MONITOR] [CONFIG] UpdateConfig succeeded, stats: is_collecting=%v", stats.IsCollecting)

	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
		"stats":   stats,
	})
}

func (h *MonitorHandler) StartStop(c *gin.Context) {
	clientIP := c.ClientIP()
	log.Printf("[MONITOR] [HTTP] POST /api/monitor/action - client=%s", clientIP)

	if h.engine == nil {
		log.Printf("[MONITOR] [ERROR] StartStop: engine is nil")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Monitor engine not available"})
		return
	}

	var req struct {
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[MONITOR] [ERROR] StartStop: invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[MONITOR] [ACTION] StartStop: action=%s", req.Action)

	var err error
	if req.Action == "start" {
		if h.engine.IsRunning() {
			log.Printf("[MONITOR] [ACTION] StartStop: monitor already running")
			c.JSON(http.StatusOK, gin.H{
				"message": "Monitor already running",
				"stats":   h.engine.GetStats(),
			})
			return
		}
		if h.ctx == nil || h.ctx.Err() != nil {
			h.ctx, h.cancel = context.WithCancel(context.Background())
		}
		log.Printf("[MONITOR] [ACTION] Starting monitor engine...")
		err = h.engine.Start(h.ctx)
		if err == nil {
			log.Printf("[MONITOR] [ACTION] Monitor engine started successfully")
		} else {
			log.Printf("[MONITOR] [ERROR] Failed to start monitor engine: %v", err)
		}
	} else if req.Action == "stop" {
		if !h.engine.IsRunning() {
			log.Printf("[MONITOR] [ACTION] StartStop: monitor already stopped")
			c.JSON(http.StatusOK, gin.H{
				"message": "Monitor already stopped",
				"stats":   h.engine.GetStats(),
			})
			return
		}
		if h.cancel != nil {
			log.Printf("[MONITOR] [ACTION] Stopping monitor engine...")
			h.cancel()
		}
		err = h.engine.Stop()
		h.ctx = nil
		h.cancel = nil
		if err == nil {
			log.Printf("[MONITOR] [ACTION] Monitor engine stopped successfully")
		} else {
			log.Printf("[MONITOR] [ERROR] Failed to stop monitor engine: %v", err)
		}
	} else {
		log.Printf("[MONITOR] [ERROR] StartStop: invalid action '%s', expected 'start' or 'stop'", req.Action)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action. Use 'start' or 'stop'"})
		return
	}

	if err != nil {
		log.Printf("[MONITOR] [ERROR] StartStop action '%s' failed: %v", req.Action, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats := h.engine.GetStats()
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Monitor %s successfully", req.Action),
		"stats":   stats,
	})
}

func SetupMonitorRoutes(r *gin.Engine, h *MonitorHandler) {
	log.Println("[MONITOR] [SETUP] Registering monitor routes...")
	monitorGroup := r.Group("/api/monitor")
	{
		monitorGroup.GET("/stats", h.GetStats)
		monitorGroup.GET("/events", h.ListEvents)
		monitorGroup.POST("/config", h.UpdateConfig)
		monitorGroup.POST("/action", h.StartStop)
	}
	log.Println("[MONITOR] [SETUP] Monitor routes registered: GET /api/monitor/stats, GET /api/monitor/events, POST /api/monitor/config, POST /api/monitor/action")
}
