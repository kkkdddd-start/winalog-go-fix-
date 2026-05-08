//go:build windows

package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/monitor"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"go.uber.org/zap"
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
	observability.Info("Creating new MonitorHandler", zap.String("module", "handlers_monitor"))
	handler := &MonitorHandler{
		engine: engine,
	}
	observability.Info("MonitorHandler created successfully", zap.String("module", "handlers_monitor"))
	return handler
}

func (h *MonitorHandler) GetStats(c *gin.Context) {
	clientIP := c.ClientIP()
	observability.Info("GET /api/monitor/stats",
		zap.String("module", "handlers_monitor"),
		zap.String("client", clientIP))

	if h.engine == nil {
		observability.Error("GetStats: engine is nil (not available on this platform)",
			zap.String("module", "handlers_monitor"))
		c.JSON(http.StatusServiceUnavailable, gin.H{"stats": &types.MonitorStats{IsCollecting: false}})
		return
	}

	stats := h.engine.GetStats()

	observability.Info("GET /api/monitor/stats response",
		zap.String("module", "handlers_monitor"),
		zap.Bool("is_collecting", stats.IsCollecting),
		zap.Bool("process_enabled", stats.ProcessEnabled),
		zap.Bool("network_enabled", stats.NetworkEnabled),
		zap.Uint64("process_count", stats.ProcessCount),
		zap.Uint64("network_count", stats.NetworkCount),
		zap.Uint64("alert_count", stats.AlertCount))

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

	observability.Info("GET /api/monitor/events",
		zap.String("module", "handlers_monitor"),
		zap.String("client", clientIP),
		zap.String("type", eventType),
		zap.String("severity", severity),
		zap.String("limit", limit),
		zap.String("offset", offset))

	if h.engine == nil {
		observability.Error("ListEvents: engine is nil", zap.String("module", "handlers_monitor"))
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

	observability.Info("GET /api/monitor/events response",
		zap.String("module", "handlers_monitor"),
		zap.Int("returned", len(events)),
		zap.Int64("total", total))

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

func (h *MonitorHandler) UpdateConfig(c *gin.Context) {
	clientIP := c.ClientIP()
	observability.Info("POST /api/monitor/config",
		zap.String("module", "handlers_monitor"),
		zap.String("client", clientIP))

	if h.engine == nil {
		observability.Error("UpdateConfig: engine is nil", zap.String("module", "handlers_monitor"))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Monitor engine not available"})
		return
	}

	var req monitor.MonitorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		observability.Error("UpdateConfig: invalid request body",
			zap.String("module", "handlers_monitor"),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pollInterval := 0
	if req.PollInterval != nil {
		pollInterval = *req.PollInterval
	}
	processEnabled := false
	if req.ProcessEnabled != nil {
		processEnabled = *req.ProcessEnabled
	}
	networkEnabled := false
	if req.NetworkEnabled != nil {
		networkEnabled = *req.NetworkEnabled
	}

	observability.Info("UpdateConfig request",
		zap.String("module", "handlers_monitor"),
		zap.Bool("process_enabled", processEnabled),
		zap.Bool("network_enabled", networkEnabled),
		zap.Int("poll_interval", pollInterval))

	if err := h.engine.UpdateConfig(&req); err != nil {
		observability.Error("UpdateConfig failed",
			zap.String("module", "handlers_monitor"),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats := h.engine.GetStats()
	observability.Info("UpdateConfig succeeded",
		zap.String("module", "handlers_monitor"),
		zap.Bool("is_collecting", stats.IsCollecting))

	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
		"stats":   stats,
	})
}

func (h *MonitorHandler) StartStop(c *gin.Context) {
	clientIP := c.ClientIP()
	observability.Info("POST /api/monitor/action",
		zap.String("module", "handlers_monitor"),
		zap.String("client", clientIP))

	if h.engine == nil {
		observability.Error("StartStop: engine is nil", zap.String("module", "handlers_monitor"))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Monitor engine not available"})
		return
	}

	var req struct {
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		observability.Error("StartStop: invalid request body",
			zap.String("module", "handlers_monitor"),
			zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	observability.Info("StartStop action request",
		zap.String("module", "handlers_monitor"),
		zap.String("action", req.Action))

	var err error
	if req.Action == "start" {
		if h.engine.IsRunning() {
			observability.Info("StartStop: monitor already running", zap.String("module", "handlers_monitor"))
			c.JSON(http.StatusOK, gin.H{
				"message": "Monitor already running",
				"stats":   h.engine.GetStats(),
			})
			return
		}
		if h.ctx == nil || h.ctx.Err() != nil {
			h.ctx, h.cancel = context.WithCancel(context.Background())
		}
		observability.Info("Starting monitor engine...", zap.String("module", "handlers_monitor"))
		err = h.engine.Start(h.ctx)
		if err == nil {
			observability.Info("Monitor engine started successfully", zap.String("module", "handlers_monitor"))
		} else {
			observability.Error("Failed to start monitor engine",
				zap.String("module", "handlers_monitor"),
				zap.Error(err))
		}
	} else if req.Action == "stop" {
		if !h.engine.IsRunning() {
			observability.Info("StartStop: monitor already stopped", zap.String("module", "handlers_monitor"))
			c.JSON(http.StatusOK, gin.H{
				"message": "Monitor already stopped",
				"stats":   h.engine.GetStats(),
			})
			return
		}
		if h.cancel != nil {
			observability.Info("Stopping monitor engine...", zap.String("module", "handlers_monitor"))
			h.cancel()
		}
		err = h.engine.Stop()
		h.ctx = nil
		h.cancel = nil
		if err == nil {
			observability.Info("Monitor engine stopped successfully", zap.String("module", "handlers_monitor"))
		} else {
			observability.Error("Failed to stop monitor engine",
				zap.String("module", "handlers_monitor"),
				zap.Error(err))
		}
	} else {
		observability.Error("StartStop: invalid action",
			zap.String("module", "handlers_monitor"),
			zap.String("action", req.Action))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action. Use 'start' or 'stop'"})
		return
	}

	if err != nil {
		observability.Error("StartStop action failed",
			zap.String("module", "handlers_monitor"),
			zap.String("action", req.Action),
			zap.Error(err))
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
	observability.Info("Registering monitor routes...", zap.String("module", "handlers_monitor"))
	monitorGroup := r.Group("/api/monitor")
	{
		monitorGroup.GET("/stats", h.GetStats)
		monitorGroup.GET("/events", h.ListEvents)
		monitorGroup.POST("/config", h.UpdateConfig)
		monitorGroup.POST("/action", h.StartStop)
	}
	observability.Info("Monitor routes registered",
		zap.String("module", "handlers_monitor"),
		zap.String("routes", "GET /api/monitor/stats, GET /api/monitor/events, POST /api/monitor/config, POST /api/monitor/action"))
}
