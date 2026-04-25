//go:build !windows

package api

import (
	"context"
	"log"
	"net/http"

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
}

func NewMonitorHandler(engine *monitor.MonitorEngine) *MonitorHandler {
	return &MonitorHandler{}
}

func (h *MonitorHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"stats": &types.MonitorStats{
			IsRunning: false,
		},
	})
}

func (h *MonitorHandler) ListEvents(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"events": []*types.MonitorEvent{},
		"total":  0,
		"limit":  50,
		"offset": 0,
	})
}

func (h *MonitorHandler) UpdateConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitor not available on this platform",
	})
}

func (h *MonitorHandler) StartStop(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitor not available on this platform",
	})
}

func (h *MonitorHandler) StreamEvents(c *gin.Context) {
	log.Printf("[INFO] [SSE] Monitor stream requested but not available on Linux")
	c.JSON(http.StatusOK, gin.H{
		"events": []*types.MonitorEvent{},
	})
}

func SetupMonitorRoutes(r *gin.Engine, h *MonitorHandler) {
	monitorGroup := r.Group("/api/monitor")
	{
		monitorGroup.GET("/stats", h.GetStats)
		monitorGroup.GET("/events", h.ListEvents)
		monitorGroup.POST("/config", h.UpdateConfig)
		monitorGroup.POST("/action", h.StartStop)
		monitorGroup.GET("/events/stream", h.StreamEvents)
	}
}
