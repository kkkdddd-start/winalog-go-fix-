package api

import (
	"time"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, alertHandler *AlertHandler, importHandler *ImportHandler, liveHandler *LiveHandler, timelineHandler *TimelineHandler, dashboardHandler *DashboardHandler) {
	r.GET("/api/health", healthCheck)

	api := r.Group("/api")
	{
		events := api.Group("/events")
		{
			events.GET("", alertHandler.ListEvents)
			events.GET("/:id", alertHandler.GetEvent)
			events.POST("/search", alertHandler.SearchEvents)
			events.POST("/export", alertHandler.ExportEvents)
		}

		alerts := api.Group("/alerts")
		{
			alerts.GET("", alertHandler.ListAlerts)
			alerts.GET("/stats", alertHandler.GetAlertStats)
			alerts.GET("/trend", alertHandler.GetAlertTrend)
			alerts.GET("/export", alertHandler.ExportAlerts)
			alerts.POST("/run-analysis", alertHandler.RunAnalysis)
			alerts.GET("/:id", alertHandler.GetAlert)
			alerts.POST("/:id/resolve", alertHandler.ResolveAlert)
			alerts.POST("/:id/false-positive", alertHandler.MarkFalsePositive)
			alerts.DELETE("/:id", alertHandler.DeleteAlert)
			alerts.POST("/batch", alertHandler.BatchAlertAction)
		}

		timeline := api.Group("/timeline")
		{
			timeline.GET("", timelineHandler.GetTimeline)
			timeline.GET("/stats", timelineHandler.GetTimelineStats)
			timeline.GET("/chains", timelineHandler.GetAttackChains)
			timeline.GET("/export", timelineHandler.ExportTimeline)
			timeline.DELETE("/alerts/:id", timelineHandler.DeleteAlert)
		}

		importGroup := api.Group("/import")
		{
			importGroup.POST("/logs", importHandler.ImportLogs)
			importGroup.GET("/status", importHandler.GetImportStatus)
			importGroup.GET("/history", importHandler.GetImportHistory)
		}

		live := api.Group("/live")
		{
			live.GET("/stats", liveHandler.GetLiveStats)
			live.GET("/channels", liveHandler.GetLiveChannels)
			live.POST("/channels", liveHandler.UpdateLiveChannels)
			live.GET("/channels/available", liveHandler.GetAvailableChannels)
			live.GET("/stream", liveHandler.Stream)
			live.GET("/events", liveHandler.GetLiveEvents)
			live.DELETE("/events", liveHandler.ClearLiveEvents)
			live.GET("/events/export", liveHandler.ExportLiveEvents)
			live.GET("/monitoring-stats", liveHandler.GetLiveMonitoringStats)
		}

		dashboard := api.Group("/dashboard")
		{
			dashboard.GET("/collection-stats", dashboardHandler.GetCollectionStats)
			dashboard.GET("/log-names", dashboardHandler.GetLogNames)
		}
	}
}

func healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "ok",
		"service":   "winalog-api",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
