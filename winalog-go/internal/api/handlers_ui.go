package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type UIHandler struct {
	db *storage.DB
}

type DashboardOverview struct {
	TotalEvents      int64            `json:"total_events"`
	TotalAlerts      int64            `json:"total_alerts"`
	CriticalAlerts   int64            `json:"critical_alerts"`
	HighAlerts       int64            `json:"high_alerts"`
	MediumAlerts     int64            `json:"medium_alerts"`
	LowAlerts        int64            `json:"low_alerts"`
	ResolvedAlerts   int64            `json:"resolved_alerts"`
	UnresolvedAlerts int64            `json:"unresolved_alerts"`
	EventsLast24h    int64            `json:"events_last_24h"`
	AlertsLast24h    int64            `json:"alerts_last_24h"`
	DatabaseSize     string           `json:"database_size"`
	EventSources     map[string]int64 `json:"event_sources"`
	TopAlerts        []*AlertSummary  `json:"top_alerts"`
	RecentEvents     []*EventSummary  `json:"recent_events"`
	AlertTrend       []*TrendPoint    `json:"alert_trend"`
	RiskScore        float64          `json:"risk_score"`
}

type AlertSummary struct {
	ID         int64     `json:"id"`
	RuleName   string    `json:"rule_name"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	Count      int       `json:"count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IsResolved bool      `json:"is_resolved"`
}

type EventSummary struct {
	ID        int64     `json:"id"`
	EventID   int32     `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Computer  string    `json:"computer"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type TrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// NewUIHandler godoc
// @Summary 创建UI处理器
// @Description 初始化UIHandler
// @Tags ui
// @Param db query string true "数据库实例"
// @Router /api/ui [get]
func NewUIHandler(db *storage.DB) *UIHandler {
	return &UIHandler{db: db}
}

// GetDashboardOverview godoc
// @Summary 获取仪表板概览
// @Description 返回仪表板所需的综合数据
// @Tags ui
// @Produce json
// @Success 200 {object} DashboardOverview
// @Failure 500 {object} ErrorResponse
// @Router /api/ui/dashboard [get]
func (h *UIHandler) GetDashboardOverview(c *gin.Context) {
	ctx := c.Request.Context()

	var (
		wg           sync.WaitGroup
		statsMu      sync.Mutex
		alertStatsMu sync.Mutex
		sourcesMu    sync.Mutex
		events24hMu  sync.Mutex
		alerts24hMu  sync.Mutex
		alertsMu     sync.Mutex
		listEventsMu sync.Mutex

		stats         *storage.DBStats
		alertStats    *types.AlertStatsData
		eventsLast24h int64
		alertsLast24h int64
		sources       = make(map[string]int64)
		topAlerts     []*AlertSummary
		recentEvents  []*EventSummary
	)

	now := time.Now()
	last24h := now.Add(-24 * time.Hour)

	wg.Add(7)

	go func() {
		defer wg.Done()
		if s, err := h.db.GetStatsWithContext(ctx); err == nil {
			statsMu.Lock()
			stats = s
			statsMu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if as, err := h.db.AlertRepo().GetStatsWithContext(ctx); err == nil {
			alertStatsMu.Lock()
			alertStats = as
			alertStatsMu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		var count int64
		row := h.db.QueryRowWithContext(ctx, `SELECT COUNT(*) FROM events WHERE timestamp >= ?`, last24h.Format(time.RFC3339))
		if row != nil {
			_ = row.Scan(&count)
		}
		events24hMu.Lock()
		eventsLast24h = count
		events24hMu.Unlock()
	}()

	go func() {
		defer wg.Done()
		var count int64
		row := h.db.QueryRowWithContext(ctx, `SELECT COUNT(*) FROM alerts WHERE first_seen >= ?`, last24h.Format(time.RFC3339))
		if row != nil {
			_ = row.Scan(&count)
		}
		alerts24hMu.Lock()
		alertsLast24h = count
		alerts24hMu.Unlock()
	}()

	go func() {
		defer wg.Done()
		rows, err := h.db.QueryWithContext(ctx, `
			SELECT log_name, COUNT(*) as count
			FROM events
			GROUP BY log_name
			ORDER BY count DESC
			LIMIT 8
		`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var logName string
				var count int64
				if err := rows.Scan(&logName, &count); err == nil {
					sourcesMu.Lock()
					sources[logName] = count
					sourcesMu.Unlock()
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		alerts, err := h.db.AlertRepo().QueryWithContext(ctx, &storage.AlertFilter{Limit: 10})
		if err == nil {
			summary := make([]*AlertSummary, 0, len(alerts))
			for _, alert := range alerts {
				summary = append(summary, &AlertSummary{
					ID:         alert.ID,
					RuleName:   alert.RuleName,
					Severity:   string(alert.Severity),
					Message:    alert.Message,
					Count:      alert.Count,
					FirstSeen:  alert.FirstSeen,
					LastSeen:   alert.LastSeen,
					IsResolved: alert.Resolved,
				})
			}
			alertsMu.Lock()
			topAlerts = summary
			alertsMu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		events, _, err := h.db.ListEventsWithContext(ctx, &storage.EventFilter{Limit: 10})
		if err == nil {
			summary := make([]*EventSummary, 0, len(events))
			for _, event := range events {
				summary = append(summary, &EventSummary{
					ID:        event.ID,
					EventID:   event.EventID,
					Timestamp: event.Timestamp,
					Source:    event.Source,
					Computer:  event.Computer,
					Level:     event.Level.String(),
					Message:   event.Message,
				})
			}
			listEventsMu.Lock()
			recentEvents = summary
			listEventsMu.Unlock()
		}
	}()

	wg.Wait()

	overview := &DashboardOverview{}

	if stats != nil {
		overview.TotalEvents = stats.EventCount
		overview.DatabaseSize = formatBytes(stats.DatabaseSize)
	}

	if alertStats != nil {
		overview.TotalAlerts = alertStats.TotalCount
		if bySev, ok := alertStats.BySeverity["critical"]; ok {
			overview.CriticalAlerts = bySev
		}
		if bySev, ok := alertStats.BySeverity["high"]; ok {
			overview.HighAlerts = bySev
		}
		if bySev, ok := alertStats.BySeverity["medium"]; ok {
			overview.MediumAlerts = bySev
		}
		if bySev, ok := alertStats.BySeverity["low"]; ok {
			overview.LowAlerts = bySev
		}
		if byStatus, ok := alertStats.ByStatus["resolved"]; ok {
			overview.ResolvedAlerts = byStatus
		}
		overview.UnresolvedAlerts = overview.TotalAlerts - overview.ResolvedAlerts
	}

	if overview.TotalAlerts > 0 {
		overview.RiskScore = float64(overview.UnresolvedAlerts) / float64(overview.TotalAlerts) * 100
	}

	overview.EventsLast24h = eventsLast24h
	overview.AlertsLast24h = alertsLast24h
	overview.EventSources = sources
	overview.TopAlerts = topAlerts
	overview.RecentEvents = recentEvents

	c.JSON(http.StatusOK, overview)
}

// GetAlertGroups godoc
// @Summary 获取告警分组
// @Description 返回按不同维度分组的告警数据
// @Tags ui
// @Produce json
// @Param group_by query string false "分组维度" default(severity)
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/ui/alerts/groups [get]
func (h *UIHandler) GetAlertGroups(c *gin.Context) {
	groupBy := c.DefaultQuery("group_by", "severity")

	var query string
	switch groupBy {
	case "rule_name":
		query = `
			SELECT rule_name, severity, COUNT(*) as count, 
			       MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
			FROM alerts 
			WHERE 1=1
			GROUP BY rule_name, severity
			ORDER BY count DESC
			LIMIT 50
		`
	case "computer":
		query = `
			SELECT log_name as computer, severity, COUNT(*) as count,
			       MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
			FROM alerts 
			WHERE 1=1
			GROUP BY log_name, severity
			ORDER BY count DESC
			LIMIT 50
		`
	case "time":
		query = `
			SELECT 
				DATE(first_seen) as date,
				severity, 
				COUNT(*) as count
			FROM alerts 
			WHERE 1=1
			GROUP BY DATE(first_seen), severity
			ORDER BY date DESC
			LIMIT 30
		`
	default:
		query = `
			SELECT severity, COUNT(*) as count,
			       MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
			FROM alerts 
			WHERE 1=1
			GROUP BY severity
			ORDER BY count DESC
		`
	}

	rows, err := h.db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	type GroupInfo struct {
		Key       string    `json:"key"`
		Severity  string    `json:"severity,omitempty"`
		Count     int64     `json:"count"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	}

	groups := make([]GroupInfo, 0)
	for rows.Next() {
		var g GroupInfo
		var firstSeen, lastSeen time.Time

		switch groupBy {
		case "rule_name":
			var severity string
			if err := rows.Scan(&g.Key, &severity, &g.Count, &firstSeen, &lastSeen); err == nil {
				g.Severity = severity
				g.FirstSeen = firstSeen
				g.LastSeen = lastSeen
				groups = append(groups, g)
			}
		case "computer":
			var severity string
			if err := rows.Scan(&g.Key, &severity, &g.Count, &firstSeen, &lastSeen); err == nil {
				g.Severity = severity
				g.FirstSeen = firstSeen
				g.LastSeen = lastSeen
				groups = append(groups, g)
			}
		case "time":
			var severity string
			if err := rows.Scan(&g.Key, &severity, &g.Count); err == nil {
				g.Severity = severity
				groups = append(groups, g)
			}
		default:
			if err := rows.Scan(&g.Severity, &g.Count, &firstSeen, &lastSeen); err == nil {
				g.Key = g.Severity
				g.FirstSeen = firstSeen
				g.LastSeen = lastSeen
				groups = append(groups, g)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"groups":   groups,
		"group_by": groupBy,
		"total":    len(groups),
	})
}

// GetMetrics godoc
// @Summary 获取指标数据
// @Description 返回用于图表展示的指标数据
// @Tags ui
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/ui/metrics [get]
func (h *UIHandler) GetMetrics(c *gin.Context) {
	metrics := make(map[string]interface{})

	stats, err := h.db.GetStats()
	if err == nil {
		metrics["total_events"] = stats.EventCount
		metrics["database_size_bytes"] = stats.DatabaseSize
		metrics["database_size_human"] = formatBytes(stats.DatabaseSize)
	}

	alertStats, err := h.db.AlertRepo().GetStats()
	if err == nil {
		metrics["total_alerts"] = alertStats.TotalCount
		metrics["alerts_by_severity"] = alertStats.BySeverity
		metrics["alerts_by_status"] = alertStats.ByStatus
		metrics["avg_per_day"] = alertStats.AvgPerDay
	}

	now := time.Now()

	hourlyCounts := make([]int64, 24)
	hourRows, err := h.db.Query(`
		SELECT 
			CAST(strftime('%H', timestamp) AS INTEGER) as hour,
			COUNT(*)
		FROM events 
		WHERE timestamp >= ?
		GROUP BY hour
		ORDER BY hour
	`, now.Add(-24*time.Hour).Format(time.RFC3339))
	if err == nil {
		defer hourRows.Close()
		for hourRows.Next() {
			var hour, count int64
			if hourRows.Scan(&hour, &count) == nil {
				if hour >= 0 && hour < 24 {
					hourlyCounts[hour] = count
				}
			}
		}
	}
	metrics["events_by_hour"] = hourlyCounts

	metrics["timestamp"] = now.Format(time.RFC3339)

	c.JSON(http.StatusOK, metrics)
}

// GetEventDistribution godoc
// @Summary 获取事件分布
// @Description 返回事件的分布统计信息
// @Tags ui
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/ui/events/distribution [get]
func (h *UIHandler) GetEventDistribution(c *gin.Context) {
	distribution := make(map[string]interface{})

	levelRows, err := h.db.Query(`
		SELECT level, COUNT(*) as count
		FROM events
		GROUP BY level
		ORDER BY count DESC
	`)
	if err == nil {
		defer levelRows.Close()
		byLevel := make(map[string]int64)
		for levelRows.Next() {
			var level, count int
			if levelRows.Scan(&level, &count) == nil {
				byLevel[formatLevel(level)] = int64(count)
			}
		}
		distribution["by_level"] = byLevel
	}

	sourceRows, err := h.db.Query(`
		SELECT source, COUNT(*) as count
		FROM events
		GROUP BY source
		ORDER BY count DESC
		LIMIT 20
	`)
	if err == nil {
		defer sourceRows.Close()
		bySource := make(map[string]int64)
		for sourceRows.Next() {
			var source string
			var count int64
			if sourceRows.Scan(&source, &count) == nil {
				bySource[source] = count
			}
		}
		distribution["by_source"] = bySource
	}

	logNameRows, err := h.db.Query(`
		SELECT log_name, COUNT(*) as count
		FROM events
		GROUP BY log_name
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		defer logNameRows.Close()
		byLogName := make(map[string]int64)
		for logNameRows.Next() {
			var logName string
			var count int64
			if logNameRows.Scan(&logName, &count) == nil {
				byLogName[logName] = count
			}
		}
		distribution["by_log_name"] = byLogName
	}

	eventIDRows, err := h.db.Query(`
		SELECT event_id, COUNT(*) as count
		FROM events
		GROUP BY event_id
		ORDER BY count DESC
		LIMIT 20
	`)
	if err == nil {
		defer eventIDRows.Close()
		type EventIDCount struct {
			EventID int32 `json:"event_id"`
			Count   int64 `json:"count"`
		}
		topEventIDs := make([]EventIDCount, 0)
		for eventIDRows.Next() {
			var eventID int32
			var count int64
			if eventIDRows.Scan(&eventID, &count) == nil {
				topEventIDs = append(topEventIDs, EventIDCount{EventID: eventID, Count: count})
			}
		}
		distribution["top_event_ids"] = topEventIDs
	}

	c.JSON(http.StatusOK, distribution)
}

func formatLevel(level int) string {
	switch level {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Info"
	default:
		return "Verbose"
	}
}

// SetupUIRoutes godoc
// @Summary 设置UI路由
// @Description 配置UI仪表板相关的API路由
// @Tags ui
// @Router /api/ui/dashboard [get]
// @Router /api/ui/alerts/groups [get]
// @Router /api/ui/metrics [get]
// @Router /api/ui/events/distribution [get]
func SetupUIRoutes(r *gin.Engine, uiHandler *UIHandler) {
	ui := r.Group("/api/ui")
	{
		ui.GET("/dashboard", uiHandler.GetDashboardOverview)
		ui.GET("/alerts/groups", uiHandler.GetAlertGroups)
		ui.GET("/metrics", uiHandler.GetMetrics)
		ui.GET("/events/distribution", uiHandler.GetEventDistribution)
	}
}
