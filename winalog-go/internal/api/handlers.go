package api

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/alerts"
	"github.com/kkkdddd-start/winalog-go/internal/engine"
	"github.com/kkkdddd-start/winalog-go/internal/exporters"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AlertHandler struct {
	db          *storage.DB
	alertEngine *alerts.Engine
}

type ImportHandler struct {
	db          *storage.DB
	alertEngine *alerts.Engine
}

type ErrorResponse struct {
	Error   string          `json:"error"`
	Code    types.ErrorCode `json:"code,omitempty"`
	Details map[string]any  `json:"details,omitempty"`
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type PaginationRequest struct {
	Page     int `form:"page,default=1" binding:"min=1"`
	PageSize int `form:"page_size,default=100" binding:"min=1,max=10000"`
}

// ListEventsRequest represents request parameters for listing events
type ListEventsRequest struct {
	Page      int      `form:"page,default=1" binding:"min=1"`
	PageSize  int      `form:"page_size,default=100" binding:"min=1,max=10000"`
	Levels    []int    `form:"levels"`
	EventIDs  []int32  `form:"event_ids"`
	LogNames  []string `form:"log_names"`
	Sources   []string `form:"sources"`
	Users     []string `form:"users"`
	Computers []string `form:"computers"`
	StartTime string   `form:"start_time"`
	EndTime   string   `form:"end_time"`
	SortBy    string   `form:"sort_by"`
	SortOrder string   `form:"sort_order"`
}

type ListEventsResponse struct {
	Events     []*types.Event `json:"events"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// ListEvents godoc
// @Summary List events
// @Description Get a paginated list of events with optional filtering
// @Tags events
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(100)
// @Param levels query []int false "Filter by event levels"
// @Param event_ids query []int32 false "Filter by event IDs"
// @Param log_names query []string false "Filter by log names"
// @Param sources query []string false "Filter by sources"
// @Param users query []string false "Filter by users"
// @Param computers query []string false "Filter by computers"
// @Param start_time query string false "Start time (RFC3339 format)"
// @Param end_time query string false "End time (RFC3339 format)"
// @Param sort_by query string false "Sort field"
// @Param sort_order query string false "Sort order (asc/desc)"
// @Success 200 {object} ListEventsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/events [get]
func (h *AlertHandler) ListEvents(c *gin.Context) {
	var req ListEventsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	filter := &storage.EventFilter{
		Limit:     req.PageSize,
		Offset:    (req.Page - 1) * req.PageSize,
		Levels:    req.Levels,
		EventIDs:  req.EventIDs,
		LogNames:  req.LogNames,
		Sources:   req.Sources,
		Users:     req.Users,
		Computers: req.Computers,
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
	}

	if req.StartTime != "" {
		t, err := time.Parse(time.RFC3339, req.StartTime)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", req.StartTime)
		}
		if err != nil {
			c.JSON(400, ErrorResponse{
				Error: fmt.Sprintf("invalid start_time format: %s (expected RFC3339 or 2006-01-02T15:04)", req.StartTime),
				Code:  types.ErrCodeInvalidRequest,
			})
			return
		}
		filter.StartTime = &t
	}
	if req.EndTime != "" {
		t, err := time.Parse(time.RFC3339, req.EndTime)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", req.EndTime)
		}
		if err != nil {
			c.JSON(400, ErrorResponse{
				Error: fmt.Sprintf("invalid end_time format: %s (expected RFC3339 or 2006-01-02T15:04)", req.EndTime),
				Code:  types.ErrCodeInvalidRequest,
			})
			return
		}
		if req.StartTime == "" {
			t = t.Add(24*time.Hour - time.Second)
		}
		filter.EndTime = &t
	}

	events, total, err := h.db.ListEvents(filter)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	c.JSON(200, ListEventsResponse{
		Events:     events,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	})
}

// GetEvent godoc
// @Summary Get event by ID
// @Description Get a single event by its database ID
// @Tags events
// @Accept json
// @Produce json
// @Param id path int true "Event ID"
// @Success 200 {object} types.Event
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/events/{id} [get]
func (h *AlertHandler) GetEvent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid event id", Code: types.ErrCodeInvalidRequest})
		return
	}

	event, err := h.db.GetEventByID(id)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "event not found", Code: types.ErrCodeEventNotFound})
		return
	}

	c.JSON(200, event)
}

// SearchEventsRequest represents request body for searching events
type SearchEventsRequest struct {
	Keywords    string   `json:"keywords"`
	KeywordMode string   `json:"keyword_mode"`
	Regex       bool     `json:"regex"`
	EventIDs    []int32  `json:"event_ids"`
	Levels      []int    `json:"levels"`
	LogNames    []string `json:"log_names"`
	Sources     []string `json:"sources"`
	Users       []string `json:"users"`
	Computers   []string `json:"computers"`
	StartTime   string   `json:"start_time"`
	EndTime     string   `json:"end_time"`
	Page        int      `json:"page"`
	PageSize    int      `json:"page_size"`
	SortBy      string   `json:"sort_by"`
	SortOrder   string   `json:"sort_order"`
	Highlight   bool     `json:"highlight"`
}

// SearchEvents godoc
// @Summary Search events
// @Description Search events with full-text search and advanced filters
// @Tags events
// @Accept json
// @Produce json
// @Param request body SearchEventsRequest true "Search parameters"
// @Success 200 {object} types.SearchResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/events/search [post]
func (h *AlertHandler) SearchEvents(c *gin.Context) {
	var req SearchEventsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 10000 {
		req.PageSize = 100
	}

	filter := &storage.EventFilter{
		Keywords:    req.Keywords,
		KeywordMode: req.KeywordMode,
		Regex:       req.Regex,
		Limit:       req.PageSize,
		Offset:      (req.Page - 1) * req.PageSize,
		EventIDs:    req.EventIDs,
		Levels:      req.Levels,
		LogNames:    req.LogNames,
		Sources:     req.Sources,
		Computers:   req.Computers,
		Users:       req.Users,
		SortBy:      req.SortBy,
		SortOrder:   req.SortOrder,
	}

	if req.StartTime != "" {
		t, err := time.Parse(time.RFC3339, req.StartTime)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", req.StartTime)
		}
		if err != nil {
			c.JSON(400, ErrorResponse{
				Error: fmt.Sprintf("invalid start_time format: %s (expected RFC3339 or 2006-01-02T15:04)", req.StartTime),
				Code:  types.ErrCodeInvalidRequest,
			})
			return
		}
		filter.StartTime = &t
	}
	if req.EndTime != "" {
		t, err := time.Parse(time.RFC3339, req.EndTime)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", req.EndTime)
		}
		if err != nil {
			c.JSON(400, ErrorResponse{
				Error: fmt.Sprintf("invalid end_time format: %s (expected RFC3339 or 2006-01-02T15:04)", req.EndTime),
				Code:  types.ErrCodeInvalidRequest,
			})
			return
		}
		if req.StartTime == "" {
			t = t.Add(24*time.Hour - time.Second)
		}
		filter.EndTime = &t
	}

	start := time.Now()
	events, total, err := h.db.SearchEvents(filter)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	c.JSON(200, types.SearchResponse{
		Events:     events,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
		QueryTime:  time.Since(start).Milliseconds(),
	})
}

type ExportRequest struct {
	Format  string        `json:"format"` // "json" | "csv" | "excel"
	Filters ExportFilters `json:"filters"`
}

type ExportFilters struct {
	EventIDs  []int32  `json:"event_ids"`
	Levels    []int    `json:"levels"`
	LogNames  []string `json:"log_names"`
	Computers []string `json:"computers"`
	Users     []string `json:"users"`
	StartTime string   `json:"start_time"`
	EndTime   string   `json:"end_time"`
	Keywords  string   `json:"keywords"`
	Limit     int      `json:"limit"`
}

type ExportResponse struct {
	Success bool   `json:"success"`
	Total   int    `json:"total"`
	Message string `json:"message,omitempty"`
}

// ExportEvents godoc
// @Summary Export events
// @Description Export events in various formats (json, csv, excel)
// @Tags events
// @Accept json
// @Produce json
// @Param request body ExportRequest true "Export parameters"
// @Success 200 {object} ExportResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/events/export [post]
func (h *AlertHandler) ExportEvents(c *gin.Context) {
	var req ExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	if req.Format == "" {
		req.Format = "json"
	}
	if req.Filters.Limit <= 0 || req.Filters.Limit > 100000 {
		req.Filters.Limit = 10000
	}

	filter := &storage.EventFilter{
		Limit:     req.Filters.Limit,
		EventIDs:  req.Filters.EventIDs,
		Levels:    req.Filters.Levels,
		LogNames:  req.Filters.LogNames,
		Computers: req.Filters.Computers,
	}

	if req.Filters.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.Filters.StartTime); err == nil {
			filter.StartTime = &t
		}
	}
	if req.Filters.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.Filters.EndTime); err == nil {
			filter.EndTime = &t
		}
	}

	events, _, err := h.db.ListEvents(filter)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	factory := &exporters.ExporterFactory{}
	exporter := factory.Create(req.Format)

	switch req.Format {
	case "csv":
		c.Header("Content-Type", exporter.ContentType())
		c.Header("Content-Disposition", "attachment; filename=events_export.csv")
		if err := exporter.Export(events, c.Writer); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	case "excel", "xlsx":
		c.Header("Content-Type", exporter.ContentType())
		c.Header("Content-Disposition", "attachment; filename=events_export.xlsx")
		if err := exporter.Export(events, c.Writer); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	default:
		c.JSON(200, gin.H{
			"events": events,
			"total":  len(events),
		})
	}
}

type ListAlertsResponse struct {
	Alerts     []*types.Alert `json:"alerts"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

type RunAnalysisResponse struct {
	Success        bool     `json:"success"`
	AlertsCreated  int      `json:"alerts_created"`
	EventsAnalyzed int      `json:"events_analyzed"`
	RulesExecuted  int      `json:"rules_executed"`
	Duration       string   `json:"duration"`
	Errors         []string `json:"errors,omitempty"`
}

type AlertWithDetails struct {
	*types.Alert
	Explanation    string         `json:"explanation"`
	Recommendation string         `json:"recommendation"`
	RealCase       string         `json:"real_case"`
	Keywords       string         `json:"keywords"`
	MatchedEvents  []*types.Event `json:"matched_events,omitempty"`
}

// RunAnalysis godoc
// @Summary Run alert analysis
// @Description Run the alert analysis engine on all stored events
// @Tags alerts
// @Accept json
// @Produce json
// @Success 200 {object} RunAnalysisResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/alerts/run-analysis [post]
func (h *AlertHandler) RunAnalysis(c *gin.Context) {
	if h.alertEngine == nil {
		c.JSON(500, ErrorResponse{Error: "alert engine not initialized", Code: types.ErrCodeInternalError})
		return
	}

	startTime := time.Now()
	ctx := context.Background()

	builtinRules := builtin.GetAlertRules()
	enabledRules := make([]*rules.AlertRule, 0)
	for _, r := range builtinRules {
		if r.Enabled {
			enabledRules = append(enabledRules, r)
		}
	}

	if len(enabledRules) == 0 {
		c.JSON(200, RunAnalysisResponse{
			Success:        true,
			AlertsCreated:  0,
			EventsAnalyzed: 0,
			RulesExecuted:  0,
			Duration:       time.Since(startTime).String(),
		})
		return
	}

	h.alertEngine.LoadRules(enabledRules)

	const batchSize = 1000
	var totalEvents, totalAlerts int
	var errors []string

	offset := 0
	for {
		events, _, err := h.db.ListEvents(&storage.EventFilter{
			Limit:  batchSize,
			Offset: offset,
		})
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to fetch events at offset %d: %v", offset, err))
			break
		}

		if len(events) == 0 {
			break
		}

		alerts, err := h.alertEngine.EvaluateBatch(ctx, events)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to evaluate batch: %v", err))
		}

		if len(alerts) > 0 {
			if err := h.alertEngine.SaveAlerts(alerts); err != nil {
				errors = append(errors, fmt.Sprintf("failed to save alerts: %v", err))
			} else {
				totalAlerts += len(alerts)
			}
		}

		totalEvents += len(events)
		offset += batchSize

		if len(events) < batchSize {
			break
		}
	}

	c.JSON(200, RunAnalysisResponse{
		Success:        len(errors) == 0,
		AlertsCreated:  totalAlerts,
		EventsAnalyzed: totalEvents,
		RulesExecuted:  len(enabledRules),
		Duration:       time.Since(startTime).String(),
		Errors:         errors,
	})
}

// ListAlerts godoc
// @Summary List alerts
// @Description Get a paginated list of alerts with optional filtering
// @Tags alerts
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(100)
// @Param severity query string false "Filter by severity (critical/high/medium/low)"
// @Param resolved query bool false "Filter by resolved status"
// @Success 200 {object} ListAlertsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/alerts [get]
func (h *AlertHandler) ListAlerts(c *gin.Context) {
	var req struct {
		PaginationRequest
		Severity string `form:"severity"`
		Resolved *bool  `form:"resolved"`
	}

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	filter := &storage.AlertQuery{
		Page:     req.Page,
		PageSize: req.PageSize,
	}
	if req.Severity != "" {
		filter.Severity = req.Severity
	}
	if req.Resolved != nil {
		filter.Resolved = req.Resolved
	}

	alerts, total, err := h.db.AlertRepo().List(filter)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	c.JSON(200, ListAlertsResponse{
		Alerts:     alerts,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	})
}

// GetAlertStats godoc
// @Summary Get alert statistics
// @Description Get aggregated alert statistics including counts by severity, status, and top rules
// @Tags alerts
// @Accept json
// @Produce json
// @Success 200 {object} types.AlertStats
// @Failure 500 {object} ErrorResponse
// @Router /api/alerts/stats [get]
func (h *AlertHandler) GetAlertStats(c *gin.Context) {
	stats, err := h.db.AlertRepo().GetStats()
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	alertStats := &types.AlertStats{
		Total:      stats.TotalCount,
		BySeverity: stats.BySeverity,
		ByStatus:   stats.ByStatus,
		ByRule:     stats.TopRules,
		AvgPerDay:  stats.AvgPerDay,
	}

	c.JSON(200, alertStats)
}

// GetAlertTrend godoc
// @Summary Get alert trend
// @Description Get alert trend data over a specified number of days
// @Tags alerts
// @Accept json
// @Produce json
// @Param days query int false "Number of days for trend data" default(7)
// @Success 200 {object} types.AlertTrend
// @Failure 500 {object} ErrorResponse
// @Router /api/alerts/trend [get]
func (h *AlertHandler) GetAlertTrend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days <= 0 || days > 90 {
		days = 7
	}

	trend, err := h.db.AlertRepo().GetTrend(days)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(200, trend)
}

// GetAlert godoc
// @Summary Get alert by ID
// @Description Get a single alert with explanation, recommendation, and matched events
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Alert ID"
// @Success 200 {object} AlertWithDetails
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/alerts/{id} [get]
func (h *AlertHandler) GetAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid alert id", Code: types.ErrCodeInvalidRequest})
		return
	}

	alert, err := h.db.AlertRepo().GetByID(id)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "alert not found", Code: types.ErrCodeAlertNotFound})
		return
	}

	explanation, recommendation, realCase := builtin.GetRuleDetails(alert.RuleName)
	keywords := builtin.GetAlertRuleKeywords(alert.RuleName)

	var relatedEvents []*types.Event

	if len(alert.EventDBIDs) > 0 {
		relatedEvents, _ = h.db.EventRepo().GetByIDs(alert.EventDBIDs)
	}

	if len(relatedEvents) == 0 && len(alert.EventIDs) > 0 {
		timeWindow := 5 * time.Minute
		startTime := alert.FirstSeen.Add(-timeWindow)
		endTime := alert.LastSeen.Add(timeWindow)
		relatedEvents, _ = h.db.EventRepo().GetEventsByWindowsEventIDs(alert.EventIDs, startTime, endTime)
	}

	response := AlertWithDetails{
		Alert:          alert,
		Explanation:    explanation,
		Recommendation: recommendation,
		RealCase:       realCase,
		Keywords:       keywords,
		MatchedEvents:  relatedEvents,
	}

	c.JSON(200, response)
}

type ResolveAlertRequest struct {
	Notes string `json:"notes"`
}

// ResolveAlert godoc
// @Summary Resolve an alert
// @Description Mark an alert as resolved with optional notes
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Alert ID"
// @Param request body ResolveAlertRequest true "Resolve request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/alerts/{id}/resolve [post]
func (h *AlertHandler) ResolveAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid alert id", Code: types.ErrCodeInvalidRequest})
		return
	}

	var req ResolveAlertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	alert, err := h.db.AlertRepo().GetByID(id)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "alert not found", Code: types.ErrCodeAlertNotFound})
		return
	}

	if alert.Resolved {
		c.JSON(400, ErrorResponse{Error: "alert already resolved", Code: types.ErrCodeAlertAlreadyResolved})
		return
	}

	if err := h.db.AlertRepo().Resolve(id, req.Notes); err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(200, SuccessResponse{Message: "Alert resolved"})
}

type MarkFalsePositiveRequest struct {
	Reason string `json:"reason"`
}

// MarkFalsePositive godoc
// @Summary Mark alert as false positive
// @Description Mark an alert as a false positive with a reason
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Alert ID"
// @Param request body MarkFalsePositiveRequest true "False positive request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/alerts/{id}/false-positive [post]
func (h *AlertHandler) MarkFalsePositive(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid alert id", Code: types.ErrCodeInvalidRequest})
		return
	}

	var req MarkFalsePositiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	alert, err := h.db.AlertRepo().GetByID(id)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "alert not found", Code: types.ErrCodeAlertNotFound})
		return
	}

	if alert.FalsePositive {
		c.JSON(400, ErrorResponse{Error: "alert already marked as false positive", Code: types.ErrCodeInvalidRequest})
		return
	}

	if err := h.db.AlertRepo().MarkFalsePositive(id, req.Reason); err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(200, SuccessResponse{Message: "Alert marked as false positive"})
}

// DeleteAlert godoc
// @Summary Delete an alert
// @Description Delete an alert by ID
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Alert ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/alerts/{id} [delete]
func (h *AlertHandler) DeleteAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid alert id", Code: types.ErrCodeInvalidRequest})
		return
	}

	_, err = h.db.AlertRepo().GetByID(id)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "alert not found", Code: types.ErrCodeAlertNotFound})
		return
	}

	if err := h.db.AlertRepo().Delete(id); err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(200, SuccessResponse{Message: "Alert deleted"})
}

type BatchAlertActionRequest struct {
	IDs    []int64 `json:"ids"`
	Action string  `json:"action"`
	Notes  string  `json:"notes"`
	Reason string  `json:"reason"`
}

// BatchAlertAction godoc
// @Summary Batch alert action
// @Description Perform an action (resolve, false-positive, delete) on multiple alerts
// @Tags alerts
// @Accept json
// @Produce json
// @Param request body BatchAlertActionRequest true "Batch action request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/alerts/batch [post]
func (h *AlertHandler) BatchAlertAction(c *gin.Context) {
	var req BatchAlertActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	if len(req.IDs) == 0 {
		c.JSON(400, ErrorResponse{Error: "no alert IDs provided", Code: types.ErrCodeInvalidRequest})
		return
	}

	var errors []string
	successCount := 0

	for _, id := range req.IDs {
		alert, err := h.db.AlertRepo().GetByID(id)
		if err != nil {
			errors = append(errors, fmt.Sprintf("alert %d not found", id))
			continue
		}

		var actionErr error
		switch req.Action {
		case "resolve":
			if alert.Resolved {
				errors = append(errors, fmt.Sprintf("alert %d already resolved", id))
				continue
			}
			actionErr = h.db.AlertRepo().Resolve(id, req.Notes)
		case "false-positive":
			if alert.FalsePositive {
				errors = append(errors, fmt.Sprintf("alert %d already marked as false positive", id))
				continue
			}
			actionErr = h.db.AlertRepo().MarkFalsePositive(id, req.Reason)
		case "delete":
			actionErr = h.db.AlertRepo().Delete(id)
		default:
			errors = append(errors, fmt.Sprintf("unknown action: %s", req.Action))
			continue
		}
		if actionErr != nil {
			errors = append(errors, fmt.Sprintf("failed to %s alert %d: %v", req.Action, id, actionErr))
		} else {
			successCount++
		}
	}

	c.JSON(200, SuccessResponse{
		Message: "Batch action completed",
		Data: gin.H{
			"affected": successCount,
			"failed":   len(errors),
			"errors":   errors,
		},
	})
}

// ExportAlerts godoc
// @Summary Export alerts
// @Description Export alerts in various formats (json, csv, excel)
// @Tags alerts
// @Accept json
// @Produce json
// @Param format query string false "Export format (json/csv/excel)" default(json)
// @Param severity query string false "Filter by severity (critical/high/medium/low/info)"
// @Param resolved query string false "Filter by resolved status (true/false)"
// @Param false_positive query string false "Filter by false positive status (true/false)"
// @Param rule_name query string false "Filter by rule name"
// @Param start_time query string false "Filter by start time (RFC3339 format)"
// @Param end_time query string false "Filter by end time (RFC3339 format)"
// @Param limit query int false "Maximum number of alerts to export (default 100000)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/alerts/export [get]
func (h *AlertHandler) ExportAlerts(c *gin.Context) {
	var req struct {
		Format       string `form:"format"`
		Severity     string `form:"severity"`
		Resolved     string `form:"resolved"`
		FalsePositive string `form:"false_positive"`
		RuleName     string `form:"rule_name"`
		StartTime    string `form:"start_time"`
		EndTime      string `form:"end_time"`
		Limit        int    `form:"limit"`
	}

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	format := req.Format
	if format == "" {
		format = "json"
	}

	limit := req.Limit
	if limit <= 0 || limit > 1000000 {
		limit = 100000
	}

	filter := &storage.AlertFilter{
		Limit:    limit,
		Severity: req.Severity,
		RuleName: req.RuleName,
	}

	if req.Resolved != "" {
		resolved := req.Resolved == "true"
		filter.Resolved = &resolved
	}

	if req.FalsePositive != "" {
		fp := req.FalsePositive == "true"
		filter.FalsePositive = &fp
	}

	if req.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
			filter.StartTime = &t
		}
	}

	if req.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
			filter.EndTime = &t
		}
	}

	alerts, err := h.db.AlertRepo().Query(filter)
	if err != nil {
		log.Printf("[ERROR] ExportAlerts Query failed: %v", err)
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	log.Printf("[REPORT] ExportAlerts: format=%s, count=%d, filters=%+v", format, len(alerts), filter)

	exporter := exporters.NewAlertExporter(format)

	switch format {
	case "csv", "excel", "xlsx":
		c.Header("Content-Type", exporter.ContentType())
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=alerts_export.%s", exporter.FileExtension()))
		if err := exporter.Export(alerts, c.Writer); err != nil {
			log.Printf("[ERROR] ExportAlerts Export failed: %v", err)
			c.JSON(500, ErrorResponse{Error: err.Error()})
			return
		}
	default:
		c.Header("Content-Type", exporter.ContentType())
		c.Header("Content-Disposition", "attachment; filename=alerts_export.json")
		if err := exporter.Export(alerts, c.Writer); err != nil {
			log.Printf("[ERROR] ExportAlerts Export failed: %v", err)
			c.JSON(500, ErrorResponse{Error: err.Error()})
			return
		}
	}
}

// ImportRequest represents request body for importing logs
type ImportRequest struct {
	Files          []string `json:"files" binding:"required"`
	AlertOnImport  bool     `json:"alert_on_import"`
	EnabledFormats []string `json:"enabled_formats"`
	SkipPatterns   []string `json:"skip_patterns"`
}

// ImportLogs godoc
// @Summary Import log files
// @Description Import Windows event log files (evtx, csv, etc.) for analysis
// @Tags import
// @Accept json
// @Produce json
// @Param request body ImportRequest true "Import request"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/import/logs [post]
func (h *ImportHandler) ImportLogs(c *gin.Context) {
	var req ImportRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[IMPORT] Failed to parse request: %v", err)
		c.JSON(400, ErrorResponse{Error: err.Error(), Code: types.ErrCodeInvalidRequest})
		return
	}

	if len(req.Files) == 0 {
		c.JSON(400, ErrorResponse{Error: "no files provided", Code: types.ErrCodeInvalidRequest})
		return
	}

	log.Printf("[IMPORT] Received import request with %d files", len(req.Files))
	for i, f := range req.Files {
		if i < 5 {
			log.Printf("[IMPORT]   file[%d]: %s", i, f)
		} else if i == 5 {
			log.Printf("[IMPORT]   ... and %d more", len(req.Files)-5)
			break
		}
	}

	eng := engine.NewEngine(h.db)

	totalResult := &engine.ImportResult{}

	files := req.Files
	for i, file := range files {
		log.Printf("[IMPORT] Processing file %d/%d: %s", i+1, len(files), file)

		fileReq := &engine.ImportRequest{
			Paths:          []string{file},
			BatchSize:      1000,
			SkipPatterns:   req.SkipPatterns,
			EnabledFormats: req.EnabledFormats,
		}

		log.Printf("[IMPORT] Calling eng.Import for file %d/%d, ctx=%p", i+1, len(files), c.Request.Context())
		result, err := eng.Import(c.Request.Context(), fileReq, nil)
		log.Printf("[IMPORT] eng.Import returned for file %d/%d, err=%v", i+1, len(files), err)

		if err != nil {
			log.Printf("[IMPORT] File %d/%d failed: %v", i+1, len(files), err)
			totalResult.Errors = append(totalResult.Errors, &types.ImportError{
				FilePath: file,
				Error:    err.Error(),
			})
			totalResult.FileResults = append(totalResult.FileResults, &engine.FileResult{
				FilePath: file,
				Status:   "failed",
				Error:    err.Error(),
			})
			totalResult.FilesFailed++
			continue
		}

		totalResult.FilesImported += result.FilesImported
		totalResult.FilesFailed += result.FilesFailed
		totalResult.EventsImported += result.EventsImported
		totalResult.Errors = append(totalResult.Errors, result.Errors...)
		totalResult.FileResults = append(totalResult.FileResults, result.FileResults...)
		totalResult.Duration += result.Duration
		if result.StartTime.IsZero() == false && (result.StartTime.Before(totalResult.StartTime) || totalResult.StartTime.IsZero()) {
			totalResult.StartTime = result.StartTime
		}
	}

	log.Printf("[IMPORT] All batches completed: %d files imported, %d failed, %d events",
		totalResult.FilesImported, totalResult.FilesFailed, totalResult.EventsImported)

	if totalResult.FilesImported > 0 && req.AlertOnImport && h.alertEngine != nil {
		if !totalResult.StartTime.IsZero() {
			events, _, _ := h.db.ListEvents(&storage.EventFilter{
				Limit:     10000,
				StartTime: &totalResult.StartTime,
			})

			if len(events) > 0 {
				alerts, _ := h.alertEngine.EvaluateBatch(context.Background(), events)
				if len(alerts) > 0 {
					_ = h.alertEngine.SaveAlerts(alerts)
				}
			}
		}
	}

	resp := gin.H{
		"success":          totalResult.FilesFailed == 0,
		"files_imported":   totalResult.FilesImported,
		"files_failed":     totalResult.FilesFailed,
		"events_imported":  totalResult.EventsImported,
		"duration":         totalResult.Duration.String(),
		"files":            totalResult.FileResults,
	}
	if len(totalResult.Errors) > 0 {
		resp["errors"] = totalResult.Errors
	}

	c.JSON(200, resp)
}

// GetImportStatus godoc
// @Summary Get import status
// @Description Get the status of a log file import operation
// @Tags import
// @Accept json
// @Produce json
// @Param path query string true "File path to check import status"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/import/status [get]
func (h *ImportHandler) GetImportStatus(c *gin.Context) {
	filePath := c.Query("path")
	if filePath == "" {
		c.JSON(400, ErrorResponse{Error: "path parameter required", Code: types.ErrCodeInvalidRequest})
		return
	}

	log, err := h.db.GetImportLog(filePath)
	if err != nil {
		c.JSON(404, ErrorResponse{Error: "import log not found"})
		return
	}

	c.JSON(200, log)
}

// GetImportHistory godoc
// @Summary Get import history
// @Description Get a list of all past import operations
// @Tags import
// @Accept json
// @Produce json
// @Param limit query int false "Number of entries to return" default(50)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/import/history [get]
func (h *ImportHandler) GetImportHistory(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, _ := strconv.Atoi(offsetStr)
	if offset < 0 {
		offset = 0
	}

	entries, total, err := h.db.ListImportLogs(limit, offset)
	if err != nil {
		log.Printf("[IMPORT] Failed to get import history: %v", err)
		c.JSON(500, ErrorResponse{Error: "failed to get import history", Code: types.ErrCodeInternalError})
		return
	}

	c.JSON(200, SuccessResponse{
		Data: gin.H{
			"total":   total,
			"entries": entries,
		},
	})
}

// TimelineHandler handles timeline-related operations
type TimelineHandler struct {
	db *storage.DB
}

// TimelineEntry represents a single entry in the timeline
type TimelineEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"` // "event" or "alert"
	EventID    int32     `json:"event_id,omitempty"`
	AlertID    int64     `json:"alert_id,omitempty"`
	Level      string    `json:"level,omitempty"`
	Source     string    `json:"source,omitempty"`
	Message    string    `json:"message"`
	Severity   string    `json:"severity,omitempty"`
	RuleName   string    `json:"rule_name,omitempty"`
	MITRE      []string  `json:"mitre_attack,omitempty"`
	Computer   string    `json:"computer,omitempty"`
	LogName    string    `json:"log_name,omitempty"`
	EventDBIDs []int64   `json:"event_db_ids,omitempty"`
}

// TimelineResponse represents the timeline API response
type TimelineResponse struct {
	Entries    []*TimelineEntry `json:"entries"`
	TotalCount int              `json:"total_count"`
	EventCount int              `json:"event_count"`
	AlertCount int              `json:"alert_count"`
	HasMore    bool             `json:"has_more"`
	NextOffset int              `json:"next_offset,omitempty"`
}

// GetTimeline godoc
// @Summary Get timeline
// @Description Get a timeline of events and alerts with pagination
// @Tags timeline
// @Accept json
// @Produce json
// @Param limit query int false "Number of entries to return" default(200)
// @Param offset query int false "Offset for pagination" default(0)
// @Param start_time query string false "Start time (RFC3339 format)"
// @Param end_time query string false "End time (RFC3339 format)"
// @Success 200 {object} TimelineResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/timeline [get]
func (h *TimelineHandler) GetTimeline(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "200")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, _ := strconv.Atoi(offsetStr)
	if offset < 0 {
		offset = 0
	}

	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var start, end *time.Time
	if startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			start = &t
		}
	}
	if endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			end = &t
		}
	}

	entries := make([]*TimelineEntry, 0)

	eventFilter := &storage.EventFilter{
		Limit: 0,
	}
	if start != nil {
		eventFilter.StartTime = start
	}
	if end != nil {
		eventFilter.EndTime = end
	}

	maxEvents := limit + offset + 100
	eventFilter.Limit = int(maxEvents)
	eventFilter.Offset = 0
	events, _, err := h.db.ListEvents(eventFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch events for timeline: %v", err)
	}
	for _, e := range events {
		entries = append(entries, &TimelineEntry{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			Type:      "event",
			EventID:   e.EventID,
			Level:     e.Level.String(),
			Source:    e.Source,
			Message:   e.Message,
			Computer:  e.Computer,
			LogName:   e.LogName,
		})
	}

	alertFilter := &storage.AlertFilter{
		Limit: 0,
	}
	if start != nil {
		alertFilter.StartTime = start
	}
	if end != nil {
		alertFilter.EndTime = end
	}

	maxAlerts := limit + offset + 100
	alertFilter.Limit = int(maxAlerts)
	alertFilter.Offset = 0
	alerts, err := h.db.AlertRepo().Query(alertFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch alerts for timeline: %v", err)
	}
	for _, a := range alerts {
		entries = append(entries, &TimelineEntry{
			ID:         a.ID,
			Timestamp:  a.FirstSeen,
			Type:       "alert",
			AlertID:    a.ID,
			Severity:   string(a.Severity),
			Message:    a.Message,
			RuleName:   a.RuleName,
			MITRE:      a.MITREAttack,
			LogName:    a.LogName,
			EventDBIDs: a.EventDBIDs,
		})
	}

	sortTimeline(entries)

	eventCount := len(events)
	alertCount := len(alerts)

	if offset > 0 && offset < len(entries) {
		entries = entries[offset:]
	} else if offset >= len(entries) {
		entries = []*TimelineEntry{}
	}

	if len(entries) > limit {
		entries = entries[:limit]
	}

	totalItems := eventCount + alertCount
	hasMore := (offset + limit) < totalItems
	nextOffset := offset + limit
	if !hasMore {
		nextOffset = 0
	}

	c.JSON(200, TimelineResponse{
		Entries:    entries,
		TotalCount: totalItems,
		EventCount: eventCount,
		AlertCount: alertCount,
		HasMore:    hasMore,
		NextOffset: nextOffset,
	})
}

// DeleteAlert godoc
// @Summary Delete alert from timeline
// @Description Delete an alert from the timeline by ID
// @Tags timeline
// @Accept json
// @Produce json
// @Param id path int true "Alert ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/timeline/alerts/{id} [delete]
func (h *TimelineHandler) DeleteAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "invalid alert id", Code: types.ErrCodeInvalidRequest})
		return
	}

	if err := h.db.AlertRepo().Delete(id); err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(200, SuccessResponse{Message: "Alert deleted"})
}

func sortTimeline(entries []*TimelineEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
}

// TimelineStats represents timeline statistics
type TimelineStats struct {
	TotalEvents  int64            `json:"total_events"`
	TotalAlerts  int64            `json:"total_alerts"`
	ByLevel      map[string]int64 `json:"by_level"`
	ByCategory   map[string]int64 `json:"by_category"`
	BySource     map[string]int64 `json:"by_source"`
	TopEventIDs  map[int32]int64  `json:"top_event_ids"`
	TimeRange    string           `json:"time_range"`
	AttackChains int              `json:"attack_chains"`
}

// AttackChainInfo represents information about an attack chain
type AttackChainInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Technique  string    `json:"technique"`
	Tactic     string    `json:"tactic"`
	Severity   string    `json:"severity"`
	EventCount int       `json:"event_count"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
}

// GetTimelineStats godoc
// @Summary Get timeline statistics
// @Description Get aggregated statistics for the timeline
// @Tags timeline
// @Accept json
// @Produce json
// @Param start_time query string false "Start time (RFC3339 format)"
// @Param end_time query string false "End time (RFC3339 format)"
// @Success 200 {object} TimelineStats
// @Failure 500 {object} ErrorResponse
// @Router /api/timeline/stats [get]
func (h *TimelineHandler) GetTimelineStats(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var start, end *time.Time
	if startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			start = &t
		}
	}
	if endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			end = &t
		}
	}

	eventFilter := &storage.EventFilter{Limit: 10000}
	if start != nil {
		eventFilter.StartTime = start
	}
	if end != nil {
		eventFilter.EndTime = end
	}

	events, _, err := h.db.ListEvents(eventFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch events for timeline stats: %v", err)
	}

	stats := &TimelineStats{
		ByLevel:     make(map[string]int64),
		ByCategory:  make(map[string]int64),
		BySource:    make(map[string]int64),
		TopEventIDs: make(map[int32]int64),
	}

	stats.TotalEvents = int64(len(events))

	for _, e := range events {
		stats.ByLevel[e.Level.String()]++
		stats.BySource[e.Source]++
		stats.TopEventIDs[e.EventID]++
		stats.ByCategory[categorizeEventID(e.EventID)]++
	}

	alertFilter := &storage.AlertFilter{Limit: 1000}
	if start != nil {
		alertFilter.StartTime = start
	}
	if end != nil {
		alertFilter.EndTime = end
	}
	alerts, err := h.db.AlertRepo().Query(alertFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch alerts for timeline stats: %v", err)
	}
	stats.TotalAlerts = int64(len(alerts))

	if len(events) > 0 {
		stats.TimeRange = fmt.Sprintf("%.1f hours", events[len(events)-1].Timestamp.Sub(events[0].Timestamp).Hours())
	}

	c.JSON(200, stats)
}

func categorizeEventID(eventID int32) string {
	switch {
	case eventID >= 4624 && eventID <= 4628:
		return "Authentication"
	case eventID >= 4648 && eventID <= 4650:
		return "Remote Access"
	case eventID >= 4660 && eventID <= 4663:
		return "File/Registry"
	case eventID >= 4670 && eventID <= 4674:
		return "Authorization"
	case eventID == 4688 || eventID == 4689:
		return "Process"
	case eventID >= 4696 && eventID <= 4702:
		return "Scheduled Task/Service"
	case eventID >= 4720 && eventID <= 4735:
		return "Account"
	case eventID >= 4740 && eventID <= 4769:
		return "Account"
	default:
		return "Other"
	}
}

// GetAttackChains godoc
// @Summary Get attack chains
// @Description Detect and return attack chains from events
// @Tags timeline
// @Accept json
// @Produce json
// @Param start_time query string false "Start time (RFC3339 format)"
// @Param end_time query string false "End time (RFC3339 format)"
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/timeline/chains [get]
func (h *TimelineHandler) GetAttackChains(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var start, end *time.Time
	if startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			start = &t
		}
	}
	if endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			end = &t
		}
	}

	eventFilter := &storage.EventFilter{Limit: 10000}
	if start != nil {
		eventFilter.StartTime = start
	}
	if end != nil {
		eventFilter.EndTime = end
	}

	events, _, err := h.db.ListEvents(eventFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch events for attack chains: %v", err)
	}

	chains := detectAttackChains(events)

	c.JSON(200, gin.H{
		"chains": chains,
		"total":  len(chains),
	})
}

func detectAttackChains(events []*types.Event) []*AttackChainInfo {
	chains := make([]*AttackChainInfo, 0)

	bruteForceEvents := make([]*types.Event, 0)
	lateralMovementEvents := make([]*types.Event, 0)
	persistenceEvents := make([]*types.Event, 0)

	for _, e := range events {
		switch e.EventID {
		case 4625:
			bruteForceEvents = append(bruteForceEvents, e)
		case 4624, 4648:
			lateralMovementEvents = append(lateralMovementEvents, e)
		case 4698, 4699, 4702:
			persistenceEvents = append(persistenceEvents, e)
		}
	}

	if len(bruteForceEvents) >= 10 {
		chains = append(chains, &AttackChainInfo{
			ID:         "brute-force",
			Name:       "Brute Force Attack",
			Technique:  "T1110",
			Tactic:     "Credential Access",
			Severity:   "high",
			EventCount: len(bruteForceEvents),
			StartTime:  bruteForceEvents[0].Timestamp,
			EndTime:    bruteForceEvents[len(bruteForceEvents)-1].Timestamp,
		})
	}

	if len(lateralMovementEvents) >= 3 {
		chains = append(chains, &AttackChainInfo{
			ID:         "lateral-movement",
			Name:       "Lateral Movement",
			Technique:  "T1021",
			Tactic:     "Lateral Movement",
			Severity:   "high",
			EventCount: len(lateralMovementEvents),
			StartTime:  lateralMovementEvents[0].Timestamp,
			EndTime:    lateralMovementEvents[len(lateralMovementEvents)-1].Timestamp,
		})
	}

	if len(persistenceEvents) > 0 {
		chains = append(chains, &AttackChainInfo{
			ID:         "persistence",
			Name:       "Persistence Mechanism",
			Technique:  "T1053",
			Tactic:     "Persistence",
			Severity:   "medium",
			EventCount: len(persistenceEvents),
			StartTime:  persistenceEvents[0].Timestamp,
			EndTime:    persistenceEvents[len(persistenceEvents)-1].Timestamp,
		})
	}

	return chains
}

// ExportTimeline godoc
// @Summary Export timeline
// @Description Export timeline events in various formats (json, csv, html)
// @Tags timeline
// @Accept json
// @Produce json
// @Param format query string false "Export format (json/csv/html)" default(json)
// @Param start_time query string false "Start time (RFC3339 format)"
// @Param end_time query string false "End time (RFC3339 format)"
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/timeline/export [get]
func (h *TimelineHandler) ExportTimeline(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	var start, end *time.Time
	if startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			start = &t
		}
	}
	if endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			end = &t
		}
	}

	eventFilter := &storage.EventFilter{Limit: 5000}
	if start != nil {
		eventFilter.StartTime = start
	}
	if end != nil {
		eventFilter.EndTime = end
	}

	events, _, err := h.db.ListEvents(eventFilter)
	if err != nil {
		log.Printf("[ERROR] failed to fetch events for timeline export: %v", err)
	}

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=timeline.csv")
		h.exportTimelineCSV(events, c.Writer)
	case "html":
		c.Header("Content-Type", "text/html")
		c.Header("Content-Disposition", "attachment; filename=timeline.html")
		h.exportTimelineHTML(events, c.Writer)
	default:
		c.JSON(200, gin.H{
			"events": events,
			"total":  len(events),
		})
	}
}

func (h *TimelineHandler) exportTimelineCSV(events []*types.Event, w gin.ResponseWriter) {
	fmt.Fprintf(w, "ID,Timestamp,EventID,Level,Source,LogName,Computer,User,Message\n")
	for _, e := range events {
		user := ""
		if e.User != nil {
			user = *e.User
		}
		fmt.Fprintf(w, "%d,%s,%d,%s,%s,%s,%s,%s,%s\n",
			e.ID, e.Timestamp.Format(time.RFC3339), e.EventID,
			e.Level.String(), e.Source, e.LogName, e.Computer,
			user, e.Message)
	}
}

func (h *TimelineHandler) exportTimelineHTML(events []*types.Event, w gin.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WinLogAnalyzer Timeline</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a1a2e; color: #eee; padding: 20px; }
        .timeline { position: relative; padding-left: 30px; }
        .timeline::before { content: ''; position: absolute; left: 10px; top: 0; bottom: 0; width: 2px; background: #3498db; }
        .event { position: relative; margin-bottom: 20px; padding: 10px 15px; background: #16213e; border-radius: 5px; }
        .event::before { content: ''; position: absolute; left: -25px; top: 15px; width: 10px; height: 10px; border-radius: 50%; background: #3498db; }
        .level-critical { border-left: 3px solid #dc3545; }
        .level-error { border-left: 3px solid #fd7e14; }
        .level-warning { border-left: 3px solid #ffc107; }
        .level-info { border-left: 3px solid #3498db; }
        .event-id { color: #00d9ff; font-weight: bold; }
        .timestamp { color: #888; font-size: 0.85em; }
    </style>
</head>
<body>
    <h2>WinLogAnalyzer Timeline</h2>
    <p>Total Events: %d</p>
    <div class="timeline">
`
	fmt.Fprintf(w, html, len(events))

	for _, e := range events {
		level := strings.ToLower(e.Level.String())
		fmt.Fprintf(w, `        <div class="event level-%s">
            <div class="timestamp">%s</div>
            <div><span class="event-id">EventID: %d</span> - %s</div>
            <div>Source: %s | Computer: %s</div>
        </div>
`, level, e.Timestamp.Format("2006-01-02 15:04:05"), e.EventID, e.Message, e.Source, e.Computer)
	}

	fmt.Fprint(w, `
    </div>
</body>
</html>`)
}
