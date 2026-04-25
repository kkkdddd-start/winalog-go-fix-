package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/exporters"
	"github.com/kkkdddd-start/winalog-go/internal/reports"
	reporttemplate "github.com/kkkdddd-start/winalog-go/internal/reports/template"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func parseReportTimeString(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}

	monotonicIdx := strings.Index(s, " m=")
	if monotonicIdx > 0 {
		s = s[:monotonicIdx]
	}

	formats := []string{
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05.999999999Z07:00:00",
		"2006-01-02T15:04:05.999999999 -0700",
		"2006-01-02T15:04:05.999999999 -0700 UTC",
		"2006-01-02T15:04:05 -0700",
		"2006-01-02T15:04:05 -0700 UTC",
		"2006-01-02T15:04:05Z",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

type ReportsHandler struct {
	db  *storage.DB
	svc *reports.ReportService
}

type ReportRequest struct {
	Type         string `json:"type" binding:"required"`
	Format       string `json:"format" binding:"required"`
	Language     string `json:"language"` // "en" or "zh"
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	IncludeRaw   bool   `json:"include_raw"`
	IncludeIOC   bool   `json:"include_ioc"`
	IncludeMITRE bool   `json:"include_mitre"`
	Compression  bool   `json:"compression"`
	Title        string `json:"title"`
	Description  string `json:"description"`
}

type ReportInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Format      string    `json:"format"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	GeneratedAt time.Time `json:"generated_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	FileSize    int64     `json:"file_size,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type ReportContent struct {
	Summary   *ReportSummary    `json:"summary,omitempty"`
	Alerts    []*ReportAlert    `json:"alerts,omitempty"`
	Events    []*ReportEvent    `json:"events,omitempty"`
	Timeline  []*ReportTimeline `json:"timeline,omitempty"`
	RawEvents []*types.Event    `json:"raw_events,omitempty"`
}

type ReportSummary struct {
	TotalEvents     int64            `json:"total_events"`
	TotalAlerts     int64            `json:"total_alerts"`
	CriticalAlerts  int64            `json:"critical_alerts"`
	HighAlerts      int64            `json:"high_alerts"`
	MediumAlerts    int64            `json:"medium_alerts"`
	LowAlerts       int64            `json:"low_alerts"`
	TopEventSources map[string]int64 `json:"top_sources"`
	TimeRange       TimeRange        `json:"time_range"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ReportAlert struct {
	ID        int64     `json:"id"`
	RuleName  string    `json:"rule_name"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	MITRE     []string  `json:"mitre_attack,omitempty"`
}

type ReportEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventID   int32     `json:"event_id"`
	Level     string    `json:"level"`
	Source    string    `json:"source"`
	LogName   string    `json:"log_name"`
	Computer  string    `json:"computer"`
	Message   string    `json:"message"`
}

type ReportTimeline struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity,omitempty"`
}

// NewReportsHandler godoc
// @Summary 创建报表处理器
// @Description 初始化ReportsHandler
// @Tags reports
// @Param db query string true "数据库实例"
// @Router /api/reports [get]
func NewReportsHandler(db *storage.DB) *ReportsHandler {
	return &ReportsHandler{
		db:  db,
		svc: reports.NewReportService(db),
	}
}

// ListReports godoc
// @Summary 列出报表
// @Description 返回所有已生成的报表
// @Tags reports
// @Produce json
// @Success 200 {object} map[string]interface{} "reports": []ReportInfo, "total": int
// @Failure 500 {object} ErrorResponse
// @Router /api/reports [get]
func (h *ReportsHandler) ListReports(c *gin.Context) {
	rows, err := h.db.Query(`
		SELECT id, report_type, format, title, description, status, generated_at, completed_at, file_path, file_size
		FROM reports 
		ORDER BY generated_at DESC 
		LIMIT 100
	`)
	if err != nil {
		log.Printf("[ERROR] ListReports failed: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	reports := make([]ReportInfo, 0)
	for rows.Next() {
		var r ReportInfo
		var generatedAtStr, completedAtStr sql.NullString
		var filePath sql.NullString
		var fileSize sql.NullInt64
		var title, description sql.NullString

		if err := rows.Scan(&r.ID, &r.Type, &r.Format, &title, &description, &r.Status, &generatedAtStr, &completedAtStr, &filePath, &fileSize); err != nil {
			continue
		}

		if title.Valid {
			r.Title = title.String
		}
		if description.Valid {
			r.Description = description.String
		}
		if generatedAtStr.Valid {
			r.GeneratedAt = parseReportTimeString(generatedAtStr.String)
		}
		if completedAtStr.Valid {
			r.CompletedAt = parseReportTimeString(completedAtStr.String)
		}
		if filePath.Valid {
			r.FilePath = filePath.String
		}
		if fileSize.Valid {
			r.FileSize = fileSize.Int64
		}

		reports = append(reports, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"reports": reports,
		"total":   len(reports),
	})
}

// GenerateReport godoc
// @Summary 生成报表
// @Description 异步生成新的报表
// @Tags reports
// @Accept json
// @Produce json
// @Param request body ReportRequest true "报表生成请求"
// @Success 200 {object} map[string]interface{} "id": string, "status": string, "download_url": string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/reports [post]
func (h *ReportsHandler) GenerateReport(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	reportID := fmt.Sprintf("report_%s_%d", req.Type, time.Now().UnixNano())
	reportDir := filepath.Join(os.TempDir(), "winalog_reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to create report directory"})
		return
	}

	generatedAt := time.Now()

	_, err := h.db.Exec(`
		INSERT INTO reports (id, report_type, format, title, description, status, generated_at, query_params)
		VALUES (?, ?, ?, ?, ?, 'generating', ?, ?)`,
		reportID, req.Type, req.Format, req.Title, req.Description, generatedAt, "")

	if err != nil {
		log.Printf("[ERROR] GenerateReport insert failed: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	go h.generateReportAsync(reportID, req, generatedAt)

	c.JSON(http.StatusOK, gin.H{
		"id":           reportID,
		"type":         req.Type,
		"format":       req.Format,
		"status":       "generating",
		"generated_at": generatedAt,
		"message":      "Report generation started",
		"download_url": fmt.Sprintf("/api/reports/%s/download", reportID),
	})
}

func (h *ReportsHandler) generateReportAsync(reportID string, req ReportRequest, generatedAt time.Time) {
	defer func() {
		if r := recover(); r != nil {
			errMsg := fmt.Sprintf("panic recovered: %v", r)
			log.Printf("[ERROR] generateReportAsync panic: %s", errMsg)
			_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
				errMsg, time.Now(), reportID)
		}
	}()

	report, err := h.svc.GenerateFromAPIRequest(&reports.APIReportRequest{
		Type:         req.Type,
		Format:       req.Format,
		Language:     req.Language,
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
		IncludeRaw:   req.IncludeRaw,
		IncludeIOC:   false,
		IncludeMITRE: false,
		Title:        req.Title,
		Description:  req.Description,
	})
	if err != nil {
		_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
			err.Error(), time.Now(), reportID)
		return
	}

	reportDir := filepath.Join(os.TempDir(), "winalog_reports")
	_ = os.MkdirAll(reportDir, 0755)
	fileName := fmt.Sprintf("%s.%s", reportID, req.Format)
	filePath := filepath.Join(reportDir, fileName)

	switch req.Format {
	case "pdf":
		if f, err := os.Create(filePath); err == nil {
			pdfReq := &reports.ReportRequest{
				Type:       req.Type,
				Title:      req.Title,
				Format:     reports.ReportFormat(req.Format),
				IncludeRaw: req.IncludeRaw,
			}
			if req.StartTime != "" || req.EndTime != "" {
				timeInput := req.StartTime
				if req.EndTime != "" {
					timeInput = req.StartTime + "," + req.EndTime
				}
				if tf, err := types.ParseTimeFilter(timeInput); err == nil && tf != nil {
					pdfReq.StartTime = tf.Start
					pdfReq.EndTime = tf.End
				}
			}
			err = h.svc.ExportPDF(pdfReq, f)
			f.Close()
			if err != nil {
				_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
					err.Error(), time.Now(), reportID)
				return
			}
		} else {
			_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
				err.Error(), time.Now(), reportID)
			return
		}
	case "html":
		if f, err := os.Create(filePath); err == nil {
			err = h.svc.ExportHTMLFromReport(report, f)
			f.Close()
			if err != nil {
				_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
					err.Error(), time.Now(), reportID)
				return
			}
		} else {
			_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
				err.Error(), time.Now(), reportID)
			return
		}
	default:
		apiContent := reports.AdaptReportToAPI(report)
		data, _ := json.MarshalIndent(apiContent, "", "  ")
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			_, _ = h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
				err.Error(), time.Now(), reportID)
			return
		}
	}

	fi, _ := os.Stat(filePath)
	fileSize := int64(0)
	if fi != nil {
		fileSize = fi.Size()
	}

	_, _ = h.db.Exec(`UPDATE reports SET status = 'completed', completed_at = ?, file_path = ?, file_size = ? WHERE id = ?`,
		time.Now(), filePath, fileSize, reportID)
}

// GetReport godoc
// @Summary 获取报表详情
// @Description 返回指定报表的详细信息
// @Tags reports
// @Produce json
// @Param id path string true "报表ID"
// @Success 200 {object} ReportInfo
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/reports/{id} [get]
func (h *ReportsHandler) GetReport(c *gin.Context) {
	reportID := c.Param("id")

	var report ReportInfo
	var generatedAtStr, completedAtStr sql.NullString
	var title, description, queryParams sql.NullString
	var filePath sql.NullString
	var fileSize sql.NullInt64

	err := h.db.QueryRow(`
		SELECT id, report_type, format, title, description, status, generated_at, completed_at, file_path, file_size, query_params
		FROM reports WHERE id = ?
	`, reportID).Scan(&report.ID, &report.Type, &report.Format, &title, &description, &report.Status,
		&generatedAtStr, &completedAtStr, &filePath, &fileSize, &queryParams)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "report not found"})
			return
		}
		log.Printf("[ERROR] GetReport query failed: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "GetReport query/scan error: " + err.Error()})
		return
	}

	if title.Valid {
		report.Title = title.String
	}
	if description.Valid {
		report.Description = description.String
	}
	if generatedAtStr.Valid {
		report.GeneratedAt = parseReportTimeString(generatedAtStr.String)
	}
	if completedAtStr.Valid {
		report.CompletedAt = parseReportTimeString(completedAtStr.String)
	}
	if filePath.Valid {
		report.FilePath = filePath.String
	}
	if fileSize.Valid {
		report.FileSize = fileSize.Int64
	}

	c.JSON(http.StatusOK, report)
}

// DownloadReport godoc
// @Summary 下载报表文件
// @Description 下载指定报表的文件内容
// @Tags reports
// @Produce json
// @Param id path string true "报表ID"
// @Success 200 {file} file "报表文件"
// @Failure 404 {object} ErrorResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/reports/{id}/download [get]
func (h *ReportsHandler) DownloadReport(c *gin.Context) {
	reportID := c.Param("id")

	var filePath string
	var format string
	var status string
	var errorMessage sql.NullString

	err := h.db.QueryRow(`
		SELECT COALESCE(file_path, ''), COALESCE(format, ''), COALESCE(status, ''), error_message
		FROM reports WHERE id = ?
	`, reportID).Scan(&filePath, &format, &status, &errorMessage)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "report not found"})
			return
		}
		log.Printf("[ERROR] DownloadReport query failed: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "GetReport query/scan error: " + err.Error()})
		return
	}

	if status == "generating" {
		c.JSON(http.StatusAccepted, gin.H{
			"status":    status,
			"message":   "Report is still being generated. Please wait and try again.",
			"report_id": reportID,
		})
		return
	}

	if status == "failed" {
		errMsg := "Report generation failed"
		if errorMessage.Valid && errorMessage.String != "" {
			errMsg = errorMessage.String
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Report generation failed: %s", errMsg),
		})
		return
	}

	if status != "completed" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Report is not ready for download. Current status: %s", status),
		})
		return
	}

	if filePath == "" {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Report file path not found in database"})
		return
	}

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		log.Printf("[ERROR] DownloadReport filepath.Abs failed: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to resolve file path: " + err.Error()})
		return
	}
	absReportDir, _ := filepath.Abs(filepath.Join(os.TempDir(), "winalog_reports"))
	if !strings.HasPrefix(absFilePath, absReportDir) {
		log.Printf("[WARN] DownloadReport blocked path traversal attempt: %s", filePath)
		c.JSON(http.StatusForbidden, ErrorResponse{Error: "Access denied"})
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Report file not found on disk"})
		return
	}

	fileName := filepath.Base(filePath)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.Header("Content-Type", getContentType(format))
	c.File(filePath)
}

func getContentType(format string) string {
	switch strings.ToLower(format) {
	case "pdf":
		return "application/pdf"
	case "html":
		return "text/html"
	case "json":
		return "application/json"
	case "csv":
		return "text/csv"
	default:
		return "application/octet-stream"
	}
}

type TemplateRequest struct {
	Name        string `json:"name" binding:"required"`
	Content     string `json:"content" binding:"required"`
	Description string `json:"description"`
}

// ListTemplates godoc
// @Summary 列出报表模板
// @Description 返回所有可用的报表模板
// @Tags reports
// @Produce json
// @Success 200 {object} map[string]interface{} "templates": []object, "total": int
// @Router /api/report-templates [get]
func (h *ReportsHandler) ListTemplates(c *gin.Context) {
	tmplMgr := reporttemplate.GetManager()
	infos := tmplMgr.ListTemplateInfo()

	c.JSON(200, gin.H{
		"templates": infos,
		"total":     len(infos),
	})
}

// GetTemplate godoc
// @Summary 获取报表模板详情
// @Description 返回指定报表模板的详细信息
// @Tags reports
// @Produce json
// @Param name path string true "模板名称"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} ErrorResponse
// @Router /api/report-templates/{name} [get]
func (h *ReportsHandler) GetTemplate(c *gin.Context) {
	name := c.Param("name")
	tmplMgr := reporttemplate.GetManager()

	if _, ok := tmplMgr.GetTemplate(name); ok {
		isCustom := tmplMgr.IsCustomTemplate(name)
		isBuiltIn := tmplMgr.IsBuiltInTemplate(name)

		c.JSON(200, gin.H{
			"name":        name,
			"content":     "",
			"template":    "",
			"is_custom":   isCustom,
			"is_built_in": isBuiltIn,
		})
		return
	}

	c.JSON(404, ErrorResponse{Error: "Template not found"})
}

// CreateTemplate godoc
// @Summary 创建报表模板
// @Description 创建新的自定义报表模板
// @Tags reports
// @Accept json
// @Produce json
// @Param request body TemplateRequest true "模板创建请求"
// @Success 201 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/report-templates [post]
func (h *ReportsHandler) CreateTemplate(c *gin.Context) {
	var req TemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}

	tmplMgr := reporttemplate.GetManager()
	if err := tmplMgr.SetCustomTemplate(req.Name, req.Content); err != nil {
		c.JSON(400, ErrorResponse{Error: "Invalid template: " + err.Error()})
		return
	}

	c.JSON(201, SuccessResponse{Message: "Template created"})
}

// UpdateTemplate godoc
// @Summary 更新报表模板
// @Description 更新指定报表模板的内容
// @Tags reports
// @Accept json
// @Produce json
// @Param name path string true "模板名称"
// @Param request body TemplateRequest true "模板更新请求"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/report-templates/{name} [put]
func (h *ReportsHandler) UpdateTemplate(c *gin.Context) {
	name := c.Param("name")

	var req TemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}

	tmplMgr := reporttemplate.GetManager()
	if err := tmplMgr.SetCustomTemplate(name, req.Content); err != nil {
		c.JSON(400, ErrorResponse{Error: "Invalid template: " + err.Error()})
		return
	}

	c.JSON(200, SuccessResponse{Message: "Template updated"})
}

// DeleteTemplate godoc
// @Summary 删除报表模板
// @Description 删除指定的自定义报表模板
// @Tags reports
// @Produce json
// @Param name path string true "模板名称"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/report-templates/{name} [delete]
func (h *ReportsHandler) DeleteTemplate(c *gin.Context) {
	name := c.Param("name")

	tmplMgr := reporttemplate.GetManager()
	if !tmplMgr.IsCustomTemplate(name) {
		c.JSON(404, ErrorResponse{Error: "Template not found or cannot be deleted"})
		return
	}

	tmplMgr.DeleteCustomTemplate(name)
	c.JSON(200, SuccessResponse{Message: "Template deleted"})
}

// ExportData godoc
// @Summary 导出事件数据
// @Description 导出事件数据为指定格式
// @Tags reports
// @Produce json
// @Param format query string false "导出格式" default(json)
// @Success 200 {file} file "导出文件"
// @Failure 500 {object} ErrorResponse
// @Router /api/reports/export [get]
func (h *ReportsHandler) ExportData(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	events, _, err := h.db.ListEvents(&storage.EventFilter{Limit: 1000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to fetch events"})
		return
	}

	factory := &exporters.ExporterFactory{}
	exporter := factory.Create(format)

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=events_export.%s", format))
	c.Header("Content-Type", exporter.ContentType())

	if err := exporter.Export(events, c.Writer); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
}

// SetupReportsRoutes godoc
// @Summary 设置报表路由
// @Description 配置报表相关的API路由
// @Tags reports
// @Router /api/reports [get]
// @Router /api/reports [post]
// @Router /api/reports/{id} [get]
// @Router /api/reports/{id}/download [get]
// @Router /api/reports/export [get]
// @Router /api/report-templates [get]
// @Router /api/report-templates/{name} [get]
// @Router /api/report-templates [post]
// @Router /api/report-templates/{name} [put]
// @Router /api/report-templates/{name} [delete]
func SetupReportsRoutes(r *gin.Engine, reportsHandler *ReportsHandler) {
	reportsGroup := r.Group("/api/reports")
	{
		reportsGroup.GET("", reportsHandler.ListReports)
		reportsGroup.POST("", reportsHandler.GenerateReport)
		reportsGroup.GET("/:id/download", reportsHandler.DownloadReport)
		reportsGroup.GET("/:id", reportsHandler.GetReport)
		reportsGroup.GET("/export", reportsHandler.ExportData)
	}

	templateGroup := r.Group("/api/report-templates")
	{
		templateGroup.GET("", reportsHandler.ListTemplates)
		templateGroup.GET("/:name", reportsHandler.GetTemplate)
		templateGroup.POST("", reportsHandler.CreateTemplate)
		templateGroup.PUT("/:name", reportsHandler.UpdateTemplate)
		templateGroup.DELETE("/:name", reportsHandler.DeleteTemplate)
	}
}
