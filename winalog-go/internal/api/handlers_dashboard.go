package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type DashboardHandler struct {
	db *storage.DB
}

type CollectionStatsResponse struct {
	TotalEvents int64            `json:"total_events"`
	TotalSize   string           `json:"total_size"`
	Sources     map[string]int64 `json:"sources"`
	LastImport  string           `json:"last_import"`
}

// NewDashboardHandler godoc
// @Summary 创建仪表板处理器
// @Description 初始化DashboardHandler
// @Tags dashboard
// @Param db query string true "数据库实例"
// @Router /api/dashboard [get]
func NewDashboardHandler(db *storage.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

// GetLogNames godoc
// @Summary 获取日志名称列表
// @Description 返回数据库中所有不重复的日志名称
// @Tags dashboard
// @Produce json
// @Success 200 {object} map[string]interface{} "log_names": []string
// @Failure 500 {object} ErrorResponse
// @Router /api/dashboard/log-names [get]
func (h *DashboardHandler) GetLogNames(c *gin.Context) {
	rows, err := h.db.Query(`
		SELECT DISTINCT log_name
		FROM events
		ORDER BY log_name ASC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	var logNames []string
	for rows.Next() {
		var logName string
		if err := rows.Scan(&logName); err == nil {
			logNames = append(logNames, logName)
		}
	}

	c.JSON(http.StatusOK, gin.H{"log_names": logNames})
}

// GetCollectionStats godoc
// @Summary 获取收集统计信息
// @Description 返回事件收集的统计数据，包括总数、大小、数据源等
// @Tags dashboard
// @Produce json
// @Success 200 {object} CollectionStatsResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/dashboard/stats [get]
func (h *DashboardHandler) GetCollectionStats(c *gin.Context) {
	stats, err := h.db.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	sources := make(map[string]int64)
	rows, err := h.db.Query(`
		SELECT log_name, COUNT(*) as count 
		FROM events 
		GROUP BY log_name 
		ORDER BY count DESC
		LIMIT 10
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var logName string
			var count int64
			if err := rows.Scan(&logName, &count); err == nil {
				sources[logName] = count
			}
		}
	}

	var lastImportStr string
	var lastImportTime sql.NullString
	row := h.db.QueryRow(`
		SELECT import_time FROM import_log 
		WHERE status = 'success' 
		ORDER BY import_time DESC LIMIT 1
	`)
	if err := row.Scan(&lastImportTime); err == nil && lastImportTime.Valid {
		lastImportStr = lastImportTime.String
	}

	totalSize := formatBytes(stats.DatabaseSize)

	c.JSON(http.StatusOK, CollectionStatsResponse{
		TotalEvents: stats.EventCount,
		TotalSize:   totalSize,
		Sources:     sources,
		LastImport:  lastImportStr,
	})
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return "< 1 KB"
	}

	exp := 0
	size := float64(bytes)
	for size >= unit {
		size /= unit
		exp++
	}

	if exp >= len("KMGTPE") {
		return "> 1 PB"
	}

	return fmt.Sprintf("%.1f%cB", size, "KMGTPE"[exp-1])
}
