package api

import (
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
)

type LogsHandler struct{}

// NewLogsHandler godoc
// @Summary 创建日志处理器
// @Description 初始化LogsHandler
// @Tags logs
// @Router /api/logs [get]
func NewLogsHandler() *LogsHandler {
	return &LogsHandler{}
}

// GetLogs godoc
// @Summary 获取应用日志
// @Description 返回系统运行日志记录
// @Tags logs
// @Produce json
// @Param offset query int false "偏移量" default(0)
// @Param limit query int false "返回数量限制" default(100)
// @Param keyword query string false "关键词过滤"
// @Param level query string false "日志级别过滤"
// @Param category query string false "日志分类过滤"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/logs [get]
func (h *LogsHandler) GetLogs(c *gin.Context) {
	offsetStr := c.DefaultQuery("offset", "0")
	limitStr := c.DefaultQuery("limit", "100")
	keyword := c.Query("keyword")
	level := c.Query("level")
	category := c.Query("category")

	offset, _ := strconv.Atoi(offsetStr)
	limit, _ := strconv.Atoi(limitStr)

	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	metricsLogger := observability.GetMetricsLogger()
	entries, total, err := metricsLogger.ReadLines(offset, limit, keyword, level, category)
	if err != nil {
		log.Printf("[ERROR] GetLogs failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entries":  entries,
		"total":    total,
		"offset":   offset,
		"limit":    limit,
		"keyword":  keyword,
		"level":    level,
		"category": category,
	})
}

// GetLogFiles godoc
// @Summary 获取日志文件列表
// @Description 返回所有可用的日志文件
// @Tags logs
// @Produce json
// @Success 200 {object} map[string]interface{} "files": []object, "count": int
// @Router /api/logs/files [get]
func (h *LogsHandler) GetLogFiles(c *gin.Context) {
	metricsLogger := observability.GetMetricsLogger()
	files := metricsLogger.GetLogFiles()

	c.JSON(http.StatusOK, gin.H{
		"files": files,
		"count": len(files),
	})
}

// GetLogFileContent godoc
// @Summary 获取日志文件内容
// @Description 返回指定日志文件的完整内容
// @Tags logs
// @Produce json
// @Param filename path string true "日志文件名"
// @Success 200 {object} map[string]interface{} "path": string, "content": string
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/logs/files/{filename} [get]
func (h *LogsHandler) GetLogFileContent(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "filename is required"})
		return
	}

	metricsLogger := observability.GetMetricsLogger()
	files := metricsLogger.GetLogFiles()

	var targetPath string
	for _, f := range files {
		if f.Name == filename {
			targetPath = f.Path
			break
		}
	}

	if targetPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "log file not found"})
		return
	}

	file, err := os.Open(targetPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open log file"})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read log file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"path":    targetPath,
		"content": string(content),
	})
}

// SetupLogsRoutes godoc
// @Summary 设置日志路由
// @Description 配置日志相关的API路由
// @Tags logs
// @Router /api/logs [get]
// @Router /api/logs/files [get]
// @Router /api/logs/files/{filename} [get]
func SetupLogsRoutes(r *gin.Engine, logsHandler *LogsHandler) {
	logs := r.Group("/api/logs")
	{
		logs.GET("", logsHandler.GetLogs)
		logs.GET("/files", logsHandler.GetLogFiles)
		logs.GET("/files/:filename", logsHandler.GetLogFileContent)
	}
}
