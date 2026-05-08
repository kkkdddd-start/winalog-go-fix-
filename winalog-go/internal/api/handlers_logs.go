package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"go.uber.org/zap"
)

type LogsHandler struct{}

func NewLogsHandler() *LogsHandler {
	return &LogsHandler{}
}

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

	logFile := observability.GetLogFile()
	if logFile == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "log file not available"})
		return
	}

	entries, total, err := logFile.ReadJSONEntries(offset, limit)
	if err != nil {
		observability.Error("GetLogs failed", zap.String("module", "handlers_logs"), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if keyword != "" {
		kw := keyword
		var filtered []observability.LogFileEntry
		for _, e := range entries {
			if matchEntry(e, kw, level, category) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
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

func matchEntry(e observability.LogFileEntry, keyword, level, category string) bool {
	if keyword != "" {
		kw := strings.ToLower(keyword)
		if !strings.Contains(strings.ToLower(e.Message), kw) &&
			!strings.Contains(strings.ToLower(e.Level), kw) &&
			!strings.Contains(strings.ToLower(e.Category), kw) &&
			!strings.Contains(strings.ToLower(e.Error), kw) &&
			!strings.Contains(strings.ToLower(e.Path), kw) &&
			!strings.Contains(strings.ToLower(e.Method), kw) {
			return false
		}
	}
	if level != "" && level != "all" && e.Level != level {
		return false
	}
	if category != "" && category != "all" && e.Category != category {
		return false
	}
	return true
}

func (h *LogsHandler) GetLogFiles(c *gin.Context) {
	var files []observability.LogFileInfo

	appLogFile := observability.GetLogFile()
	if appLogFile != nil {
		files = append(files, appLogFile.GetLogFiles()...)
	}

	c.JSON(http.StatusOK, gin.H{
		"files": files,
		"count": len(files),
	})
}

func (h *LogsHandler) GetLogFileContent(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "filename is required"})
		return
	}

	var targetPath string

	appLogFile := observability.GetLogFile()
	if appLogFile != nil {
		for _, f := range appLogFile.GetLogFiles() {
			if f.Name == filename {
				targetPath = f.Path
				break
			}
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

func (h *LogsHandler) GetLogEntry(c *gin.Context) {
	filename := c.Param("filename")
	lineNumStr := c.Param("line")
	if filename == "" || lineNumStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "filename and line number are required"})
		return
	}

	lineNum, err := strconv.Atoi(lineNumStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid line number"})
		return
	}

	var targetPath string
	appLogFile := observability.GetLogFile()
	if appLogFile != nil {
		for _, f := range appLogFile.GetLogFiles() {
			if f.Name == filename {
				targetPath = f.Path
				break
			}
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

	var line string
	buf := make([]byte, 1)
	lineBytes := make([]byte, 0, 4096)
	currentLine := 1

	for {
		n, err := file.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				if currentLine == lineNum {
					line = string(lineBytes)
					break
				}
				lineBytes = lineBytes[:0]
				currentLine++
			} else {
				lineBytes = append(lineBytes, buf[0])
			}
		}
		if err != nil {
			break
		}
	}

	if line == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "line not found"})
		return
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"filename": filename,
			"line":     lineNum,
			"raw":      line,
		})
		return
	}

	dir := filepath.Dir(targetPath)
	c.JSON(http.StatusOK, gin.H{
		"filename": filename,
		"line":     lineNum,
		"entry":    entry,
		"file":     dir,
	})
}

func SetupLogsRoutes(r *gin.Engine, logsHandler *LogsHandler) {
	logs := r.Group("/api/logs")
	{
		logs.GET("", logsHandler.GetLogs)
		logs.GET("/files", logsHandler.GetLogFiles)
		logs.GET("/files/:filename", logsHandler.GetLogFileContent)
		logs.GET("/files/:filename/line/:line", logsHandler.GetLogEntry)
	}
}
