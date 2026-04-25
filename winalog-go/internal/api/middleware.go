package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/config"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
)

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		logEntry := observability.APILogEntry{
			Timestamp: start.Format(time.RFC3339),
			Level:     getLogLevel(statusCode),
			Message:   "[API]",
			Status:    statusCode,
			Latency:   latency.String(),
			ClientIP:  clientIP,
			Method:    method,
			Path:      path,
		}

		jsonBytes, _ := json.Marshal(logEntry)
		jsonBytes = append(jsonBytes, '\n')

		os.Stdout.Write(jsonBytes)

		if lf := getLogFile(); lf != nil {
			_, _ = lf.Write(jsonBytes)
		}

		observability.LogAPIRequest(logEntry)
	}
}

func getLogLevel(statusCode int) string {
	switch {
	case statusCode >= 500:
		return "error"
	case statusCode >= 400:
		return "warn"
	default:
		return "info"
	}
}

var logFileInstance *os.File

func getLogFile() *os.File {
	return logFileInstance
}

func initLogFile() error {
	exePath, err := os.Executable()
	if err != nil {
		exePath, _ = os.Getwd()
	}
	exeDir := filepath.Dir(exePath)
	logDir := filepath.Join(exeDir, "logs")

	if err := os.MkdirAll(logDir, 0755); err != nil {
		logDir = os.TempDir()
	}

	logPath := filepath.Join(logDir, "winalog_metrics.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	logFileInstance = file

	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("[INFO] log file initialized: %s", logPath)

	return nil
}

var defaultAllowedOrigins = []string{
	"http://localhost:3000",
	"http://localhost:8080",
}

func corsMiddleware(cfg *config.CORSConfig) gin.HandlerFunc {
	if cfg == nil || len(cfg.AllowedOrigins) == 0 {
		cfg = &config.CORSConfig{
			AllowedOrigins: defaultAllowedOrigins,
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
			AllowedHeaders: []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "accept", "origin", "Cache-Control", "X-Requested-With"},
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		allowedOrigin := ""
		for _, ao := range cfg.AllowedOrigins {
			if ao == "*" || origin == ao {
				allowedOrigin = ao
				break
			}
		}

		if allowedOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			if allowedOrigin != "*" {
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		c.Writer.Header().Set("Access-Control-Allow-Headers", stringsJoin(cfg.AllowedHeaders, ", "))
		c.Writer.Header().Set("Access-Control-Allow-Methods", stringsJoin(cfg.AllowedMethods, ", "))

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func stringsJoin(elems []string, sep string) string {
	return strings.Join(elems, sep)
}

func recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] %v", err)

				panicEntry := struct {
					Timestamp string `json:"timestamp"`
					Level     string `json:"level"`
					Message   string `json:"message"`
					Error     string `json:"error"`
					Path      string `json:"path"`
				}{
					Timestamp: time.Now().Format(time.RFC3339),
					Level:     "fatal",
					Message:   "[PANIC]",
					Error:     fmt.Sprintf("%v", err),
					Path:      c.Request.URL.Path,
				}

				jsonBytes, _ := json.Marshal(panicEntry)
				jsonBytes = append(jsonBytes, '\n')
				os.Stdout.Write(jsonBytes)

				if lf := getLogFile(); lf != nil {
					_, _ = lf.Write(jsonBytes)
				}

				c.AbortWithStatusJSON(500, gin.H{
					"error": "Internal server error",
				})
			}
		}()
		c.Next()
	}
}
