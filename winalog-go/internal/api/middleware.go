package api

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/config"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"go.uber.org/zap"
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

		level := "info"
		if statusCode >= 500 {
			level = "error"
		} else if statusCode >= 400 {
			level = "warn"
		}

		observability.Info("api_request",
			zap.String("category", "api"),
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", statusCode),
			zap.Duration("latency", latency),
			zap.String("client_ip", clientIP),
			zap.String("level", level),
		)
	}
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
				observability.Error("panic_recovered",
					zap.String("category", "panic"),
					zap.String("module", "middleware"),
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
				)

				c.AbortWithStatusJSON(500, gin.H{
					"error": "Internal server error",
				})
			}
		}()
		c.Next()
	}
}
