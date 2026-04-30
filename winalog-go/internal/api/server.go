package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/alerts"
	"github.com/kkkdddd-start/winalog-go/internal/analyzers"
	"github.com/kkkdddd-start/winalog-go/internal/config"
	"github.com/kkkdddd-start/winalog-go/internal/monitor"
	monitorApi "github.com/kkkdddd-start/winalog-go/internal/monitor/api"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type Server struct {
	engine         *gin.Engine
	httpServer     *http.Server
	db             *storage.DB
	cfg            *config.Config
	configPath     string
	addr           string
	alertEngine    *alerts.Engine
	alertEng       *AlertHandler
	importEng      *ImportHandler
	liveEng        *LiveHandler
	persistenceEng *PersistenceHandler
	timelineEng    *TimelineHandler
	systemEng      *SystemHandler
	rulesEng       *RulesHandler
	reportsEng     *ReportsHandler
	forensicsEng   *ForensicsHandler
	dashboardEng   *DashboardHandler
	settingsEng    *SettingsHandler
	analyzeEng     *AnalyzeHandler
	collectEng     *CollectHandler
	suppressEng    *SuppressHandler
	uebaEng        *UEBAHandler
	correlationEng *CorrelationHandler
	multiEng       *MultiHandler
	queryEng       *QueryHandler
	policyEng      *PolicyHandler
	uiEng          *UIHandler
	logsEng        *LogsHandler
	monitorEng     *monitorApi.MonitorHandler
}

func NewServer(db *storage.DB, cfg *config.Config, configPath, addr string) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	_ = initLogFile()
	observability.InitMetricsLogger()

	engine.Use(recoveryMiddleware())
	engine.Use(requestLogger())
	engine.Use(corsMiddleware(&cfg.API.CORS))

	server := &Server{
		engine:     engine,
		db:         db,
		cfg:        cfg,
		configPath: configPath,
		addr:       addr,
	}

	server.setupHandlers()
	server.setupRoutes()

	return server
}

func (s *Server) setupHandlers() {
	s.alertEngine = alerts.NewEngine(s.db, alerts.EngineConfig{
		DedupWindow: 5 * time.Minute,
		StatsWindow: 24 * time.Hour,
	})
	s.alertEng = &AlertHandler{
		db:          s.db,
		alertEngine: s.alertEngine,
	}
	s.importEng = &ImportHandler{
		db:          s.db,
		alertEngine: s.alertEngine,
	}
	s.liveEng = NewLiveHandler(s.db)
	s.persistenceEng = NewPersistenceHandler(s.db)
	s.timelineEng = &TimelineHandler{
		db: s.db,
	}
	s.systemEng = NewSystemHandler(s.db)
	s.rulesEng = NewRulesHandler(s.db)
	s.reportsEng = NewReportsHandler(s.db)
	s.forensicsEng = NewForensicsHandler(s.db)
	s.dashboardEng = NewDashboardHandler(s.db)
	s.settingsEng = NewSettingsHandler(s.cfg, s.configPath)

	analyzerManager := analyzers.NewDefaultManager()
	s.analyzeEng = NewAnalyzeHandler(s.db, analyzerManager)

	s.collectEng = NewCollectHandler(s.db, s.alertEngine)
	s.suppressEng = NewSuppressHandler(s.db, s.alertEngine)
	s.uebaEng = NewUEBAHandler(s.db)
	s.correlationEng = NewCorrelationHandler(s.db)
	s.multiEng = NewMultiHandler(s.db)
	s.queryEng = NewQueryHandler(s.db)
	s.policyEng = NewPolicyHandler(s.alertEngine)
	s.uiEng = NewUIHandler(s.db)
	s.logsEng = NewLogsHandler()

	monitorEngine, err := monitor.NewMonitorEngine("monitor-config.json")
	if err == nil {
		s.monitorEng = monitorApi.NewMonitorHandler(monitorEngine)
		log.Println("[MONITOR] Live monitoring engine initialized successfully")
		log.Println("[MONITOR] Monitor routes registered: GET /api/monitor/stats, GET /api/monitor/events, POST /api/monitor/config")
	} else {
		log.Printf("[MONITOR] Failed to initialize live monitoring engine: %v", err)
		log.Println("[MONITOR] Live monitoring is disabled - this is expected on non-Windows systems")
	}
}

func (s *Server) setupRoutes() {
	SetupRoutes(s.engine, s.alertEng, s.importEng, s.liveEng, s.timelineEng, s.dashboardEng)
	SetupPersistenceRoutes(s.engine, s.persistenceEng)
	SetupSystemRoutes(s.engine, s.systemEng)
	SetupRulesRoutes(s.engine, s.rulesEng)
	SetupReportsRoutes(s.engine, s.reportsEng)
	SetupForensicsRoutes(s.engine, s.forensicsEng)
	SetupSettingsRoutes(s.engine, s.settingsEng)
	SetupAnalyzeRoutes(s.engine, s.analyzeEng)
	SetupCollectRoutes(s.engine, s.collectEng)
	SetupSuppressRoutes(s.engine, s.suppressEng)
	SetupUEBARoutes(s.engine, s.uebaEng)
	SetupCorrelationRoutes(s.engine, s.correlationEng)
	SetupMultiRoutes(s.engine, s.multiEng)
	SetupQueryRoutes(s.engine, s.queryEng)
	SetupPolicyRoutes(s.engine, s.policyEng)
	SetupUIRoutes(s.engine, s.uiEng)
	SetupLogsRoutes(s.engine, s.logsEng)
	if s.monitorEng != nil {
		monitorApi.SetupMonitorRoutes(s.engine, s.monitorEng)
	}

	s.engine.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		if strings.Contains(path, "..") {
			log.Printf("[WARN] Blocked path traversal attempt: %s", path)
			c.Data(403, "text/plain", []byte("Forbidden"))
			return
		}

		if path == "/" {
			path = "/index.html"
			filePath := "index.html"
			content, err := staticFiles.ReadFile("_statich/" + filePath)
			if err != nil {
				c.Data(404, "text/plain", []byte("Not found"))
				return
			}
			c.Header("Content-Type", "text/html")
			c.Data(200, "text/html", content)
			return
		}

		hasExtension := strings.Contains(path, ".")
		filePath := getStaticFilePath(path)
		content, err := staticFiles.ReadFile("_statich/" + filePath)
		if err != nil {
			if hasExtension {
				c.Data(404, "text/plain", []byte("Not found"))
			} else {
				indexContent, indexErr := staticFiles.ReadFile("_statich/index.html")
				if indexErr != nil {
					c.Data(404, "text/plain", []byte("Not found"))
					return
				}
				c.Header("Content-Type", "text/html")
				c.Data(200, "text/html", indexContent)
			}
			return
		}

		contentType := getStaticContentType(filePath)
		c.Header("Content-Type", contentType)
		c.Data(200, contentType, content)
	})
}

func (s *Server) Start() error {
	log.Printf("Starting HTTP API server on %s", s.addr)

	requestTimeout := s.cfg.API.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 5 * time.Minute
	}
	writeTimeout := requestTimeout * 2
	if writeTimeout < 10*time.Minute {
		writeTimeout = 10 * time.Minute
	}

	s.httpServer = &http.Server{
		Addr:           s.addr,
		Handler:        s.engine,
		ReadTimeout:    requestTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("HTTP server timeouts - Read: %v, Write: %v", requestTimeout, writeTimeout)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Shutting down HTTP server gracefully...")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}
	log.Println("HTTP server gracefully stopped")

	if logFileInstance != nil {
		logFileInstance.Close()
		logFileInstance = nil
	}

	return nil
}

func (s *Server) ReloadConfig(cfg *config.Config) {
	s.cfg = cfg
	s.settingsEng.UpdateConfig(cfg)
	log.Println("Configuration reloaded successfully")
}

func getStaticContentType(path string) string {
	path = strings.ToLower(path)
	if strings.HasSuffix(path, ".html") {
		return "text/html"
	}
	if strings.HasSuffix(path, ".css") {
		return "text/css"
	}
	if strings.HasSuffix(path, ".js") {
		return "application/javascript"
	}
	if strings.HasSuffix(path, ".json") {
		return "application/json"
	}
	if strings.HasSuffix(path, ".png") {
		return "image/png"
	}
	if strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg") {
		return "image/jpeg"
	}
	if strings.HasSuffix(path, ".svg") {
		return "image/svg+xml"
	}
	if strings.HasSuffix(path, ".ico") {
		return "image/x-icon"
	}
	if strings.HasSuffix(path, ".woff") {
		return "font/woff"
	}
	if strings.HasSuffix(path, ".woff2") {
		return "font/woff2"
	}
	if strings.HasSuffix(path, ".ttf") {
		return "font/ttf"
	}
	if strings.HasSuffix(path, ".eot") {
		return "application/vnd.ms-fontobject"
	}
	return "application/octet-stream"
}
