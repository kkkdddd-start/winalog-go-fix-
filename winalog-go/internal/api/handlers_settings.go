package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/config"
)

type SettingsHandler struct {
	cfg        *config.Config
	configPath string
}

type Settings struct {
	DatabasePath         string `json:"database_path"`
	LogLevel             string `json:"log_level"`
	MaxEvents            int    `json:"max_events"`
	RetentionDays        int    `json:"retention_days"`
	EnableAlerting       bool   `json:"enable_alerting"`
	EnableLiveCollection bool   `json:"enable_live_collection"`
	EnableAutoUpdate     bool   `json:"enable_auto_update"`
	APIPort              int    `json:"api_port"`
	APIHost              string `json:"api_host"`
	CORSEnabled          bool   `json:"cors_enabled"`
	MaxImportFileSize    int    `json:"max_import_file_size"`
	ExportDirectory      string `json:"export_directory"`
	ParserWorkers        int    `json:"parser_workers"`
	MemoryLimit          int    `json:"memory_limit"`
	RequestTimeout       int    `json:"request_timeout"`
}

// NewSettingsHandler godoc
// @Summary 创建设置处理器
// @Description 初始化SettingsHandler
// @Tags settings
// @Param cfg query string true "配置实例"
// @Param configPath query string true "配置文件路径"
// @Router /api/settings [get]
func NewSettingsHandler(cfg *config.Config, configPath string) *SettingsHandler {
	return &SettingsHandler{
		cfg:        cfg,
		configPath: configPath,
	}
}

// GetSettings godoc
// @Summary 获取设置
// @Description 返回当前系统的所有配置设置
// @Tags settings
// @Produce json
// @Success 200 {object} Settings
// @Router /api/settings [get]
func (h *SettingsHandler) GetSettings(c *gin.Context) {
	retentionDays := int(h.cfg.Alerts.StatsRetention.Hours() / 24)
	c.JSON(http.StatusOK, Settings{
		DatabasePath:         h.cfg.Database.Path,
		LogLevel:             h.cfg.Log.Level,
		MaxEvents:            h.cfg.Search.MaxResults,
		RetentionDays:        retentionDays,
		EnableAlerting:       h.cfg.Alerts.Enabled,
		EnableLiveCollection: h.cfg.Alerts.EnableCollection,
		EnableAutoUpdate:     h.cfg.TUI.AutoUpdate,
		APIPort:              h.cfg.API.Port,
		APIHost:              h.cfg.API.Host,
		CORSEnabled:          len(h.cfg.API.CORS.AllowedOrigins) > 0,
		MaxImportFileSize:    h.cfg.Import.BatchSize,
		ExportDirectory:      h.cfg.Report.OutputDir,
		ParserWorkers:        h.cfg.Parser.Workers,
		MemoryLimit:          h.cfg.Parser.MemoryLimit,
		RequestTimeout:       int(h.cfg.API.RequestTimeout.Seconds()),
	})
}

// SaveSettings godoc
// @Summary 保存设置
// @Description 保存系统配置设置
// @Tags settings
// @Accept json
// @Produce json
// @Param settings body Settings true "设置内容"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Router /api/settings [post]
func (h *SettingsHandler) SaveSettings(c *gin.Context) {
	var settings Settings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "invalid settings: " + err.Error(),
		})
		return
	}

	if settings.APIPort < 1 || settings.APIPort > 65535 {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "api_port must be between 1 and 65535",
		})
		return
	}

	h.cfg.Database.Path = settings.DatabasePath
	h.cfg.Log.Level = settings.LogLevel
	h.cfg.Search.MaxResults = settings.MaxEvents
	h.cfg.Alerts.Enabled = settings.EnableAlerting
	h.cfg.Alerts.EnableCollection = settings.EnableLiveCollection
	h.cfg.Alerts.StatsRetention = time.Duration(settings.RetentionDays) * 24 * time.Hour
	h.cfg.TUI.AutoUpdate = settings.EnableAutoUpdate
	h.cfg.API.Port = settings.APIPort
	h.cfg.API.Host = settings.APIHost
	h.cfg.Import.BatchSize = settings.MaxImportFileSize
	h.cfg.Report.OutputDir = settings.ExportDirectory
	h.cfg.Parser.Workers = settings.ParserWorkers
	h.cfg.Parser.MemoryLimit = settings.MemoryLimit
	h.cfg.API.RequestTimeout = time.Duration(settings.RequestTimeout) * time.Second

	if h.configPath != "" {
		loader := config.NewLoader()
		if err := loader.Save(h.cfg, h.configPath); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status":  "partial",
				"message": "Settings updated in memory, but failed to persist: " + err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "saved",
		"message": "Settings saved successfully.",
	})
}

// ResetSettings godoc
// @Summary 重置设置
// @Description 将所有设置重置为默认值
// @Tags settings
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/settings/reset [post]
func (h *SettingsHandler) ResetSettings(c *gin.Context) {
	defaultCfg := config.DefaultConfig()
	h.cfg.Database = defaultCfg.Database
	h.cfg.Import = defaultCfg.Import
	h.cfg.Search = defaultCfg.Search
	h.cfg.Alerts = defaultCfg.Alerts
	h.cfg.TUI = defaultCfg.TUI
	h.cfg.API = defaultCfg.API
	h.cfg.Report = defaultCfg.Report
	h.cfg.Log = defaultCfg.Log

	if h.configPath != "" {
		loader := config.NewLoader()
		if err := loader.Save(h.cfg, h.configPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "reset",
		"message": "Settings reset to defaults.",
	})
}

func (h *SettingsHandler) UpdateConfig(cfg *config.Config) {
	h.cfg = cfg
}

// SetupSettingsRoutes godoc
// @Summary 设置设置路由
// @Description 配置系统设置相关的API路由
// @Tags settings
// @Router /api/settings [get]
// @Router /api/settings [post]
// @Router /api/settings/reset [post]
func SetupSettingsRoutes(r *gin.Engine, settingsHandler *SettingsHandler) {
	settings := r.Group("/api/settings")
	{
		settings.GET("", settingsHandler.GetSettings)
		settings.POST("", settingsHandler.SaveSettings)
		settings.POST("/reset", settingsHandler.ResetSettings)
	}
}
