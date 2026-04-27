package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/persistence"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

const (
	defaultDetectTimeout = 5 * time.Minute
	defaultCacheTTL      = 30 * time.Second
)

type PersistenceHandler struct {
	db               *storage.DB
	cache            *DetectionCache
	cacheMutex       sync.RWMutex
	detectorConfig   map[string]bool
	detectorMutex    sync.RWMutex
	detectionEngine  *persistence.DetectionEngine
	engineMutex      sync.RWMutex
	ruleConfigs      map[string]PersistenceRuleInfo
	ruleConfigsMutex sync.RWMutex
}

type DetectorConfig struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	Technique   string `json:"technique"`
	Category    string `json:"category"`
}

type DetectionCache struct {
	result    *persistence.DetectionResult
	timestamp time.Time
	params    string
	ttl       time.Duration
}

// NewPersistenceHandler godoc
// @Summary 创建持久化检测处理器
// @Description 初始化PersistenceHandler，注册所有持久化检测器
// @Tags persistence
// @Router /api/persistence [get]
func NewPersistenceHandler(db *storage.DB) *PersistenceHandler {
	engine := persistence.NewDetectionEngine()
	engine.RegisterAll(persistence.AllDetectors())

	whitelistStore := persistence.GetWhitelistStore()

	defaultRuleConfigs := map[string]PersistenceRuleInfo{
		"run_key_detector":              {Name: "run_key_detector", Description: "Run Key Persistence", Technique: "T1547.001", Category: "Registry", Enabled: true, EventIDs: []int32{4657}, Patterns: []string{"CurrentVersion\\Run", "CurrentVersion\\RunOnce"}, Whitelist: []string{"C:\\Windows\\System32\\*"}},
		"user_init_detector":            {Name: "user_init_detector", Description: "UserInit MPR Logon", Technique: "T1546.001", Category: "Registry", Enabled: true, EventIDs: []int32{4688}, Patterns: []string{"UserInitMprLogonScript"}, Whitelist: []string{}},
		"startup_folder_detector":       {Name: "startup_folder_detector", Description: "Startup Folder Persistence", Technique: "T1547.016", Category: "Registry", Enabled: true, EventIDs: []int32{4657}, Patterns: []string{"Startup"}, Whitelist: []string{}},
		"accessibility_detector":        {Name: "accessibility_detector", Description: "Accessibility Features Backdoor", Technique: "T1546.001", Category: "Accessibility", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"sethc.exe", "utilman.exe", "magnify.exe", "narrator.exe", "osk.exe", "displayswitch.exe"}, Whitelist: []string{"C:\\Windows\\System32\\*"}},
		"com_hijack_detector": {Name: "com_hijack_detector", Description: "COM Hijacking", Technique: "T1546.015", Category: "COM", Enabled: true, EventIDs: []int32{4670}, Patterns: []string{"HKEY_CURRENT_USER\\Software\\Classes\\"}, Whitelist: []string{}, BuiltinWhitelist: []string{
			"C:\\Windows\\System32",
			"C:\\Windows\\SysWOW64",
			"C:\\Windows",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\ProgramData",
			"%SystemRoot%\\System32",
			"%SystemRoot%\\SysWOW64",
			"%SystemRoot%",
			"%ProgramFiles%\\Java",
			"%ProgramFiles(x86)%\\Java",
			"D:\\Programs\\Java",
			"%CommonProgramFiles%\\Microsoft Shared\\Ink",
			"%CommonProgramFiles%\\System\\Ole DB",
			"%CommonProgramFiles%\\System\\msadc",
			"%CommonProgramFiles%\\ado",
			"%ProgramFiles%\\Common Files\\Microsoft Shared\\Ink",
			"%ProgramFiles%\\Common Files\\System\\Ole DB",
			"%ProgramFiles%\\Common Files\\System\\msadc",
			"%ProgramFiles%\\Common Files\\ado",
			"%windir%\\System32\\SecurityHealth",
			"%windir%\\System32\\F12",
		}, BuiltinDllWhitelist: []string{
			"InkObj.dll", "tabskb.dll", "rtscom.dll", "tipskins.dll", "tiptsf.dll",
			"mraut.DLL", "micaut.dll", "sqloledb.dll", "msdaosp.dll", "sqlxmlx.dll",
			"msdaps.dll", "msxactps.dll", "msdarem.dll", "msadds.dll", "msdasql.dll",
			"SecurityHealthAgent.dll", "SecurityHealthSSO.dll", "SecurityHealthProxyStub.dll",
			"wab32.dll", "wab32res.dll", "rdpcredentialprovider.dll", "amsi.dll",
			"amsiproxy.dll", "btpanui.dll", "AppxDeploymentClient.dll", "msdbg2.dll",
			"ole32.dll", "combase.dll", "mscoree.dll",
			"jp2iexp.dll", "jp2launch.dll", "jp2ser.dll", "jp2ssv.dll",
		}, BuiltinClsidsWhitelist: []string{
			"CAFEEFAC-", "00000300-", "00000303-", "00000304-", "00000305-",
			"00000306-", "00000308-", "00000309-",
		}, WhitelistType: "com"},
		"ifeo_detector":                 {Name: "ifeo_detector", Description: "IFEO Injection", Technique: "T1546.012", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"Debugger"}, Whitelist: []string{}},
		"appinit_detector":              {Name: "appinit_detector", Description: "AppInit DLLs", Technique: "T1546.010", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"AppInit_DLLs"}, Whitelist: []string{}},
		"wmi_persistence_detector":      {Name: "wmi_persistence_detector", Description: "WMI Event Subscription", Technique: "T1546.003", Category: "WMI", Enabled: true, EventIDs: []int32{4688, 5861}, Patterns: []string{"ActiveScriptEventConsumer"}, Whitelist: []string{}},
		"service_persistence_detector":  {Name: "service_persistence_detector", Description: "Service Persistence", Technique: "T1543.003", Category: "Service", Enabled: true, EventIDs: []int32{4697, 7045}, Patterns: []string{"sc.exe create"}, Whitelist: []string{}},
		"lsa_persistence_detector":      {Name: "lsa_persistence_detector", Description: "LSA Authentication Package", Technique: "T1546.008", Category: "Registry", Enabled: true, EventIDs: []int32{4670}, Patterns: []string{"Security Packages"}, Whitelist: []string{}},
		"winsock_detector":              {Name: "winsock_detector", Description: "Winsock Helper DLL", Technique: "T1546.007", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"NetworkProvider"}, Whitelist: []string{}},
		"bho_detector":                  {Name: "bho_detector", Description: "Browser Helper Object", Technique: "T1546.001", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"InprocServer32"}, Whitelist: []string{}},
		"print_monitor_detector":        {Name: "print_monitor_detector", Description: "Print Monitor", Technique: "T1546.001", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"Print\\Monitors"}, Whitelist: []string{}},
		"boot_execute_detector":         {Name: "boot_execute_detector", Description: "Boot Execute", Technique: "T1053", Category: "ScheduledTask", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"boot execute"}, Whitelist: []string{}},
		"etw_persistence_detector":      {Name: "etw_persistence_detector", Description: "ETW Manipulation", Technique: "T1546.006", Category: "Registry", Enabled: true, EventIDs: []int32{4670}, Patterns: []string{"ETW Providers"}, Whitelist: []string{}},
		"scheduled_task_detector":       {Name: "scheduled_task_detector", Description: "Scheduled Task Persistence", Technique: "T1053", Category: "ScheduledTask", Enabled: true, EventIDs: []int32{4698, 4699, 4700, 4701, 4702}, Patterns: []string{"powershell", "cmd.exe", "rundll32"}, Whitelist: []string{}},
		"appcert_detector":              {Name: "appcert_detector", Description: "AppCertDlls Persistence", Technique: "T1546.001", Category: "Registry", Enabled: true, EventIDs: []int32{4697}, Patterns: []string{"AppCertDlls"}, Whitelist: []string{}},
	}

	for _, d := range engine.ListDetectors() {
		detectorName := d.Name
		if baseConfig, exists := defaultRuleConfigs[detectorName]; exists {
			userWhitelist := whitelistStore.GetUserWhitelist(detectorName)
			dllWhitelist := whitelistStore.GetBuiltinDllWhitelist(detectorName)
			clsidsWhitelist := whitelistStore.GetBuiltinClsidsWhitelist(detectorName)

			whitelist := baseConfig.Whitelist
			if userWhitelist != nil {
				whitelist = userWhitelist
			}

			builtinDllWhitelist := baseConfig.BuiltinDllWhitelist
			if dllWhitelist != nil {
				builtinDllWhitelist = dllWhitelist
			}

			builtinClsidsWhitelist := baseConfig.BuiltinClsidsWhitelist
			if clsidsWhitelist != nil {
				builtinClsidsWhitelist = clsidsWhitelist
			}

			if err := engine.SetDetectorConfig(detectorName, &persistence.DetectorConfig{
				Enabled:               baseConfig.Enabled,
				EventIDs:              baseConfig.EventIDs,
				Patterns:              baseConfig.Patterns,
				Whitelist:            whitelist,
				BuiltinWhitelist:     baseConfig.BuiltinWhitelist,
				BuiltinDllWhitelist:  builtinDllWhitelist,
				BuiltinClsidsWhitelist: builtinClsidsWhitelist,
			}); err != nil {
				log.Printf("[WARN] [PERSISTENCE] Failed to set config for %s: %v", detectorName, err)
			}
			log.Printf("[INFO] [PERSISTENCE] Enabled detector: %s (enabled=%v)", detectorName, baseConfig.Enabled)
		}
	}

	return &PersistenceHandler{
		db: db,
		cache: &DetectionCache{
			ttl: defaultCacheTTL,
		},
		detectorConfig: map[string]bool{
			"run_key_detector":              true,
			"user_init_detector":            true,
			"startup_folder_detector":       true,
			"accessibility_detector":        true,
			"com_hijack_detector":           true,
			"ifeo_detector":                 true,
			"appinit_detector":              true,
			"wmi_persistence_detector":      true,
			"service_persistence_detector":  true,
			"lsa_persistence_detector":      true,
			"winsock_detector":              true,
			"bho_detector":                  true,
			"print_monitor_detector":        true,
			"boot_execute_detector":         true,
			"etw_persistence_detector":      true,
			"scheduled_task_detector":       true,
			"appcert_detector":             true,
		},
		detectionEngine: engine,
		ruleConfigs:     defaultRuleConfigs,
	}
}

type DetectRequest struct {
	Category  string `json:"category"`
	Technique string `json:"technique"`
}

type DetectResponse struct {
	Detections []*EnrichedDetection   `json:"detections"`
	Summary    map[string]interface{} `json:"summary"`
	Duration   string                 `json:"duration"`
	TotalCount int                    `json:"total_count"`
	Cached     bool                   `json:"cached,omitempty"`
}

type EnrichedDetection struct {
	ID                string                 `json:"id"`
	Time              time.Time              `json:"time"`
	Technique         string                 `json:"technique"`
	Category          string                 `json:"category"`
	Severity          string                 `json:"severity"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Evidence          map[string]interface{} `json:"evidence"`
	MITRERef          []string               `json:"mitre_ref"`
	RecommendedAction string                 `json:"recommended_action"`
	FalsePositiveRisk string                 `json:"false_positive_risk"`
	Explanation       string                 `json:"explanation"`
	Recommendation    string                 `json:"recommendation"`
	RealCase          string                 `json:"real_case"`
}

func enrichDetections(detections []*persistence.Detection) []*EnrichedDetection {
	enriched := make([]*EnrichedDetection, 0, len(detections))
	for _, d := range detections {
		explanation, recommendation, realCase := d.GetRuleDetails()
		enriched = append(enriched, &EnrichedDetection{
			ID:                d.ID,
			Time:              d.Time,
			Technique:         string(d.Technique),
			Category:          d.Category,
			Severity:          string(d.Severity),
			Title:             d.Title,
			Description:       d.Description,
			Evidence:          map[string]interface{}{"type": string(d.Evidence.Type), "key": d.Evidence.Key, "value": d.Evidence.Value, "file_path": d.Evidence.Path},
			MITRERef:          d.MITRERef,
			RecommendedAction: recommendation,
			FalsePositiveRisk: d.FalsePositiveRisk,
			Explanation:       explanation,
			Recommendation:    recommendation,
			RealCase:          realCase,
		})
	}
	return enriched
}

// Detect godoc
// @Summary 检测持久化威胁
// @Description 执行Windows持久化机制检测，包括注册表、计划任务、服务等
// @Tags persistence
// @Accept json
// @Produce json
// @Param category query string false "检测类别"
// @Param technique query string false "MITRE ATT&CK技术ID"
// @Param format query string false "返回格式" default(json)
// @Param timeout query string false "检测超时时间" default(5m)
// @Param force query string false "强制刷新缓存" default(false)
// @Success 200 {object} DetectResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/persistence/detect [get]
func (h *PersistenceHandler) Detect(c *gin.Context) {
	log.Printf("[DEBUG] Detect API called with category=%s, technique=%s, force=%s", c.Query("category"), c.Query("technique"), c.Query("force"))

	if runtime.GOOS != "windows" {
		log.Printf("[DEBUG] Detect API returning empty - not Windows")
		c.JSON(http.StatusOK, DetectResponse{
			Detections: []*EnrichedDetection{},
			Summary:    map[string]interface{}{},
			Duration:   "0s",
			TotalCount: 0,
		})
		return
	}

	var req DetectRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		log.Printf("[WARN] Detect API bad request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	forceRefresh := c.Query("force") == "true"

	format := c.DefaultQuery("format", "json")

	timeoutStr := c.DefaultQuery("timeout", "5m")
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil || timeout <= 0 {
		timeout = defaultDetectTimeout
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cacheParams := fmt.Sprintf("%s|%s", req.Category, req.Technique)

	if !forceRefresh && req.Category == "" && req.Technique == "" {
		h.cacheMutex.RLock()
		if h.cache.result != nil &&
			time.Since(h.cache.timestamp) < h.cache.ttl &&
			h.cache.params == cacheParams {
			log.Printf("[DEBUG] Detect API returning cached result")
			response := DetectResponse{
				Detections: enrichDetections(h.cache.result.Detections),
				Summary:    h.cache.result.Summary(),
				Duration:   h.cache.result.Duration.String(),
				TotalCount: h.cache.result.TotalCount,
				Cached:     true,
			}
			h.cacheMutex.RUnlock()
			c.JSON(http.StatusOK, response)
			return
		}
		h.cacheMutex.RUnlock()
	}

	if forceRefresh {
		log.Printf("[DEBUG] Detect API force refresh - clearing cache")
		h.cacheMutex.Lock()
		h.cache = &DetectionCache{ttl: defaultCacheTTL}
		h.cacheMutex.Unlock()
	}

	var result *persistence.DetectionResult

	h.engineMutex.RLock()
	engine := h.detectionEngine
	h.engineMutex.RUnlock()

	log.Printf("[DEBUG] Detect API starting detection with timeout=%v", timeout)

	if req.Technique != "" {
		result = engine.DetectTechnique(ctx, persistence.Technique(req.Technique))
	} else if req.Category != "" {
		result = engine.DetectCategory(ctx, req.Category)
	} else {
		result = engine.Detect(ctx)
	}

	if result == nil {
		result = &persistence.DetectionResult{
			Detections: []*persistence.Detection{},
		}
	}

	if result.Detections == nil {
		result.Detections = []*persistence.Detection{}
	}

	log.Printf("[INFO] Detect API completed: totalCount=%d, errorCount=%d", result.TotalCount, result.ErrorCount)

	if result.ErrorCount > 0 {
		for _, errMsg := range result.Errors {
			observability.LogServiceError("persistence_detector", errMsg)
		}
	}

	if req.Category == "" && req.Technique == "" {
		h.cacheMutex.Lock()
		h.cache.result = result
		h.cache.timestamp = time.Now()
		h.cache.params = cacheParams
		h.cacheMutex.Unlock()
	}

	if h.db != nil && len(result.Detections) > 0 {
		repo := storage.NewPersistenceDetectionRepo(h.db)
		if err := repo.SaveResult(result); err != nil {
			log.Printf("[ERROR] Failed to save persistence detections: %v", err)
		} else {
			log.Printf("[INFO] Saved %d persistence detections to database", len(result.Detections))
		}
	}

	if format == "csv" {
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=persistence_detections.csv")
		c.String(http.StatusOK, exportDetectionsToCSV(result.Detections))
		return
	}

	response := DetectResponse{
		Detections: enrichDetections(result.Detections),
		Summary:    result.Summary(),
		Duration:   result.Duration.String(),
		TotalCount: result.TotalCount,
	}

	c.JSON(http.StatusOK, response)
}

func exportDetectionsToCSV(detections []*persistence.Detection) string {
	return persistence.ExportDetectionsToCSVString(detections)
}

// ListCategories godoc
// @Summary 列出持久化检测类别
// @Description 返回所有可用的持久化检测类别
// @Tags persistence
// @Produce json
// @Success 200 {object} map[string]interface{} "categories": []object
// @Router /api/persistence/categories [get]
func (h *PersistenceHandler) ListCategories(c *gin.Context) {
	categories := []map[string]interface{}{
		{
			"name":        "Registry",
			"label":       "注册表",
			"description": "Registry-based persistence mechanisms",
			"techniques":  []string{"T1546.001", "T1546.010", "T1546.012", "T1546.015", "T1547.001", "T1547.016"},
		},
		{
			"name":        "ScheduledTask",
			"label":       "计划任务",
			"description": "Scheduled task/Job persistence",
			"techniques":  []string{"T1053", "T1053.020"},
		},
		{
			"name":        "Service",
			"label":       "服务持久化",
			"description": "Windows service persistence",
			"techniques":  []string{"T1543.003"},
		},
		{
			"name":        "WMI",
			"label":       "WMI持久化",
			"description": "WMI event subscription persistence",
			"techniques":  []string{"T1546.003"},
		},
		{
			"name":        "COM",
			"label":       "COM劫持",
			"description": "COM object hijacking persistence",
			"techniques":  []string{"T1546.015"},
		},
		{
			"name":        "BITS",
			"label":       "BITS作业",
			"description": "BITS persistence",
			"techniques":  []string{"T1197"},
		},
		{
			"name":        "Accessibility",
			"label":       "辅助功能后门",
			"description": "Accessibility features backdoor",
			"techniques":  []string{"T1546.001"},
		},
	}

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// ListTechniques godoc
// @Summary 列出MITRE ATT&CK技术
// @Description 返回所有支持的持久化检测技术
// @Tags persistence
// @Produce json
// @Success 200 {object} map[string]interface{} "techniques": []object
// @Router /api/persistence/techniques [get]
func (h *PersistenceHandler) ListTechniques(c *gin.Context) {
	techniques := []map[string]interface{}{
		{"id": "T1546.001", "name": "辅助功能后门", "category": "Accessibility"},
		{"id": "T1546.002", "name": "SCM", "category": "Registry"},
		{"id": "T1546.003", "name": "WMI事件订阅", "category": "WMI"},
		{"id": "T1546.007", "name": "Netsh Helper DLL", "category": "Registry"},
		{"id": "T1546.008", "name": "LSASS", "category": "Registry"},
		{"id": "T1546.010", "name": "AppInit_DLLs", "category": "Registry"},
		{"id": "T1546.012", "name": "IFEO调试器劫持", "category": "Registry"},
		{"id": "T1546.015", "name": "COM劫持", "category": "COM"},
		{"id": "T1546.016", "name": "启动项", "category": "Startup"},
		{"id": "T1053", "name": "计划任务/作业", "category": "ScheduledTask"},
		{"id": "T1543.003", "name": "Windows服务", "category": "Service"},
		{"id": "T1197", "name": "BITS作业", "category": "BITS"},
		{"id": "T1098", "name": "账户操作/SID History", "category": "Account"},
	}

	c.JSON(http.StatusOK, gin.H{"techniques": techniques})
}

// ListDetectors godoc
// @Summary 列出检测器
// @Description 返回所有持久化检测器的配置状态
// @Tags persistence
// @Produce json
// @Success 200 {object} map[string]interface{} "detectors": []DetectorConfig
// @Router /api/persistence/detectors [get]
func (h *PersistenceHandler) ListDetectors(c *gin.Context) {
	h.detectorMutex.RLock()
	defer h.detectorMutex.RUnlock()

	detectorDescriptions := map[string]struct {
		Description string
		Technique   string
		Category    string
	}{
		"run_key_detector":             {"Run Key Persistence", "T1547.001", "Registry"},
		"user_init_detector":           {"UserInit MPR Logon", "T1546.001", "Registry"},
		"startup_folder_detector":      {"Startup Folder Persistence", "T1547.016", "Registry"},
		"accessibility_detector":       {"Accessibility Features Backdoor", "T1546.001", "Accessibility"},
		"com_hijack_detector":          {"COM Hijacking", "T1546.015", "COM"},
		"ifeo_detector":                {"IFEO Injection", "T1546.012", "Registry"},
		"appinit_detector":             {"AppInit DLLs", "T1546.010", "Registry"},
		"wmi_persistence_detector":     {"WMI Event Subscription", "T1546.003", "WMI"},
		"service_persistence_detector": {"Service Persistence", "T1543.003", "Service"},
		"lsa_persistence_detector":     {"LSA Authentication Package", "T1546.008", "Registry"},
		"winsock_detector":             {"Winsock Helper DLL", "T1546.007", "Registry"},
		"bho_detector":                 {"Browser Helper Object", "T1546.001", "Registry"},
		"print_monitor_detector":       {"Print Monitor", "T1546.001", "Registry"},
		"boot_execute_detector":        {"Boot Execute", "T1053", "ScheduledTask"},
		"etw_persistence_detector":     {"ETW Manipulation", "T1546.006", "Registry"},
		"scheduled_task_detector":      {"Scheduled Task Persistence", "T1053", "ScheduledTask"},
		"appcert_detector":             {"AppCertDlls Persistence", "T1546.001", "Registry"},
	}

	detectors := make([]DetectorConfig, 0, len(h.detectorConfig))
	for name, enabled := range h.detectorConfig {
		desc := detectorDescriptions[name]
		detectors = append(detectors, DetectorConfig{
			Name:        name,
			Enabled:     enabled,
			Description: desc.Description,
			Technique:   desc.Technique,
			Category:    desc.Category,
		})
	}

	c.JSON(http.StatusOK, gin.H{"detectors": detectors})
}

type DetectorConfigUpdate struct {
	Detectors []struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	} `json:"detectors"`
}

// UpdateDetectorConfig godoc
// @Summary 更新检测器配置
// @Description 更新持久化检测器的启用/禁用状态
// @Tags persistence
// @Accept json
// @Produce json
// @Param request body DetectorConfigUpdate true "检测器配置更新请求"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Router /api/persistence/detectors/config [post]
func (h *PersistenceHandler) UpdateDetectorConfig(c *gin.Context) {
	var req DetectorConfigUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.detectorMutex.Lock()
	defer h.detectorMutex.Unlock()

	for _, d := range req.Detectors {
		if _, exists := h.detectorConfig[d.Name]; exists {
			h.detectorConfig[d.Name] = d.Enabled
		}
	}

	h.cacheMutex.Lock()
	h.cache = &DetectionCache{ttl: defaultCacheTTL}
	h.cacheMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Detector configuration updated"})
}

type PersistenceRuleInfo struct {
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	Technique             string   `json:"technique"`
	Category              string   `json:"category"`
	Enabled               bool     `json:"enabled"`
	EventIDs              []int32  `json:"event_ids"`
	Patterns              []string `json:"patterns"`
	Whitelist             []string `json:"whitelist"`
	BuiltinWhitelist      []string `json:"builtin_whitelist,omitempty"`
	BuiltinDllWhitelist   []string `json:"builtin_dll_whitelist,omitempty"`
	BuiltinClsidsWhitelist []string `json:"builtin_clsids_whitelist,omitempty"`
	WhitelistType         string   `json:"whitelist_type,omitempty"`
}

// ListRules godoc
// @Summary 列出持久化规则
// @Description 返回所有持久化检测规则
// @Tags persistence
// @Produce json
// @Success 200 {object} map[string]interface{} "rules": []PersistenceRuleInfo
// @Router /api/persistence/rules [get]
func (h *PersistenceHandler) ListRules(c *gin.Context) {
	h.ruleConfigsMutex.RLock()
	defer h.ruleConfigsMutex.RUnlock()

	rules := make([]PersistenceRuleInfo, 0, len(h.ruleConfigs))
	for _, rule := range h.ruleConfigs {
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// GetRule godoc
// @Summary 获取规则详情
// @Description 返回指定持久化规则的详细信息
// @Tags persistence
// @Produce json
// @Param name path string true "规则名称"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/persistence/rules/{name} [get]
func (h *PersistenceHandler) GetRule(c *gin.Context) {
	ruleName := c.Param("name")
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule name is required"})
		return
	}

	h.ruleConfigsMutex.RLock()
	defer h.ruleConfigsMutex.RUnlock()

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found: " + ruleName})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"detector":              rule,
		"suspicious_indicators": rule.Patterns,
		"whitelist":             rule.Whitelist,
	})
}

type PersistenceRuleUpdate struct {
	Name                 string   `json:"name"`
	Enabled              *bool    `json:"enabled"`
	EventIDs             []int32  `json:"event_ids,omitempty"`
	Patterns             []string `json:"patterns,omitempty"`
	Whitelist            []string `json:"whitelist,omitempty"`
	SuspiciousIndicators []string `json:"suspicious_indicators,omitempty"`
}

// UpdateRule godoc
// @Summary 更新持久化规则
// @Description 更新指定持久化规则的配置
// @Tags persistence
// @Accept json
// @Produce json
// @Param request body PersistenceRuleUpdate true "规则更新请求"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/persistence/rules [put]
func (h *PersistenceHandler) UpdateRule(c *gin.Context) {
	var req PersistenceRuleUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	ruleName := req.Name
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule name is required"})
		return
	}

	h.ruleConfigsMutex.Lock()
	defer h.ruleConfigsMutex.Unlock()

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found: " + ruleName})
		return
	}

	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.EventIDs != nil {
		rule.EventIDs = req.EventIDs
	}
	if req.Patterns != nil {
		rule.Patterns = req.Patterns
	}
	if req.Whitelist != nil {
		rule.Whitelist = req.Whitelist
	}
	if req.SuspiciousIndicators != nil {
		rule.Patterns = req.SuspiciousIndicators
	}

	h.ruleConfigs[ruleName] = rule

	h.engineMutex.RLock()
	engine := h.detectionEngine
	h.engineMutex.RUnlock()

	config := &persistence.DetectorConfig{
		Enabled:   rule.Enabled,
		EventIDs:  rule.EventIDs,
		Patterns:  rule.Patterns,
		Whitelist: rule.Whitelist,
	}

	if err := engine.SetDetectorConfig(ruleName, config); err != nil {
		observability.LogServiceError("persistence_update_rule", fmt.Sprintf("failed to update detector config: %v", err))
	} else {
		observability.LogServiceError("persistence_update_rule", fmt.Sprintf("detector %s config updated", ruleName))
	}

	h.cacheMutex.Lock()
	h.cache = &DetectionCache{ttl: defaultCacheTTL}
	h.cacheMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"detector":              rule,
		"suspicious_indicators": rule.Patterns,
		"whitelist":             rule.Whitelist,
		"message":               "rule updated",
	})
}

type WhitelistUpdate struct {
	Name             string   `json:"name"`
	Whitelist       []string `json:"whitelist"`
	DllWhitelist    []string `json:"dll_whitelist,omitempty"`
	ClsidsWhitelist []string `json:"clsids_whitelist,omitempty"`
}

type WhitelistResponse struct {
	Name                 string   `json:"name"`
	Category             string   `json:"category"`
	UserWhitelist       []string `json:"user_whitelist"`
	BuiltinWhitelist     []string `json:"builtin_whitelist"`
	BuiltinDllWhitelist  []string `json:"builtin_dll_whitelist"`
	BuiltinClsidsWhitelist []string `json:"builtin_clsids_whitelist"`
	WhitelistType        string   `json:"whitelist_type"`
}

func (h *PersistenceHandler) GetWhitelist(c *gin.Context) {
	ruleName := c.Param("name")
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule name is required"})
		return
	}

	h.ruleConfigsMutex.RLock()
	defer h.ruleConfigsMutex.RUnlock()

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found: " + ruleName})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"whitelist": WhitelistResponse{
			Name:                  rule.Name,
			Category:              rule.Category,
			UserWhitelist:        rule.Whitelist,
			BuiltinWhitelist:     rule.BuiltinWhitelist,
			BuiltinDllWhitelist:  rule.BuiltinDllWhitelist,
			BuiltinClsidsWhitelist: rule.BuiltinClsidsWhitelist,
			WhitelistType:        rule.WhitelistType,
		},
	})
}

func (h *PersistenceHandler) UpdateWhitelist(c *gin.Context) {
	var req WhitelistUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	ruleName := req.Name
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule name is required"})
		return
	}

	h.ruleConfigsMutex.Lock()
	defer h.ruleConfigsMutex.Unlock()

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found: " + ruleName})
		return
	}

	if req.Whitelist != nil {
		rule.Whitelist = req.Whitelist
		persistence.GetWhitelistStore().SetUserWhitelist(ruleName, req.Whitelist)
	}
	if req.DllWhitelist != nil {
		rule.BuiltinDllWhitelist = req.DllWhitelist
		persistence.GetWhitelistStore().SetBuiltinDllWhitelist(ruleName, req.DllWhitelist)
	}
	if req.ClsidsWhitelist != nil {
		rule.BuiltinClsidsWhitelist = req.ClsidsWhitelist
		persistence.GetWhitelistStore().SetBuiltinClsidsWhitelist(ruleName, req.ClsidsWhitelist)
	}

	h.ruleConfigs[ruleName] = rule

	h.engineMutex.RLock()
	engine := h.detectionEngine
	h.engineMutex.RUnlock()

	config := &persistence.DetectorConfig{
		Enabled:               rule.Enabled,
		EventIDs:              rule.EventIDs,
		Patterns:              rule.Patterns,
		Whitelist:            rule.Whitelist,
		BuiltinWhitelist:     rule.BuiltinWhitelist,
		BuiltinDllWhitelist:  rule.BuiltinDllWhitelist,
		BuiltinClsidsWhitelist: rule.BuiltinClsidsWhitelist,
	}

	if err := engine.SetDetectorConfig(ruleName, config); err != nil {
		observability.LogServiceError("persistence_update_whitelist", fmt.Sprintf("failed to update whitelist: %v", err))
	}

	h.cacheMutex.Lock()
	h.cache = &DetectionCache{ttl: defaultCacheTTL}
	h.cacheMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"whitelist": WhitelistResponse{
			Name:                  rule.Name,
			Category:              rule.Category,
			UserWhitelist:        rule.Whitelist,
			BuiltinWhitelist:     rule.BuiltinWhitelist,
			BuiltinDllWhitelist:  rule.BuiltinDllWhitelist,
			BuiltinClsidsWhitelist: rule.BuiltinClsidsWhitelist,
			WhitelistType:        rule.WhitelistType,
		},
		"message": "whitelist updated",
	})
}

// SetupPersistenceRoutes godoc
// @Summary 设置持久化检测路由
// @Description 配置持久化检测相关的API路由（不含 /detect/stream，由平台特定文件处理）
// @Tags persistence
// @Router /api/persistence/detect [get]
// @Router /api/persistence/categories [get]
// @Router /api/persistence/techniques [get]
// @Router /api/persistence/detectors [get]
// @Router /api/persistence/detectors/config [post]
// @Router /api/persistence/rules [get]
// @Router /api/persistence/rules/{name} [get]
// @Router /api/persistence/rules [put]
// @Router /api/persistence/whitelist/{name} [get]
// @Router /api/persistence/whitelist [put]
func SetupPersistenceRoutes(r *gin.Engine, persistenceHandler *PersistenceHandler) {
	persistenceGroup := r.Group("/api/persistence")
	{
		persistenceGroup.GET("/detect", persistenceHandler.Detect)
		persistenceGroup.GET("/categories", persistenceHandler.ListCategories)
		persistenceGroup.GET("/techniques", persistenceHandler.ListTechniques)
		persistenceGroup.GET("/detectors", persistenceHandler.ListDetectors)
		persistenceGroup.POST("/detectors/config", persistenceHandler.UpdateDetectorConfig)
		persistenceGroup.GET("/rules", persistenceHandler.ListRules)
		persistenceGroup.GET("/rules/:name", persistenceHandler.GetRule)
		persistenceGroup.PUT("/rules", persistenceHandler.UpdateRule)
		persistenceGroup.GET("/whitelist/:name", persistenceHandler.GetWhitelist)
		persistenceGroup.PUT("/whitelist", persistenceHandler.UpdateWhitelist)
	}
}
