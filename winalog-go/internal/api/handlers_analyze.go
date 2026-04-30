package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/analyzers"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

// AnalyzeHandler handles analysis operations
type AnalyzeHandler struct {
	db          *storage.DB
	manager     *analyzers.AnalyzerManager
	ruleConfigs map[string]AnalyzerRuleInfo
}

// AnalyzeRequest represents request body for analysis
type AnalyzeRequest struct {
	Type      string `json:"type"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Hours     int    `json:"hours"`
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
}

// AnalyzeFinding represents a single finding from analysis
type AnalyzeFinding struct {
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	RuleName    string                 `json:"rule_name,omitempty"`
	MitreAttack []string               `json:"mitre_attack,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Evidence    []EvidenceItem         `json:"evidence,omitempty"`
}

// EvidenceItem represents evidence for a finding
type EvidenceItem struct {
	EventID   int32  `json:"event_id"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Computer  string `json:"computer"`
	Message   string `json:"message"`
}

// Pagination represents pagination information
type Pagination struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

// AnalyzeResult represents the result of an analysis operation
type AnalyzeResult struct {
	Type       string           `json:"type"`
	Severity   string           `json:"severity"`
	Score      float64          `json:"score"`
	Summary    string           `json:"summary"`
	Findings   []AnalyzeFinding `json:"findings"`
	Timestamp  int64            `json:"timestamp"`
	Pagination *Pagination      `json:"pagination,omitempty"`
}

func NewAnalyzeHandler(db *storage.DB, manager *analyzers.AnalyzerManager) *AnalyzeHandler {
	defaultRuleConfigs := map[string]AnalyzerRuleInfo{
		"brute_force":          {Name: "brute_force", Type: "brute_force", Enabled: true, Description: "Brute force login detection", Severity: "high", Score: 80, MitreAttack: []string{"T1110"}, EventIDs: []int32{4625, 4624}, Thresholds: map[string]int{"failed_threshold": 5, "success_threshold": 1}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1110", Category: "authentication"},
		"login":                {Name: "login", Type: "login", Enabled: true, Description: "Login analysis", Severity: "medium", Score: 50, MitreAttack: []string{"T1078"}, EventIDs: []int32{4624, 4625}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1078", Category: "authentication"},
		"kerberos":             {Name: "kerberos", Type: "kerberos", Enabled: true, Description: "Kerberos authentication analysis", Severity: "high", Score: 70, MitreAttack: []string{"T1558"}, EventIDs: []int32{4768, 4769, 4771, 4770}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1558", Category: "authentication"},
		"powershell":           {Name: "powershell", Type: "powershell", Enabled: true, Description: "PowerShell command detection", Severity: "high", Score: 75, MitreAttack: []string{"T1059.001"}, EventIDs: []int32{4103, 4104}, Patterns: []string{"powershell", "Invoke-", "cmd.exe"}, Whitelist: []string{}, Technique: "T1059.001", Category: "execution"},
		"data_exfiltration":    {Name: "data_exfiltration", Type: "data_exfiltration", Enabled: true, Description: "Data exfiltration detection", Severity: "critical", Score: 90, MitreAttack: []string{"T1041"}, EventIDs: []int32{4624, 4688, 4663}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1041", Category: "exfiltration"},
		"lateral_movement":     {Name: "lateral_movement", Type: "lateral_movement", Enabled: true, Description: "Lateral movement detection", Severity: "high", Score: 85, MitreAttack: []string{"T1021"}, EventIDs: []int32{4624, 4688, 4648}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1021", Category: "lateral_movement"},
		"persistence":          {Name: "persistence", Type: "persistence", Enabled: true, Description: "Persistence mechanism detection", Severity: "high", Score: 80, MitreAttack: []string{"T1547"}, EventIDs: []int32{4720, 4697, 7045, 4698, 4728, 4729, 4732, 4733, 4756, 4757}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1547", Category: "persistence"},
		"privilege_escalation": {Name: "privilege_escalation", Type: "privilege_escalation", Enabled: true, Description: "Privilege escalation detection", Severity: "high", Score: 75, MitreAttack: []string{"T1068"}, EventIDs: []int32{4672, 4673, 4674, 4688}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1068", Category: "privilege_escalation"},
		"dc":                   {Name: "dc", Type: "dc", Enabled: true, Description: "Domain controller analysis", Severity: "high", Score: 80, MitreAttack: []string{"T1207"}, EventIDs: []int32{4720, 4726, 4728, 4729, 4732, 4733, 4746, 4747, 4756, 4757, 5136, 4662, 5139, 5140, 4670, 4741}, Patterns: []string{}, Whitelist: []string{}, Technique: "T1207", Category: "defense_evasion"},
	}
	return &AnalyzeHandler{
		db:          db,
		manager:     manager,
		ruleConfigs: defaultRuleConfigs,
	}
}

// RunAnalysis godoc
// @Summary Run analysis
// @Description Run a specific analyzer on stored events
// @Tags analyze
// @Accept json
// @Produce json
// @Param type path string true "Analyzer type (brute-force, login, kerberos, etc.)"
// @Param request body AnalyzeRequest false "Analysis parameters"
// @Success 200 {object} AnalyzeResult
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/analyze/{type} [post]
func (h *AnalyzeHandler) RunAnalysis(c *gin.Context) {
	analyzerType := c.Param("type")
	if analyzerType == "" {
		analyzerType = c.DefaultQuery("type", "brute-force")
	}

	analyzerType = strings.ReplaceAll(analyzerType, "-", "_")

	if h.manager == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error: "analyzer manager not initialized",
			Code:  types.ErrCodeInternalError,
		})
		return
	}

	analyzer, ok := h.manager.Get(analyzerType)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "analyzer not found: " + analyzerType,
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	config := h.manager.GetConfig(analyzerType)
	if configurable, ok := analyzer.(interface {
		SetConfig(*analyzers.AnalyzerConfig)
	}); ok {
		configurable.SetConfig(config)
	}

	var req AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = AnalyzeRequest{Type: analyzerType}
	}

	hours := req.Hours
	if hours <= 0 {
		hours = 24
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 10000
	}
	if limit > 100000 {
		limit = 100000
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	filter := &storage.EventFilter{
		Limit:  limit,
		Offset: offset,
	}

	if req.StartTime != "" || req.EndTime != "" {
		timeInput := req.StartTime
		if req.EndTime != "" {
			timeInput = req.StartTime + "," + req.EndTime
		}
		if tf, err := types.ParseTimeFilter(timeInput); err == nil && tf != nil {
			filter.StartTime = &tf.Start
			filter.EndTime = &tf.End
		}
	} else if hours > 0 {
		startTime := time.Now().Add(-time.Duration(hours) * time.Hour)
		filter.StartTime = &startTime
		endTime := time.Now()
		filter.EndTime = &endTime
	}

	events, total, err := h.db.ListEvents(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "failed to fetch events: " + err.Error(),
		})
		return
	}

	result, err := analyzer.Analyze(events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "analysis failed: " + err.Error(),
		})
		return
	}

	response := AnalyzeResult{
		Type:      result.Type,
		Severity:  result.Severity,
		Score:     result.Score,
		Summary:   result.Summary,
		Findings:  make([]AnalyzeFinding, len(result.Findings)),
		Timestamp: result.Timestamp,
		Pagination: &Pagination{
			Limit:  limit,
			Offset: offset,
			Total:  total,
		},
	}

	if total > int64(limit) {
		response.Summary = fmt.Sprintf("%s (注意：共 %d 条事件，仅分析了前 %d 条，可通过 offset 参数翻页)", result.Summary, total, limit)
	}

	for i, f := range result.Findings {
		var mitre []string
		if f.MitreAttack != "" {
			mitre = []string{f.MitreAttack}
		}
		evidence := make([]EvidenceItem, 0)
		for _, e := range f.Evidence {
			evidence = append(evidence, EvidenceItem{
				EventID:   e.EventID,
				Timestamp: e.Timestamp,
				User:      e.User,
				Computer:  e.Computer,
				Message:   e.Message,
			})
		}
		response.Findings[i] = AnalyzeFinding{
			Description: f.Description,
			Severity:    f.Severity,
			Score:       f.Score,
			RuleName:    f.RuleName,
			MitreAttack: mitre,
			Metadata:    f.Metadata,
			Evidence:    evidence,
		}
	}

	c.JSON(http.StatusOK, response)
}

// ListAnalyzers godoc
// @Summary List available analyzers
// @Description Get a list of all available analyzer types
// @Tags analyze
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Router /api/analyzers [get]
func (h *AnalyzeHandler) ListAnalyzers(c *gin.Context) {
	if h.manager == nil {
		c.JSON(http.StatusOK, gin.H{
			"analyzers": []string{},
		})
		return
	}
	analyzerList := h.manager.List()
	c.JSON(http.StatusOK, gin.H{
		"analyzers": analyzerList,
	})
}

// GetAnalyzerInfo godoc
// @Summary Get analyzer info
// @Description Get information about a specific analyzer
// @Tags analyze
// @Accept json
// @Produce json
// @Param type path string true "Analyzer type"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/analyzers/{type} [get]
func (h *AnalyzeHandler) GetAnalyzerInfo(c *gin.Context) {
	analyzerType := c.Param("type")

	if h.manager == nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "analyzer not found: " + analyzerType,
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	analyzer, ok := h.manager.Get(analyzerType)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "analyzer not found: " + analyzerType,
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"type":      analyzer.Name(),
		"available": true,
	})
}

// AnalyzerRuleInfo represents configuration for an analyzer rule
type AnalyzerRuleInfo struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Score       float64        `json:"score"`
	MitreAttack []string       `json:"mitre_attack"`
	EventIDs    []int32        `json:"event_ids"`
	Thresholds  map[string]int `json:"thresholds"`
	Patterns    []string       `json:"patterns"`
	Whitelist   []string       `json:"whitelist"`
	Technique   string         `json:"technique"`
	Category    string         `json:"category"`
}

// ListRules godoc
// @Summary List analyzer rules
// @Description Get a list of all analyzer rule configurations
// @Tags analyze
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Router /api/analyzer-rules [get]
func (h *AnalyzeHandler) ListRules(c *gin.Context) {
	rules := make([]AnalyzerRuleInfo, 0, len(h.ruleConfigs))
	for _, rule := range h.ruleConfigs {
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// GetRule godoc
// @Summary Get analyzer rule
// @Description Get configuration for a specific analyzer rule
// @Tags analyze
// @Accept json
// @Produce json
// @Param type path string true "Rule type"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/analyzer-rules/{type} [get]
func (h *AnalyzeHandler) GetRule(c *gin.Context) {
	ruleName := c.Param("type")
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "rule type is required"})
		return
	}

	ruleName = strings.ReplaceAll(ruleName, "-", "_")

	// Handle aliases
	aliasMap := map[string]string{
		"domain_controller": "dc",
	}
	if actualName, ok := aliasMap[ruleName]; ok {
		ruleName = actualName
	}

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "rule not found: " + ruleName})
		return
	}

	c.JSON(http.StatusOK, gin.H{"rule": rule})
}

// AnalyzerRuleUpdate represents request body for updating an analyzer rule
type AnalyzerRuleUpdate struct {
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	EventIDs   []int32        `json:"event_ids,omitempty"`
	Thresholds map[string]int `json:"thresholds,omitempty"`
	Patterns   []string       `json:"patterns,omitempty"`
	Whitelist  []string       `json:"whitelist,omitempty"`
}

// UpdateRule godoc
// @Summary Update analyzer rule
// @Description Update configuration for a specific analyzer rule
// @Tags analyze
// @Accept json
// @Produce json
// @Param type path string true "Rule type"
// @Param request body AnalyzerRuleUpdate true "Rule configuration"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/analyzer-rules/{type} [put]
func (h *AnalyzeHandler) UpdateRule(c *gin.Context) {
	ruleName := c.Param("type")
	if ruleName == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "rule type is required"})
		return
	}

	ruleName = strings.ReplaceAll(ruleName, "-", "_")

	// Handle aliases
	aliasMap := map[string]string{
		"domain_controller": "dc",
	}
	if actualName, ok := aliasMap[ruleName]; ok {
		ruleName = actualName
	}

	var req AnalyzerRuleUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request: " + err.Error()})
		return
	}

	rule, exists := h.ruleConfigs[ruleName]
	if !exists {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "rule not found: " + ruleName})
		return
	}

	rule.Enabled = req.Enabled
	if req.EventIDs != nil {
		rule.EventIDs = req.EventIDs
	}
	if req.Thresholds != nil {
		rule.Thresholds = req.Thresholds
	}
	if req.Patterns != nil {
		rule.Patterns = req.Patterns
	}
	if req.Whitelist != nil {
		rule.Whitelist = req.Whitelist
	}

	h.ruleConfigs[ruleName] = rule

	config := &analyzers.AnalyzerConfig{
		EventIDs:   rule.EventIDs,
		Patterns:   rule.Patterns,
		Whitelist:  rule.Whitelist,
		Thresholds: rule.Thresholds,
	}
	h.manager.SetConfig(ruleName, config)

	if analyzer, ok := h.manager.Get(ruleName); ok {
		if configurable, ok := analyzer.(interface {
			SetConfig(*analyzers.AnalyzerConfig)
		}); ok {
			configurable.SetConfig(config)
		}
	}

	c.JSON(http.StatusOK, gin.H{"rule": rule, "message": "rule updated"})
}

func SetupAnalyzeRoutes(r *gin.Engine, analyzeHandler *AnalyzeHandler) {
	analyze := r.Group("/api/analyze")
	{
		analyze.POST("/:type", analyzeHandler.RunAnalysis)
	}

	analyzers := r.Group("/api/analyzers")
	{
		analyzers.GET("", analyzeHandler.ListAnalyzers)
		analyzers.GET("/:type", analyzeHandler.GetAnalyzerInfo)
	}

	analyzerRules := r.Group("/api/analyzer-rules")
	{
		analyzerRules.GET("", analyzeHandler.ListRules)
		analyzerRules.GET("/:type", analyzeHandler.GetRule)
		analyzerRules.PUT("/:type", analyzeHandler.UpdateRule)
	}
}
