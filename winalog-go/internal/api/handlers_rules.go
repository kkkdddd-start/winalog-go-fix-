package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type RulesHandler struct {
	customManager *rules.CustomRuleManager
	db            *storage.DB
}

type RuleInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Severity    string      `json:"severity"`
	Score       float64     `json:"score"`
	MitreAttack []string    `json:"mitre_attack"`
	Tags        []string    `json:"tags"`
	IsCustom    bool        `json:"is_custom"`
	EventIDs    []int32     `json:"event_ids,omitempty"`
	Levels      []string    `json:"levels,omitempty"`
	Filter      *FilterInfo `json:"filter,omitempty"`
	Message     string      `json:"message,omitempty"`
}

type FilterInfo struct {
	EventIDs         []int32  `json:"event_ids,omitempty"`
	Levels           []string `json:"levels,omitempty"`
	LogNames         []string `json:"log_names,omitempty"`
	Sources          []string `json:"sources,omitempty"`
	Computers        []string `json:"computers,omitempty"`
	Users            []string `json:"users,omitempty"`
	Keywords         []string `json:"keywords,omitempty"`
	ExcludeUsers     []string `json:"exclude_users,omitempty"`
	ExcludeComputers []string `json:"exclude_computers,omitempty"`
	IpAddress        string   `json:"ip_address,omitempty"`
}

type RulesListResponse struct {
	Rules        []RuleInfo `json:"rules"`
	TotalCount   int        `json:"total_count"`
	EnabledCount int        `json:"enabled_count"`
	Page         int        `json:"page,omitempty"`
	PageSize     int        `json:"page_size,omitempty"`
	TotalPages   int        `json:"total_pages,omitempty"`
}

type ListRulesRequest struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Severity string `form:"severity"`
	Enabled  *bool  `form:"enabled"`
	Keyword  string `form:"keyword"`
}

// NewRulesHandler godoc
// @Summary 创建规则处理器
// @Description 初始化RulesHandler
// @Tags rules
// @Param db query string true "数据库实例"
// @Router /api/rules [get]
func NewRulesHandler(db *storage.DB) *RulesHandler {
	return &RulesHandler{
		customManager: rules.NewCustomRuleManager("./data/rules"),
		db:            db,
	}
}

// ListRules godoc
// @Summary 列出规则
// @Description 返回所有告警规则，包括内置规则和自定义规则
// @Tags rules
// @Produce json
// @Param page query int false "页码" default(1)
// @Param page_size query int false "每页数量" default(20)
// @Param severity query string false "严重级别过滤"
// @Param enabled query bool false "启用状态过滤"
// @Param keyword query string false "关键词搜索"
// @Success 200 {object} RulesListResponse
// @Router /api/rules [get]
func (h *RulesHandler) ListRules(c *gin.Context) {
	var req ListRulesRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		req.Page = 1
		req.PageSize = 20
	}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 {
		req.PageSize = 20
	}
	if req.PageSize > 100 {
		req.PageSize = 100
	}

	alertRules := builtin.GetAlertRules()
	customRules := h.customManager.List()

	allRules := make([]RuleInfo, 0, len(alertRules)+len(customRules))
	enabledCount := 0

	for _, rule := range alertRules {
		ruleInfo := convertToRuleInfo(rule, false)
		if !applyRuleFilter(ruleInfo, &req) {
			continue
		}
		allRules = append(allRules, ruleInfo)
		if rule.Enabled {
			enabledCount++
		}
	}

	for _, rule := range customRules {
		ruleInfo := convertToRuleInfoFromCustom(rule)
		if !applyRuleFilter(ruleInfo, &req) {
			continue
		}
		allRules = append(allRules, ruleInfo)
		if rule.Enabled {
			enabledCount++
		}
	}

	rules.SortRules(alertRules)

	totalCount := len(allRules)
	totalPages := (totalCount + req.PageSize - 1) / req.PageSize

	start := (req.Page - 1) * req.PageSize
	end := start + req.PageSize
	if start > totalCount {
		start = totalCount
	}
	if end > totalCount {
		end = totalCount
	}

	pagedRules := allRules
	if start < end {
		pagedRules = allRules[start:end]
	}

	c.JSON(http.StatusOK, RulesListResponse{
		Rules:        pagedRules,
		TotalCount:   totalCount,
		EnabledCount: enabledCount,
		Page:         req.Page,
		PageSize:     req.PageSize,
		TotalPages:   totalPages,
	})
}

func convertToRuleInfo(rule *rules.AlertRule, isCustom bool) RuleInfo {
	ruleInfo := RuleInfo{
		ID:          rule.Name,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     rule.Enabled,
		Severity:    string(rule.Severity),
		Score:       rule.Score,
		MitreAttack: []string{},
		Tags:        rule.Tags,
		IsCustom:    isCustom,
	}
	if rule.Filter != nil {
		ruleInfo.EventIDs = rule.Filter.EventIDs
		ruleInfo.Levels = rule.Filter.Levels
	}
	ruleInfo.Message = rule.Message
	if rule.MitreAttack != "" {
		ruleInfo.MitreAttack = []string{rule.MitreAttack}
	}
	if rule.Filter != nil {
		keywords := []string{}
		if rule.Filter.Keywords != "" {
			keywords = strings.Fields(rule.Filter.Keywords)
		}
		ipAddr := ""
		if len(rule.Filter.IpAddress) > 0 {
			ipAddr = rule.Filter.IpAddress[0]
		}
		ruleInfo.Filter = &FilterInfo{
			EventIDs:         rule.Filter.EventIDs,
			Levels:           rule.Filter.Levels,
			LogNames:         rule.Filter.LogNames,
			Sources:          rule.Filter.Sources,
			Computers:        rule.Filter.Computers,
			Keywords:         keywords,
			ExcludeUsers:     rule.Filter.ExcludeUsers,
			ExcludeComputers: rule.Filter.ExcludeComputers,
			IpAddress:        ipAddr,
		}
	}
	return ruleInfo
}

func convertToRuleInfoFromCustom(rule *rules.CustomRule) RuleInfo {
	ruleInfo := RuleInfo{
		ID:          rule.Name,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     rule.Enabled,
		Severity:    rule.Severity,
		Score:       rule.Score,
		MitreAttack: []string{},
		Tags:        rule.Tags,
		IsCustom:    true,
		EventIDs:    rule.EventIDs,
		Levels:      rule.Levels,
		Message:     rule.Message,
	}
	if rule.MitreAttack != "" {
		ruleInfo.MitreAttack = []string{rule.MitreAttack}
	}
	if rule.Filter != nil {
		ruleInfo.Filter = &FilterInfo{
			EventIDs:         rule.Filter.EventIDs,
			Levels:           rule.Filter.Levels,
			LogNames:         rule.Filter.LogNames,
			Sources:          rule.Filter.Sources,
			Computers:        rule.Filter.Computers,
			Users:            rule.Filter.Users,
			Keywords:         rule.Filter.Keywords,
			ExcludeUsers:     rule.Filter.ExcludeUsers,
			ExcludeComputers: rule.Filter.ExcludeComputers,
			IpAddress:        rule.Filter.IpAddress,
		}
	}
	return ruleInfo
}

func applyRuleFilter(rule RuleInfo, req *ListRulesRequest) bool {
	if req.Severity != "" && rule.Severity != req.Severity {
		return false
	}

	if req.Enabled != nil && rule.Enabled != *req.Enabled {
		return false
	}

	if req.Keyword != "" {
		keyword := strings.ToLower(req.Keyword)
		name := strings.ToLower(rule.Name)
		desc := strings.ToLower(rule.Description)
		if !strings.Contains(name, keyword) && !strings.Contains(desc, keyword) {
			return false
		}
	}

	return true
}

// GetRule godoc
// @Summary 获取规则详情
// @Description 返回指定规则的详细信息
// @Tags rules
// @Produce json
// @Param name path string true "规则名称"
// @Success 200 {object} RuleInfo
// @Failure 404 {object} ErrorResponse
// @Router /api/rules/{name} [get]
func (h *RulesHandler) GetRule(c *gin.Context) {
	name := c.Param("name")

	alertRules := builtin.GetAlertRules()
	for _, rule := range alertRules {
		if rule.Name == name {
			ruleInfo := RuleInfo{
				ID:          rule.Name,
				Name:        rule.Name,
				Description: rule.Description,
				Enabled:     rule.Enabled,
				Severity:    string(rule.Severity),
				Score:       rule.Score,
				MitreAttack: []string{},
				Tags:        rule.Tags,
				IsCustom:    false,
			}
			if rule.MitreAttack != "" {
				ruleInfo.MitreAttack = []string{rule.MitreAttack}
			}
			if rule.Filter != nil {
				keywords := []string{}
				if rule.Filter.Keywords != "" {
					keywords = strings.Fields(rule.Filter.Keywords)
				}
				ipAddr := ""
				if len(rule.Filter.IpAddress) > 0 {
					ipAddr = rule.Filter.IpAddress[0]
				}
				ruleInfo.Filter = &FilterInfo{
					EventIDs:         rule.Filter.EventIDs,
					Levels:           rule.Filter.Levels,
					LogNames:         rule.Filter.LogNames,
					Sources:          rule.Filter.Sources,
					Computers:        rule.Filter.Computers,
					Keywords:         keywords,
					ExcludeUsers:     rule.Filter.ExcludeUsers,
					ExcludeComputers: rule.Filter.ExcludeComputers,
					IpAddress:        ipAddr,
				}
			}
			c.JSON(http.StatusOK, ruleInfo)
			return
		}
	}

	if rule, ok := h.customManager.Get(name); ok {
		ruleInfo := RuleInfo{
			ID:          rule.Name,
			Name:        rule.Name,
			Description: rule.Description,
			Enabled:     rule.Enabled,
			Severity:    rule.Severity,
			Score:       rule.Score,
			MitreAttack: []string{},
			Tags:        rule.Tags,
			IsCustom:    true,
			EventIDs:    rule.EventIDs,
			Levels:      rule.Levels,
			Message:     rule.Message,
		}
		if rule.MitreAttack != "" {
			ruleInfo.MitreAttack = []string{rule.MitreAttack}
		}
		if rule.Filter != nil {
			ruleInfo.Filter = &FilterInfo{
				EventIDs:         rule.Filter.EventIDs,
				Levels:           rule.Filter.Levels,
				LogNames:         rule.Filter.LogNames,
				Sources:          rule.Filter.Sources,
				Computers:        rule.Filter.Computers,
				Users:            rule.Filter.Users,
				Keywords:         rule.Filter.Keywords,
				ExcludeUsers:     rule.Filter.ExcludeUsers,
				ExcludeComputers: rule.Filter.ExcludeComputers,
				IpAddress:        rule.Filter.IpAddress,
			}
		}
		c.JSON(http.StatusOK, ruleInfo)
		return
	}

	c.JSON(http.StatusNotFound, ErrorResponse{
		Error: "Rule not found",
		Code:  "RULE_NOT_FOUND",
	})
}

// ToggleRule godoc
// @Summary 切换规则状态
// @Description 启用或禁用指定规则
// @Tags rules
// @Produce json
// @Param name path string true "规则名称"
// @Param enabled query bool true "目标状态"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/rules/{name}/toggle [post]
func (h *RulesHandler) ToggleRule(c *gin.Context) {
	name := c.Param("name")
	enabled := c.Query("enabled") == "true"

	alertRules := builtin.GetAlertRules()
	for _, rule := range alertRules {
		if rule.Name == name {
			rule.Enabled = enabled
			if h.db != nil {
				_ = h.db.SetRuleEnabled(name, "alert", enabled)
			}
			c.JSON(http.StatusOK, SuccessResponse{
				Message: "Rule " + name + " " + map[bool]string{true: "enabled", false: "disabled"}[enabled],
			})
			return
		}
	}

	if rule, ok := h.customManager.Get(name); ok {
		rule.Enabled = enabled
		_ = h.customManager.Update(rule)
		if h.db != nil {
			_ = h.db.SetRuleEnabled(name, "custom", enabled)
		}
		c.JSON(http.StatusOK, SuccessResponse{
			Message: "Rule " + name + " " + map[bool]string{true: "enabled", false: "disabled"}[enabled],
		})
		return
	}

	c.JSON(http.StatusNotFound, ErrorResponse{
		Error: "Rule not found",
		Code:  "RULE_NOT_FOUND",
	})
}

type CreateRuleRequest struct {
	Name        string      `json:"name" binding:"required"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Severity    string      `json:"severity" binding:"required"`
	Score       float64     `json:"score"`
	MitreAttack []string    `json:"mitre_attack"`
	Tags        []string    `json:"tags"`
	EventIDs    []int32     `json:"event_ids"`
	Levels      []string    `json:"levels"`
	Filter      *FilterInfo `json:"filter"`
	Message     string      `json:"message"`
}

type UpdateRuleRequest struct {
	Description string      `json:"description"`
	Enabled     *bool       `json:"enabled"`
	Severity    string      `json:"severity"`
	Score       *float64    `json:"score"`
	MitreAttack []string    `json:"mitre_attack"`
	Tags        []string    `json:"tags"`
	EventIDs    []int32     `json:"event_ids"`
	Levels      []string    `json:"levels"`
	Filter      *FilterInfo `json:"filter"`
	Message     string      `json:"message"`
}

// CreateRule godoc
// @Summary 创建规则
// @Description 创建新的自定义告警规则
// @Tags rules
// @Accept json
// @Produce json
// @Param request body CreateRuleRequest true "规则创建请求"
// @Success 201 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/rules [post]
func (h *RulesHandler) CreateRule(c *gin.Context) {
	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	if _, ok := h.customManager.Get(req.Name); ok {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error: "Rule with this name already exists",
			Code:  "RULE_EXISTS",
		})
		return
	}

	alertRules := builtin.GetAlertRules()
	for _, rule := range alertRules {
		if rule.Name == req.Name {
			c.JSON(http.StatusConflict, ErrorResponse{
				Error: "A built-in rule with this name already exists",
				Code:  "RULE_EXISTS",
			})
			return
		}
	}

	severity := req.Severity
	if severity == "" {
		severity = "medium"
	}

	score := req.Score
	if score == 0 {
		score = 50.0
	}

	mitreAttack := ""
	if len(req.MitreAttack) > 0 {
		mitreAttack = req.MitreAttack[0]
	}

	filter := &rules.CustomRuleFilter{}
	if req.Filter != nil {
		filter = &rules.CustomRuleFilter{
			EventIDs:         req.Filter.EventIDs,
			Levels:           req.Filter.Levels,
			LogNames:         req.Filter.LogNames,
			Sources:          req.Filter.Sources,
			Computers:        req.Filter.Computers,
			Users:            req.Filter.Users,
			Keywords:         req.Filter.Keywords,
			ExcludeUsers:     req.Filter.ExcludeUsers,
			ExcludeComputers: req.Filter.ExcludeComputers,
			IpAddress:        req.Filter.IpAddress,
		}
	}

	customRule := &rules.CustomRule{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     req.Enabled,
		Severity:    severity,
		Score:       score,
		MitreAttack: mitreAttack,
		EventIDs:    req.EventIDs,
		Levels:      req.Levels,
		Filter:      filter,
		Message:     req.Message,
		Tags:        req.Tags,
		CreatedAt:   time.Now().Format(time.RFC3339),
		UpdatedAt:   time.Now().Format(time.RFC3339),
	}

	if err := h.customManager.Add(customRule); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to save rule: " + err.Error(),
			Code:  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusCreated, SuccessResponse{
		Message: "Rule created successfully",
	})
}

// UpdateRule godoc
// @Summary 更新规则
// @Description 更新指定告警规则的配置
// @Tags rules
// @Accept json
// @Produce json
// @Param name path string true "规则名称"
// @Param request body UpdateRuleRequest true "规则更新请求"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/rules/{name} [put]
func (h *RulesHandler) UpdateRule(c *gin.Context) {
	name := c.Param("name")

	var req UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	alertRules := builtin.GetAlertRules()
	for _, rule := range alertRules {
		if rule.Name == name {
			if req.Description != "" {
				rule.Description = req.Description
			}
			if req.Enabled != nil {
				rule.Enabled = *req.Enabled
			}
			if req.Severity != "" {
				rule.Severity = types.Severity(req.Severity)
			}
			if req.Score != nil {
				rule.Score = *req.Score
			}
			if len(req.MitreAttack) > 0 {
				rule.MitreAttack = req.MitreAttack[0]
			}
			if req.Filter != nil {
				rule.Filter = &rules.Filter{
					EventIDs:         req.Filter.EventIDs,
					Levels:           req.Filter.Levels,
					LogNames:         req.Filter.LogNames,
					Sources:          req.Filter.Sources,
					Computers:        req.Filter.Computers,
					Keywords:         strings.Join(req.Filter.Keywords, " "),
					ExcludeUsers:     req.Filter.ExcludeUsers,
					ExcludeComputers: req.Filter.ExcludeComputers,
				}
			}
			c.JSON(http.StatusOK, SuccessResponse{
				Message: "Rule updated successfully",
			})
			return
		}
	}

	rule, ok := h.customManager.Get(name)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Rule not found",
			Code:  "RULE_NOT_FOUND",
		})
		return
	}

	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Severity != "" {
		rule.Severity = req.Severity
	}
	if req.Score != nil {
		rule.Score = *req.Score
	}
	if len(req.MitreAttack) > 0 {
		rule.MitreAttack = req.MitreAttack[0]
	}
	if req.EventIDs != nil {
		rule.EventIDs = req.EventIDs
	}
	if req.Levels != nil {
		rule.Levels = req.Levels
	}
	if req.Filter != nil {
		rule.Filter = &rules.CustomRuleFilter{
			EventIDs:         req.Filter.EventIDs,
			Levels:           req.Filter.Levels,
			LogNames:         req.Filter.LogNames,
			Sources:          req.Filter.Sources,
			Computers:        req.Filter.Computers,
			Users:            req.Filter.Users,
			Keywords:         req.Filter.Keywords,
			ExcludeUsers:     req.Filter.ExcludeUsers,
			ExcludeComputers: req.Filter.ExcludeComputers,
			IpAddress:        req.Filter.IpAddress,
		}
	}
	if req.Message != "" {
		rule.Message = req.Message
	}
	if req.Tags != nil {
		rule.Tags = req.Tags
	}

	if err := h.customManager.Update(rule); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to update rule: " + err.Error(),
			Code:  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Rule updated successfully",
	})
}

// DeleteRule godoc
// @Summary 删除规则
// @Description 删除指定的自定义告警规则
// @Tags rules
// @Produce json
// @Param name path string true "规则名称"
// @Success 200 {object} SuccessResponse
// @Failure 403 {object} ErrorResponse "无法删除内置规则"
// @Failure 404 {object} ErrorResponse
// @Router /api/rules/{name} [delete]
func (h *RulesHandler) DeleteRule(c *gin.Context) {
	name := c.Param("name")

	alertRules := builtin.GetAlertRules()
	for _, rule := range alertRules {
		if rule.Name == name {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error: "Cannot delete built-in rules",
				Code:  "RULE_BUILTIN",
			})
			return
		}
	}

	if _, ok := h.customManager.Get(name); !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Rule not found",
			Code:  "RULE_NOT_FOUND",
		})
		return
	}

	if err := h.customManager.Delete(name); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to delete rule: " + err.Error(),
			Code:  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Rule deleted successfully",
	})
}

type ValidateRuleRequest struct {
	Rule    RuleInfo `json:"rule"`
	Content string   `json:"content"`
}

type ValidateRuleResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ValidateRule godoc
// @Summary 验证规则
// @Description 验证规则配置的有效性
// @Tags rules
// @Accept json
// @Produce json
// @Param request body ValidateRuleRequest true "规则验证请求"
// @Success 200 {object} ValidateRuleResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/rules/validate [post]
func (h *RulesHandler) ValidateRule(c *gin.Context) {
	var req ValidateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	errors := []string{}
	warnings := []string{}

	if req.Content != "" {
		req.Rule.Description = req.Content
	}

	if req.Rule.Name == "" {
		errors = append(errors, "Rule name is required")
	}

	if req.Rule.Severity == "" {
		warnings = append(warnings, "Severity not specified, defaulting to 'medium'")
	} else if !isValidSeverity(req.Rule.Severity) {
		errors = append(errors, "Invalid severity: "+req.Rule.Severity+". Must be one of: critical, high, medium, low, info")
	}

	if req.Rule.Score < 0 || req.Rule.Score > 100 {
		errors = append(errors, "Score must be between 0 and 100")
	}

	for _, mitre := range req.Rule.MitreAttack {
		if !isValidMITRE(mitre) {
			warnings = append(warnings, "Unknown MITRE ATT&CK ID: "+mitre)
		}
	}

	c.JSON(http.StatusOK, ValidateRuleResponse{
		Valid:    len(errors) == 0,
		Errors:   errors,
		Warnings: warnings,
	})
}

func isValidSeverity(s string) bool {
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	for _, v := range validSeverities {
		if s == v {
			return true
		}
	}
	return false
}

func isValidMITRE(m string) bool {
	if len(m) < 5 {
		return false
	}
	if m[:4] != "T" {
		return false
	}
	return true
}

type ImportRulesRequest struct {
	Rules []RuleInfo `json:"rules"`
}

type ImportRulesResponse struct {
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// ImportRules godoc
// @Summary 导入规则
// @Description 从请求体导入规则配置
// @Tags rules
// @Accept json
// @Produce json
// @Param request body ImportRulesRequest true "规则导入请求"
// @Success 200 {object} ImportRulesResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/rules/import [post]
func (h *RulesHandler) ImportRules(c *gin.Context) {
	var req ImportRulesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	imported := 0
	failed := 0
	errors := []string{}

	for _, rule := range req.Rules {
		if rule.Name == "" {
			errors = append(errors, "Rule without name skipped")
			failed++
			continue
		}

		alertRules := builtin.GetAlertRules()
		found := false
		for _, existing := range alertRules {
			if existing.Name == rule.Name {
				existing.Description = rule.Description
				existing.Severity = types.Severity(rule.Severity)
				existing.Score = rule.Score
				existing.Enabled = rule.Enabled
				if len(rule.MitreAttack) > 0 {
					existing.MitreAttack = rule.MitreAttack[0]
				}
				found = true
				break
			}
		}

		if found {
			imported++
		} else {
			newRule := &rules.CustomRule{
				Name:        rule.Name,
				Description: rule.Description,
				Enabled:     rule.Enabled,
				Severity:    string(types.Severity(rule.Severity)),
				Score:       rule.Score,
			}
			if len(rule.MitreAttack) > 0 {
				newRule.MitreAttack = rule.MitreAttack[0]
			}
			if err := h.customManager.Add(newRule); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to create rule %s: %v", rule.Name, err))
				failed++
			} else {
				imported++
			}
		}
	}

	c.JSON(http.StatusOK, ImportRulesResponse{
		Imported: imported,
		Failed:   failed,
		Errors:   errors,
	})
}

// ExportRules godoc
// @Summary 导出规则
// @Description 导出所有规则为JSON或YAML格式
// @Tags rules
// @Produce json
// @Param format query string false "导出格式" default(json)
// @Success 200 {object} map[string]interface{}
// @Router /api/rules/export [get]
func (h *RulesHandler) ExportRules(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	alertRules := builtin.GetAlertRules()
	rulesList := make([]RuleInfo, 0, len(alertRules))

	for _, rule := range alertRules {
		ruleInfo := RuleInfo{
			ID:          rule.Name,
			Name:        rule.Name,
			Description: rule.Description,
			Enabled:     rule.Enabled,
			Severity:    string(rule.Severity),
			Score:       rule.Score,
			MitreAttack: []string{},
			Tags:        rule.Tags,
		}
		if rule.MitreAttack != "" {
			ruleInfo.MitreAttack = []string{rule.MitreAttack}
		}
		rulesList = append(rulesList, ruleInfo)
	}

	if format == "yaml" || format == "yml" {
		c.Header("Content-Disposition", "attachment; filename=rules_export.yaml")
		c.Header("Content-Type", "text/yaml")
		yamlContent := "# WinLogAnalyzer Rules Export\n# Generated: " + time.Now().Format(time.RFC3339) + "\n\n"
		for _, rule := range rulesList {
			yamlContent += fmt.Sprintf("- name: %q\n  description: %q\n  severity: %s\n  enabled: %v\n  score: %.1f\n",
				rule.Name, rule.Description, rule.Severity, rule.Enabled, rule.Score)
			if len(rule.MitreAttack) > 0 {
				yamlContent += "  mitre_attack:\n"
				for _, m := range rule.MitreAttack {
					yamlContent += fmt.Sprintf("    - %q\n", m)
				}
			}
			yamlContent += "\n"
		}
		c.String(http.StatusOK, yamlContent)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":       rulesList,
		"total":       len(rulesList),
		"exported_at": time.Now().Format(time.RFC3339),
	})
}

// SetupRulesRoutes godoc
// @Summary 设置规则路由
// @Description 配置规则管理相关的API路由
// @Tags rules
// @Router /api/rules [get]
// @Router /api/rules [post]
// @Router /api/rules/{name} [get]
// @Router /api/rules/{name} [put]
// @Router /api/rules/{name} [delete]
// @Router /api/rules/{name}/toggle [post]
// @Router /api/rules/validate [post]
// @Router /api/rules/import [post]
// @Router /api/rules/export [get]
// @Router /api/rules/templates [get]
// @Router /api/rules/templates/{name} [get]
// @Router /api/rules/templates/{name}/instantiate [post]
func SetupRulesRoutes(r *gin.Engine, rulesHandler *RulesHandler) {
	rulesGroup := r.Group("/api/rules")
	{
		rulesGroup.GET("", rulesHandler.ListRules)
		rulesGroup.GET("/:name", rulesHandler.GetRule)
		rulesGroup.POST("", rulesHandler.CreateRule)
		rulesGroup.PUT("/:name", rulesHandler.UpdateRule)
		rulesGroup.DELETE("/:name", rulesHandler.DeleteRule)
		rulesGroup.POST("/:name/toggle", rulesHandler.ToggleRule)
		rulesGroup.POST("/validate", rulesHandler.ValidateRule)
		rulesGroup.POST("/import", rulesHandler.ImportRules)
		rulesGroup.GET("/export", rulesHandler.ExportRules)
		rulesGroup.GET("/templates", rulesHandler.ListTemplates)
		rulesGroup.GET("/templates/:name", rulesHandler.GetTemplate)
		rulesGroup.POST("/templates/:name/instantiate", rulesHandler.InstantiateTemplate)
	}
}

type TemplateInfo struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Parameters  []TemplateParamInfo `json:"parameters"`
	IsTemplate  bool                `json:"is_template"`
}

type TemplateParamInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default,omitempty"`
	Required    bool     `json:"required"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
}

type InstantiateTemplateRequest struct {
	Name   string            `json:"name" binding:"required"`
	Params map[string]string `json:"params"`
}

// ListTemplates godoc
// @Summary 列出规则模板
// @Description 返回所有可用的规则模板
// @Tags rules
// @Produce json
// @Success 200 {object} map[string]interface{} "templates": []TemplateInfo, "total": int
// @Router /api/rules/templates [get]
func (h *RulesHandler) ListTemplates(c *gin.Context) {
	templates := h.customManager.ListTemplates()
	response := make([]TemplateInfo, 0, len(templates))
	for _, t := range templates {
		params := make([]TemplateParamInfo, 0, len(t.Parameters))
		for _, p := range t.Parameters {
			params = append(params, TemplateParamInfo{
				Name:        p.Name,
				Description: p.Description,
				Default:     p.Default,
				Required:    p.Required,
				Type:        p.Type,
				Options:     p.Options,
			})
		}
		response = append(response, TemplateInfo{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  params,
			IsTemplate:  t.IsTemplate,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"templates": response,
		"total":     len(response),
	})
}

// GetTemplate godoc
// @Summary 获取规则模板详情
// @Description 返回指定规则模板的详细信息
// @Tags rules
// @Produce json
// @Param name path string true "模板名称"
// @Success 200 {object} TemplateInfo
// @Failure 404 {object} ErrorResponse
// @Router /api/rules/templates/{name} [get]
func (h *RulesHandler) GetTemplate(c *gin.Context) {
	name := c.Param("name")
	template, ok := h.customManager.GetTemplate(name)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Template not found",
			Code:  "TEMPLATE_NOT_FOUND",
		})
		return
	}

	params := make([]TemplateParamInfo, 0, len(template.Parameters))
	for _, p := range template.Parameters {
		params = append(params, TemplateParamInfo{
			Name:        p.Name,
			Description: p.Description,
			Default:     p.Default,
			Required:    p.Required,
			Type:        p.Type,
			Options:     p.Options,
		})
	}

	c.JSON(http.StatusOK, TemplateInfo{
		Name:        template.Name,
		Description: template.Description,
		Parameters:  params,
		IsTemplate:  template.IsTemplate,
	})
}

// InstantiateTemplate godoc
// @Summary 实例化规则模板
// @Description 从模板创建规则实例
// @Tags rules
// @Accept json
// @Produce json
// @Param name path string true "模板名称"
// @Param request body InstantiateTemplateRequest true "模板实例化请求"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/rules/templates/{name}/instantiate [post]
func (h *RulesHandler) InstantiateTemplate(c *gin.Context) {
	name := c.Param("name")

	var req InstantiateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	req.Name = name

	instantiated, err := h.customManager.InstantiateTemplate(req.Name, req.Params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
			Code:  "INSTANTIATE_ERROR",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Template instantiated successfully",
		"rule_name": instantiated.Name,
		"template":  instantiated,
	})
}
