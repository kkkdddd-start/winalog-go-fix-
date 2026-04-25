package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/alerts"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type PolicyHandler struct {
	engine *alerts.Engine
}

type PolicyTemplateRequest struct {
	Name   string            `json:"name" binding:"required"`
	Params map[string]string `json:"params"`
}

type PolicyTemplateInfo struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	PolicyType   string          `json:"policy_type"`
	Parameters   []ParameterInfo `json:"parameters"`
	TimeWindow   string          `json:"time_window"`
	Enabled      bool            `json:"enabled"`
	Priority     int             `json:"priority"`
	MITREMapping []string        `json:"mitre_mapping,omitempty"`
}

type ParameterInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default,omitempty"`
	Required    bool     `json:"required"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
}

// NewPolicyHandler godoc
// @Summary 创建策略处理器
// @Description 初始化PolicyHandler
// @Tags policy
// @Param engine query string true "告警引擎实例"
// @Router /api/policy [get]
func NewPolicyHandler(engine *alerts.Engine) *PolicyHandler {
	return &PolicyHandler{engine: engine}
}

// ListTemplates godoc
// @Summary 列出策略模板
// @Description 返回所有可用的策略模板
// @Tags policy
// @Produce json
// @Success 200 {object} map[string]interface{} "templates": []PolicyTemplateInfo, "total": int
// @Failure 500 {object} ErrorResponse
// @Router /api/policy-templates [get]
func (h *PolicyHandler) ListTemplates(c *gin.Context) {
	policyMgr := alerts.GetPolicyManager()
	templates := policyMgr.ListTemplates()

	response := make([]PolicyTemplateInfo, 0, len(templates))
	for _, t := range templates {
		params := make([]ParameterInfo, 0, len(t.Parameters))
		for _, p := range t.Parameters {
			params = append(params, ParameterInfo{
				Name:        p.Name,
				Description: p.Description,
				Default:     p.Default,
				Required:    p.Required,
				Type:        p.Type,
				Options:     p.Options,
			})
		}

		response = append(response, PolicyTemplateInfo{
			Name:         t.Name,
			Description:  t.Description,
			PolicyType:   string(t.PolicyType),
			Parameters:   params,
			TimeWindow:   t.TimeWindow.String(),
			Enabled:      t.Enabled,
			Priority:     t.Priority,
			MITREMapping: t.MITREMapping,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": response,
		"total":     len(response),
	})
}

// GetTemplate godoc
// @Summary 获取策略模板详情
// @Description 返回指定策略模板的详细信息
// @Tags policy
// @Produce json
// @Param name path string true "模板名称"
// @Success 200 {object} PolicyTemplateInfo
// @Failure 404 {object} ErrorResponse
// @Router /api/policy-templates/{name} [get]
func (h *PolicyHandler) GetTemplate(c *gin.Context) {
	name := c.Param("name")

	policyMgr := alerts.GetPolicyManager()
	template, ok := policyMgr.GetTemplate(name)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Template not found",
			Code:  "TEMPLATE_NOT_FOUND",
		})
		return
	}

	params := make([]ParameterInfo, 0, len(template.Parameters))
	for _, p := range template.Parameters {
		params = append(params, ParameterInfo{
			Name:        p.Name,
			Description: p.Description,
			Default:     p.Default,
			Required:    p.Required,
			Type:        p.Type,
			Options:     p.Options,
		})
	}

	c.JSON(http.StatusOK, PolicyTemplateInfo{
		Name:         template.Name,
		Description:  template.Description,
		PolicyType:   string(template.PolicyType),
		Parameters:   params,
		TimeWindow:   template.TimeWindow.String(),
		Enabled:      template.Enabled,
		Priority:     template.Priority,
		MITREMapping: template.MITREMapping,
	})
}

// InstantiateTemplate godoc
// @Summary 实例化策略模板
// @Description 从模板创建策略实例
// @Tags policy
// @Accept json
// @Produce json
// @Param request body PolicyTemplateRequest true "模板实例化请求"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/policy-templates [post]
func (h *PolicyHandler) InstantiateTemplate(c *gin.Context) {
	var req PolicyTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	policyMgr := alerts.GetPolicyManager()

	_, ok := policyMgr.GetTemplate(req.Name)
	if !ok {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Template not found",
			Code:  "TEMPLATE_NOT_FOUND",
		})
		return
	}

	ruleName := req.Name
	if params, ok := req.Params["rule_name"]; ok {
		ruleName = params
		delete(req.Params, "rule_name")
	}

	if h.engine != nil {
		if err := h.engine.LoadPolicyTemplate(req.Name, ruleName, req.Params); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to load template: " + err.Error(),
				Code:  "INTERNAL_ERROR",
			})
			return
		}
	}

	instance, err := policyMgr.InstantiateTemplate(req.Name, ruleName, req.Params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to instantiate template: " + err.Error(),
			Code:  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":       "Template instantiated successfully",
		"template_name": instance.TemplateName,
		"rule_name":     instance.RuleName,
		"created_at":    instance.CreatedAt,
	})
}

// ListInstances godoc
// @Summary 列出策略实例
// @Description 返回所有策略实例
// @Tags policy
// @Produce json
// @Success 200 {object} map[string]interface{} "instances": []object, "total": int
// @Router /api/policy-instances [get]
func (h *PolicyHandler) ListInstances(c *gin.Context) {
	policyMgr := alerts.GetPolicyManager()
	instances := policyMgr.ListInstances()

	c.JSON(http.StatusOK, gin.H{
		"instances": instances,
		"total":     len(instances),
	})
}

// DeleteInstance godoc
// @Summary 删除策略实例
// @Description 删除指定的策略实例
// @Tags policy
// @Produce json
// @Param key path string true "实例键名"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/policy-instances/{key} [delete]
func (h *PolicyHandler) DeleteInstance(c *gin.Context) {
	key := c.Param("key")

	policyMgr := alerts.GetPolicyManager()
	if !policyMgr.DeleteInstance(key) {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Instance not found",
			Code:  "INSTANCE_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Instance deleted successfully",
	})
}

// ApplyTemplates godoc
// @Summary 应用策略模板
// @Description 将所有策略模板应用到告警引擎
// @Tags policy
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/policy-templates/apply [post]
func (h *PolicyHandler) ApplyTemplates(c *gin.Context) {
	if h.engine == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Alert engine not available",
			Code:  "ENGINE_NOT_AVAILABLE",
		})
		return
	}

	if err := h.engine.ApplyPolicyTemplates(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to apply templates: " + err.Error(),
			Code:  "INTERNAL_ERROR",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Policy templates applied successfully",
	})
}

type CreateCustomPolicyRequest struct {
	Name         string          `json:"name" binding:"required"`
	Description  string          `json:"description"`
	PolicyType   string          `json:"policy_type" binding:"required"`
	Parameters   []ParameterInfo `json:"parameters"`
	Conditions   []ConditionInfo `json:"conditions"`
	Actions      []ActionInfo    `json:"actions"`
	TimeWindow   int             `json:"time_window"`
	Enabled      bool            `json:"enabled"`
	Priority     int             `json:"priority"`
	MITREMapping []string        `json:"mitre_mapping"`
}

type ConditionInfo struct {
	Field    string      `json:"field" binding:"required"`
	Operator string      `json:"operator" binding:"required"`
	Value    interface{} `json:"value" binding:"required"`
}

type ActionInfo struct {
	Type       string                 `json:"type" binding:"required"`
	Parameters map[string]interface{} `json:"parameters"`
}

// CreateCustomPolicy godoc
// @Summary 创建自定义策略
// @Description 创建新的自定义策略模板
// @Tags policy
// @Accept json
// @Produce json
// @Param request body CreateCustomPolicyRequest true "自定义策略请求"
// @Success 201 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/policies [post]
func (h *PolicyHandler) CreateCustomPolicy(c *gin.Context) {
	var req CreateCustomPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	policyMgr := alerts.GetPolicyManager()

	params := make([]alerts.PolicyParam, 0, len(req.Parameters))
	for _, p := range req.Parameters {
		params = append(params, alerts.PolicyParam{
			Name:        p.Name,
			Description: p.Description,
			Default:     p.Default,
			Required:    p.Required,
			Type:        p.Type,
			Options:     p.Options,
		})
	}

	conditions := make([]alerts.PolicyCondition, 0, len(req.Conditions))
	for _, cond := range req.Conditions {
		conditions = append(conditions, alerts.PolicyCondition{
			Field:    cond.Field,
			Operator: cond.Operator,
			Value:    cond.Value,
		})
	}

	actions := make([]alerts.PolicyAction, 0, len(req.Actions))
	for _, a := range req.Actions {
		actions = append(actions, alerts.PolicyAction{
			Type:       a.Type,
			Parameters: a.Parameters,
		})
	}

	var policyType alerts.PolicyType
	switch req.PolicyType {
	case "upgrade":
		policyType = alerts.PolicyTypeUpgrade
	case "suppress":
		policyType = alerts.PolicyTypeSuppress
	default:
		policyType = alerts.PolicyTypeUpgrade
	}

	template := &alerts.PolicyTemplate{
		Name:         req.Name,
		Description:  req.Description,
		PolicyType:   policyType,
		Parameters:   params,
		Conditions:   conditions,
		Actions:      actions,
		TimeWindow:   0,
		Enabled:      req.Enabled,
		Priority:     req.Priority,
		MITREMapping: req.MITREMapping,
	}

	if req.TimeWindow > 0 {
		template.TimeWindow = 0
	}

	if err := policyMgr.CreateCustomTemplate(template); err != nil {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error: err.Error(),
			Code:  "TEMPLATE_EXISTS",
		})
		return
	}

	c.JSON(http.StatusCreated, SuccessResponse{
		Message: "Custom policy template created successfully",
	})
}

// DeleteCustomPolicy godoc
// @Summary 删除自定义策略
// @Description 删除指定的自定义策略模板
// @Tags policy
// @Produce json
// @Param name path string true "策略名称"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/policies/{name} [delete]
func (h *PolicyHandler) DeleteCustomPolicy(c *gin.Context) {
	name := c.Param("name")

	policyMgr := alerts.GetPolicyManager()
	if !policyMgr.DeleteTemplate(name) {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "Template not found",
			Code:  "TEMPLATE_NOT_FOUND",
		})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Message: "Custom policy template deleted successfully",
	})
}

// SetupPolicyRoutes godoc
// @Summary 设置策略路由
// @Description 配置策略管理相关的API路由
// @Tags policy
// @Router /api/policy-templates [get]
// @Router /api/policy-templates/{name} [get]
// @Router /api/policy-templates [post]
// @Router /api/policy-templates/apply [post]
// @Router /api/policy-templates/{name} [delete]
// @Router /api/policy-instances [get]
// @Router /api/policy-instances/{key} [delete]
// @Router /api/policies [post]
// @Router /api/policies/{name} [delete]
func SetupPolicyRoutes(r *gin.Engine, policyHandler *PolicyHandler) {
	policy := r.Group("/api/policy-templates")
	{
		policy.GET("", policyHandler.ListTemplates)
		policy.GET("/:name", policyHandler.GetTemplate)
		policy.POST("", policyHandler.InstantiateTemplate)
		policy.POST("/apply", policyHandler.ApplyTemplates)
		policy.DELETE("/:name", policyHandler.DeleteCustomPolicy)
	}

	policyInstances := r.Group("/api/policy-instances")
	{
		policyInstances.GET("", policyHandler.ListInstances)
		policyInstances.DELETE("/:key", policyHandler.DeleteInstance)
	}

	customPolicy := r.Group("/api/policies")
	{
		customPolicy.POST("", policyHandler.CreateCustomPolicy)
		customPolicy.DELETE("/:name", policyHandler.DeleteCustomPolicy)
	}
}
