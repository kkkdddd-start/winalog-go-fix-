package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/alerts"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type SuppressHandler struct {
	db          *storage.DB
	alertEngine *alerts.Engine
}

type SuppressRuleRequest struct {
	Name       string                 `json:"name" binding:"required"`
	Conditions []SuppressConditionReq `json:"conditions"`
	Duration   int                    `json:"duration"`
	Scope      string                 `json:"scope"`
	Enabled    bool                   `json:"enabled"`
	ExpiresAt  string                 `json:"expires_at"`
}

type SuppressConditionReq struct {
	Field    string      `json:"field" binding:"required"`
	Operator string      `json:"operator" binding:"required"`
	Value    interface{} `json:"value" binding:"required"`
}

type SuppressRuleResponse struct {
	ID         int64                     `json:"id"`
	Name       string                    `json:"name"`
	Conditions []types.SuppressCondition `json:"conditions"`
	Duration   int                       `json:"duration"`
	Scope      string                    `json:"scope"`
	Enabled    bool                      `json:"enabled"`
	ExpiresAt  string                    `json:"expires_at"`
	CreatedAt  string                    `json:"created_at"`
}

// NewSuppressHandler godoc
// @Summary 创建抑制处理器
// @Description 初始化SuppressHandler
// @Tags suppress
// @Param db query string true "数据库实例"
// @Param alertEngine query string true "告警引擎实例"
// @Router /api/suppress [get]
func NewSuppressHandler(db *storage.DB, alertEngine *alerts.Engine) *SuppressHandler {
	return &SuppressHandler{db: db, alertEngine: alertEngine}
}

// ListSuppressRules godoc
// @Summary 列出抑制规则
// @Description 返回所有告警抑制规则
// @Tags suppress
// @Produce json
// @Success 200 {object} map[string]interface{} "rules": []SuppressRuleResponse, "total": int
// @Failure 500 {object} ErrorResponse
// @Router /api/suppress [get]
func (h *SuppressHandler) ListSuppressRules(c *gin.Context) {
	rows, err := h.db.Query(`
		SELECT id, name, conditions, duration, scope, enabled, expires_at, created_at
		FROM suppress_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	rules := make([]SuppressRuleResponse, 0)
	for rows.Next() {
		var r SuppressRuleResponse
		var conditionsJSON string
		var expiresAt, createdAt sql.NullString

		if err := rows.Scan(&r.ID, &r.Name, &conditionsJSON, &r.Duration, &r.Scope, &r.Enabled, &expiresAt, &createdAt); err != nil {
			continue
		}

		if conditionsJSON != "" {
			parseConditions(conditionsJSON, &r.Conditions)
		}
		r.ExpiresAt = expiresAt.String
		r.CreatedAt = createdAt.String

		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// CreateSuppressRule godoc
// @Summary 创建抑制规则
// @Description 创建新的告警抑制规则
// @Tags suppress
// @Accept json
// @Produce json
// @Param request body SuppressRuleRequest true "抑制规则创建请求"
// @Success 201 {object} SuppressRuleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/suppress [post]
func (h *SuppressHandler) CreateSuppressRule(c *gin.Context) {
	var req SuppressRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	if req.Scope == "" {
		req.Scope = "global"
	}

	conditionsJSON := serializeConditions(req.Conditions)

	var expiresAt interface{}
	if req.ExpiresAt != "" {
		expiresAt = req.ExpiresAt
	}

	now := time.Now()
	result, err := h.db.Exec(`
		INSERT INTO suppress_rules (name, conditions, duration, scope, enabled, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, req.Name, conditionsJSON, req.Duration, req.Scope, req.Enabled, expiresAt, now)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	id, _ := result.LastInsertId()

	h.loadRulesToEngine()

	c.JSON(http.StatusCreated, SuppressRuleResponse{
		ID:         id,
		Name:       req.Name,
		Conditions: convertToSuppressConditions(req.Conditions),
		Duration:   req.Duration,
		Scope:      req.Scope,
		Enabled:    req.Enabled,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  now.Format(time.RFC3339),
	})
}

// UpdateSuppressRule godoc
// @Summary 更新抑制规则
// @Description 更新指定的告警抑制规则
// @Tags suppress
// @Accept json
// @Produce json
// @Param id path string true "规则ID"
// @Param request body SuppressRuleRequest true "抑制规则更新请求"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/suppress/{id} [put]
func (h *SuppressHandler) UpdateSuppressRule(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := parseID(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule id"})
		return
	}

	var req SuppressRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	conditionsJSON := serializeConditions(req.Conditions)

	var expiresAt interface{}
	if req.ExpiresAt != "" {
		expiresAt = req.ExpiresAt
	}

	_, err := h.db.Exec(`
		UPDATE suppress_rules
		SET name = ?, conditions = ?, duration = ?, scope = ?, enabled = ?, expires_at = ?
		WHERE id = ?
	`, req.Name, conditionsJSON, req.Duration, req.Scope, req.Enabled, expiresAt, id)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	h.loadRulesToEngine()

	c.JSON(http.StatusOK, SuccessResponse{Message: "Suppress rule updated"})
}

// DeleteSuppressRule godoc
// @Summary 删除抑制规则
// @Description 删除指定的告警抑制规则
// @Tags suppress
// @Produce json
// @Param id path string true "规则ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/suppress/{id} [delete]
func (h *SuppressHandler) DeleteSuppressRule(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := parseID(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule id"})
		return
	}

	_, err := h.db.Exec("DELETE FROM suppress_rules WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	h.loadRulesToEngine()

	c.JSON(http.StatusOK, SuccessResponse{Message: "Suppress rule deleted"})
}

// ToggleSuppressRule godoc
// @Summary 切换抑制规则状态
// @Description 启用或禁用指定的告警抑制规则
// @Tags suppress
// @Produce json
// @Param id path string true "规则ID"
// @Param enabled query bool true "目标状态"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/suppress/{id}/toggle [post]
func (h *SuppressHandler) ToggleSuppressRule(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := parseID(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule id"})
		return
	}

	enabled := c.Query("enabled") == "true"

	_, err := h.db.Exec("UPDATE suppress_rules SET enabled = ? WHERE id = ?", enabled, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	h.loadRulesToEngine()

	c.JSON(http.StatusOK, SuccessResponse{Message: "Suppress rule toggled"})
}

// GetSuppressRule godoc
// @Summary 获取抑制规则详情
// @Description 返回指定抑制规则的详细信息
// @Tags suppress
// @Produce json
// @Param id path string true "规则ID"
// @Success 200 {object} SuppressRuleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/suppress/{id} [get]
func (h *SuppressHandler) GetSuppressRule(c *gin.Context) {
	idStr := c.Param("id")
	var id int64
	if _, err := parseID(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule id"})
		return
	}

	var r SuppressRuleResponse
	var conditionsJSON string
	var expiresAt, createdAt sql.NullString

	err := h.db.QueryRow(`
		SELECT id, name, conditions, duration, scope, enabled, expires_at, created_at
		FROM suppress_rules WHERE id = ?
	`, id).Scan(&r.ID, &r.Name, &conditionsJSON, &r.Duration, &r.Scope, &r.Enabled, &expiresAt, &createdAt)

	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "rule not found"})
		return
	}

	if conditionsJSON != "" {
		parseConditions(conditionsJSON, &r.Conditions)
	}
	r.ExpiresAt = expiresAt.String
	r.CreatedAt = createdAt.String

	c.JSON(http.StatusOK, r)
}

func parseID(s string, id *int64) (bool, error) {
	var parsed int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		parsed = parsed*10 + int64(c-'0')
	}
	*id = parsed
	return true, nil
}

func serializeConditions(conditions []SuppressConditionReq) string {
	if len(conditions) == 0 {
		return ""
	}
	type cond struct {
		Field    string      `json:"field"`
		Operator string      `json:"operator"`
		Value    interface{} `json:"value"`
	}
	arr := make([]cond, len(conditions))
	for i, c := range conditions {
		arr[i] = cond(c)
	}
	data, err := json.Marshal(arr)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func parseConditions(jsonStr string, conditions *[]types.SuppressCondition) {
	if jsonStr == "" || jsonStr == "[]" {
		*conditions = []types.SuppressCondition{}
		return
	}

	type rawCondition struct {
		Field    string      `json:"field"`
		Operator string      `json:"operator"`
		Value    interface{} `json:"value"`
	}

	var raw []rawCondition
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		*conditions = []types.SuppressCondition{}
		return
	}

	*conditions = make([]types.SuppressCondition, len(raw))
	for i, r := range raw {
		(*conditions)[i] = types.SuppressCondition{
			Field:    r.Field,
			Operator: r.Operator,
			Value:    r.Value,
		}
	}
}

func convertToSuppressConditions(req []SuppressConditionReq) []types.SuppressCondition {
	result := make([]types.SuppressCondition, len(req))
	for i, c := range req {
		result[i] = types.SuppressCondition{
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}
	}
	return result
}

func (h *SuppressHandler) loadRulesToEngine() {
	if h.alertEngine == nil {
		return
	}
	h.alertEngine.ClearSuppressions()

	rows, err := h.db.Query(`
		SELECT id, name, conditions, duration, scope, enabled, expires_at, created_at
		FROM suppress_rules
		WHERE enabled = 1
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var name, conditionsJSON, scope string
		var expiresAt, createdAt sql.NullString
		var duration int
		var enabled bool

		if err := rows.Scan(&id, &name, &conditionsJSON, &duration, &scope, &enabled, &expiresAt, &createdAt); err != nil {
			continue
		}

		if !enabled {
			continue
		}

		rule := &types.SuppressRule{
			Name:     name,
			Duration: time.Duration(duration) * time.Minute,
			Scope:    scope,
			Enabled:  enabled,
		}

		if expiresAt.Valid && expiresAt.String != "" {
			if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
				rule.ExpiresAt = t
			}
		}

		if conditionsJSON != "" && conditionsJSON != "[]" {
			var conds []types.SuppressCondition
			parseConditions(conditionsJSON, &conds)
			rule.Conditions = conds
		}

		h.alertEngine.AddSuppressRule(rule)
	}
}

// SetupSuppressRoutes godoc
// @Summary 设置抑制路由
// @Description 配置告警抑制相关的API路由
// @Tags suppress
// @Router /api/suppress [get]
// @Router /api/suppress [post]
// @Router /api/suppress/{id} [get]
// @Router /api/suppress/{id} [put]
// @Router /api/suppress/{id} [delete]
// @Router /api/suppress/{id}/toggle [post]
func SetupSuppressRoutes(r *gin.Engine, suppressHandler *SuppressHandler) {
	suppress := r.Group("/api/suppress")
	{
		suppress.GET("", suppressHandler.ListSuppressRules)
		suppress.POST("", suppressHandler.CreateSuppressRule)
		suppress.GET("/:id", suppressHandler.GetSuppressRule)
		suppress.PUT("/:id", suppressHandler.UpdateSuppressRule)
		suppress.DELETE("/:id", suppressHandler.DeleteSuppressRule)
		suppress.POST("/:id/toggle", suppressHandler.ToggleSuppressRule)
	}
}
