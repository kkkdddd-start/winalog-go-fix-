package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/correlation"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type CorrelationHandler struct {
	db *storage.DB
}

type CorrelationRequest struct {
	TimeWindow string   `json:"time_window"`
	Rules      []string `json:"rules"`
}

type CorrelationResponse struct {
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Events      int       `json:"event_count"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Description string    `json:"description"`
}

// NewCorrelationHandler godoc
// @Summary 创建关联分析处理器
// @Description 初始化CorrelationHandler
// @Tags correlation
// @Param db query string true "数据库实例"
// @Router /api/correlation [get]
func NewCorrelationHandler(db *storage.DB) *CorrelationHandler {
	return &CorrelationHandler{db: db}
}

// Analyze godoc
// @Summary 执行关联分析
// @Description 对事件日志进行关联规则分析，检测跨事件模式
// @Tags correlation
// @Accept json
// @Produce json
// @Param request body CorrelationRequest false "关联分析请求参数"
// @Success 200 {object} map[string]interface{} "results": []CorrelationResponse, "count": int
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/correlation/analyze [post]
func (h *CorrelationHandler) Analyze(c *gin.Context) {
	var req CorrelationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.TimeWindow = "24h"
	}

	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()

	if req.TimeWindow != "" {
		if tf, err := types.ParseTimeFilter(req.TimeWindow); err == nil && tf != nil {
			startTime = tf.Start
			endTime = tf.End
		}
	}

	events, _, err := h.db.SearchEvents(&storage.EventFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
		Limit:     100000,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	if len(events) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"results": []CorrelationResponse{},
			"count":   0,
		})
		return
	}

	engine := correlation.NewEngine(0)
	engine.LoadEvents(events)

	correlationRules := builtin.GetCorrelationRules()
	if len(req.Rules) > 0 {
		var filtered []*rules.CorrelationRule
		for _, r := range correlationRules {
			for _, name := range req.Rules {
				if r.Name == name {
					filtered = append(filtered, r)
					break
				}
			}
		}
		correlationRules = filtered
	}

	results, err := engine.Analyze(context.Background(), correlationRules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	response := make([]CorrelationResponse, 0, len(results))
	for _, r := range results {
		response = append(response, CorrelationResponse{
			RuleName:    r.RuleName,
			Severity:    string(r.Severity),
			Events:      len(r.Events),
			StartTime:   r.StartTime,
			EndTime:     r.EndTime,
			Description: r.Description,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"results": response,
		"count":   len(response),
	})
}

// GetInfo godoc
// @Summary 获取关联分析服务信息
// @Description 返回关联分析服务的状态和可用端点
// @Tags correlation
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/correlation [get]
func (h *CorrelationHandler) GetInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "correlation",
		"status":  "operational",
		"endpoints": []string{
			"POST /api/correlation/analyze",
		},
	})
}

// SetupCorrelationRoutes godoc
// @Summary 设置关联分析路由
// @Description 配置关联分析相关的API路由
// @Tags correlation
// @Router /api/correlation [get]
// @Router /api/correlation/analyze [post]
func SetupCorrelationRoutes(r *gin.Engine, h *CorrelationHandler) {
	correlationGroup := r.Group("/api/correlation")
	{
		correlationGroup.GET("", h.GetInfo)
		correlationGroup.POST("/analyze", h.Analyze)
	}
}
