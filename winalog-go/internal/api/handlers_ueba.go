package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/ueba"
)

type UEBAHandler struct {
	db     *storage.DB
	engine *ueba.Engine
}

type UEBARequest struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Hours     int    `json:"hours"`
}

type UEBAResult struct {
	Type            string                `json:"type"`
	Anomalies       []*ueba.AnomalyResult `json:"anomalies"`
	TotalAnomaly    int                   `json:"total_anomaly"`
	HighRiskCount   int                   `json:"high_risk_count"`
	MediumRiskCount int                   `json:"medium_risk_count"`
	Duration        string                `json:"duration"`
}

// NewUEBAHandler godoc
// @Summary 创建UEBA处理器
// @Description 初始化UEBAHandler
// @Tags ueba
// @Param db query string true "数据库实例"
// @Router /api/ueba [get]
func NewUEBAHandler(db *storage.DB) *UEBAHandler {
	engine := ueba.NewEngine(ueba.EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	return &UEBAHandler{
		db:     db,
		engine: engine,
	}
}

// Analyze godoc
// @Summary 执行UEBA分析
// @Description 对用户行为进行分析，检测异常活动
// @Tags ueba
// @Accept json
// @Produce json
// @Param request body UEBARequest false "UEBA分析请求"
// @Success 200 {object} UEBAResult
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/ueba/analyze [post]
func (h *UEBAHandler) Analyze(c *gin.Context) {
	startTime := time.Now()

	var req UEBARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = UEBARequest{}
	}

	hours := req.Hours
	if hours <= 0 {
		hours = 24
	}

	endTime := time.Now()
	start := endTime.Add(-time.Duration(hours) * time.Hour)

	if req.StartTime != "" || req.EndTime != "" {
		timeInput := req.StartTime
		if req.EndTime != "" {
			timeInput = req.StartTime + "," + req.EndTime
		}
		if tf, err := types.ParseTimeFilter(timeInput); err == nil && tf != nil {
			start = tf.Start
			endTime = tf.End
		}
	}

	filter := &storage.EventFilter{
		StartTime: &start,
		EndTime:   &endTime,
		Limit:     50000,
	}

	events, _, err := h.db.ListEvents(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to fetch events"})
		return
	}

	if len(events) < 10 {
		c.JSON(http.StatusOK, UEBAResult{
			Type:            "ueba_analysis",
			Anomalies:       []*ueba.AnomalyResult{},
			TotalAnomaly:    0,
			HighRiskCount:   0,
			MediumRiskCount: 0,
			Duration:        time.Since(startTime).String(),
		})
		return
	}

	anomalies := h.engine.DetectAnomalies(events)

	highCount := 0
	mediumCount := 0
	for _, a := range anomalies {
		if a.Severity == "high" {
			highCount++
		} else if a.Severity == "medium" {
			mediumCount++
		}
	}

	c.JSON(http.StatusOK, UEBAResult{
		Type:            "ueba_analysis",
		Anomalies:       anomalies,
		TotalAnomaly:    len(anomalies),
		HighRiskCount:   highCount,
		MediumRiskCount: mediumCount,
		Duration:        time.Since(startTime).String(),
	})
}

// GetProfiles godoc
// @Summary 获取用户行为画像
// @Description 返回所有用户的行为分析画像
// @Tags ueba
// @Produce json
// @Success 200 {object} map[string]interface{} "profiles": []object, "total": int
// @Router /api/ueba/profiles [get]
func (h *UEBAHandler) GetProfiles(c *gin.Context) {
	profiles := h.engine.GetUserActivity()

	profileList := make([]map[string]interface{}, 0)
	for user, baseline := range profiles {
		profileList = append(profileList, map[string]interface{}{
			"user":               user,
			"login_count":        baseline.LoginCount,
			"last_updated":       baseline.LastUpdated,
			"avg_events_per_day": baseline.AvgEventsPerDay,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"profiles": profileList,
		"total":    len(profileList),
	})
}

// GetInfo godoc
// @Summary 获取UEBA服务信息
// @Description 返回UEBA服务的状态和可用端点
// @Tags ueba
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/ueba [get]
func (h *UEBAHandler) GetInfo(c *gin.Context) {
	profiles := h.engine.GetUserActivity()
	profileCount := len(profiles)

	c.JSON(http.StatusOK, gin.H{
		"service":       "ueba",
		"status":        "operational",
		"profile_count": profileCount,
		"endpoints": []string{
			"POST /api/ueba/analyze",
			"GET /api/ueba/profiles",
			"GET /api/ueba/baseline",
			"GET /api/ueba/anomaly/:type",
		},
	})
}

// GetAnomalyDetails godoc
// @Summary 获取异常类型详情
// @Description 返回指定异常类型的描述信息
// @Tags ueba
// @Produce json
// @Param type path string true "异常类型"
// @Success 200 {object} map[string]interface{}
// @Router /api/ueba/anomaly/{type} [get]
func (h *UEBAHandler) GetAnomalyDetails(c *gin.Context) {
	anomalyType := c.Param("type")

	c.JSON(http.StatusOK, gin.H{
		"type":        anomalyType,
		"description": getAnomalyDescription(anomalyType),
	})
}

// GetBaseline godoc
// @Summary 获取行为基线
// @Description 返回用户行为的基线数据
// @Tags ueba
// @Produce json
// @Success 200 {object} map[string]interface{} "baseline": []object, "total": int
// @Router /api/ueba/baseline [get]
func (h *UEBAHandler) GetBaseline(c *gin.Context) {
	profiles := h.engine.GetUserActivity()

	profileList := make([]map[string]interface{}, 0)
	for user, baseline := range profiles {
		typicalHours := make([]int, 0)
		for hour := range baseline.TypicalHours {
			typicalHours = append(typicalHours, hour)
		}

		typicalComputers := make([]string, 0)
		for computer := range baseline.TypicalComputers {
			typicalComputers = append(typicalComputers, computer)
		}

		profileList = append(profileList, map[string]interface{}{
			"user":               user,
			"login_count":        baseline.LoginCount,
			"last_updated":       baseline.LastUpdated,
			"avg_events_per_day": baseline.AvgEventsPerDay,
			"typical_hours":      typicalHours,
			"typical_computers":  typicalComputers,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"baseline": profileList,
		"total":    len(profileList),
	})
}

// LearnBaseline godoc
// @Summary 学习行为基线
// @Description 从历史事件中学习用户行为基线
// @Tags ueba
// @Accept json
// @Produce json
// @Param request body UEBARequest false "学习请求参数"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/ueba/baseline/learn [post]
func (h *UEBAHandler) LearnBaseline(c *gin.Context) {
	var req UEBARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = UEBARequest{}
	}

	hours := req.Hours
	if hours <= 0 {
		hours = 168
	}

	endTime := time.Now()
	start := endTime.Add(-time.Duration(hours) * time.Hour)

	if req.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
			start = t
		}
	}
	if req.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
			endTime = t
		}
	}

	filter := &storage.EventFilter{
		StartTime: &start,
		EndTime:   &endTime,
		Limit:     100000,
	}

	events, _, err := h.db.ListEvents(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to fetch events"})
		return
	}

	if len(events) < 10 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "insufficient events for baseline learning (minimum 10)"})
		return
	}

	if err := h.engine.Learn(events); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to learn baseline"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "baseline learned successfully",
		"events":    len(events),
		"time_span": time.Since(start).String(),
	})
}

// ClearBaseline godoc
// @Summary 清除行为基线
// @Description 清除所有学习的基线数据
// @Tags ueba
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/ueba/baseline [delete]
func (h *UEBAHandler) ClearBaseline(c *gin.Context) {
	h.engine.Clear()
	c.JSON(http.StatusOK, gin.H{
		"message": "baseline cleared successfully",
	})
}

func getAnomalyDescription(anomalyType string) string {
	descriptions := map[string]string{
		"impossible_travel":    "Detects when a user logs in from two geographically distant locations in an impossibly short time period",
		"abnormal_behavior":    "Detects deviations from a user's established behavioral patterns",
		"abnormal_hours":       "Detects activity outside typical working hours",
		"unusual_hours":        "Detects significant activity during unusual hours",
		"new_location":         "Detects logins from new or unfamiliar locations",
		"privilege_escalation": "Detects unusual privilege assignment events",
		"brute_force":          "Detects potential brute force attack patterns",
		"data_exfiltration":    "Detects potential data exfiltration activity",
	}

	if desc, ok := descriptions[anomalyType]; ok {
		return desc
	}
	return "Unknown anomaly type"
}

// SetupUEBARoutes godoc
// @Summary 设置UEBA路由
// @Description 配置UEBA分析相关的API路由
// @Tags ueba
// @Router /api/ueba [get]
// @Router /api/ueba/analyze [post]
// @Router /api/ueba/profiles [get]
// @Router /api/ueba/anomaly/{type} [get]
// @Router /api/ueba/baseline [get]
// @Router /api/ueba/baseline/learn [post]
// @Router /api/ueba/baseline [delete]
func SetupUEBARoutes(r *gin.Engine, uebaHandler *UEBAHandler) {
	ueba := r.Group("/api/ueba")
	{
		ueba.GET("", uebaHandler.GetInfo)
		ueba.POST("/analyze", uebaHandler.Analyze)
		ueba.GET("/profiles", uebaHandler.GetProfiles)
		ueba.GET("/anomaly/:type", uebaHandler.GetAnomalyDetails)
		ueba.GET("/baseline", uebaHandler.GetBaseline)
		ueba.POST("/baseline/learn", uebaHandler.LearnBaseline)
		ueba.DELETE("/baseline", uebaHandler.ClearBaseline)
	}
}
