package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type MultiHandler struct {
	db *storage.DB
}

type MachineInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Domain    string `json:"domain"`
	Role      string `json:"role"`
	OSVersion string `json:"os_version"`
	LastSeen  string `json:"last_seen"`
}

type CrossMachineActivity struct {
	User           string   `json:"user"`
	MachineCount   int      `json:"machine_count"`
	Machines       []string `json:"machines"`
	LoginCount     int      `json:"login_count"`
	Suspicious     bool     `json:"suspicious"`
	Severity       string   `json:"severity"`
	Recommendation string   `json:"recommendation"`
}

type LateralMovement struct {
	SourceMachine string   `json:"source_machine"`
	TargetMachine string   `json:"target_machine"`
	User          string   `json:"user"`
	EventID       int      `json:"event_id"`
	Timestamp     string   `json:"timestamp"`
	IPAddress     string   `json:"ip_address"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	MITREAttack   []string `json:"mitre_attack"`
}

type MultiAnalyzeResponse struct {
	Machines        []MachineInfo          `json:"machines"`
	CrossMachine    []CrossMachineActivity `json:"cross_machine_activity"`
	LateralMovement []LateralMovement      `json:"lateral_movement"`
	Summary         string                 `json:"summary"`
	SuspiciousCount int                    `json:"suspicious_count"`
	AnalysisID      string                 `json:"analysis_id"`
}

// NewMultiHandler godoc
// @Summary 创建多机分析处理器
// @Description 初始化MultiHandler
// @Tags multi
// @Param db query string true "数据库实例"
// @Router /api/multi [get]
func NewMultiHandler(db *storage.DB) *MultiHandler {
	return &MultiHandler{db: db}
}

// Analyze godoc
// @Summary 执行多机关联分析
// @Description 分析跨多台机器的活动，包括横向移动检测
// @Tags multi
// @Produce json
// @Success 200 {object} MultiAnalyzeResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/multi/analyze [post]
func (h *MultiHandler) Analyze(c *gin.Context) {
	machines, err := h.getMachineContexts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	crossMachine, err := h.analyzeCrossMachineActivity()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	lateral, err := h.detectLateralMovement()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	suspiciousCount := 0
	for _, activity := range crossMachine {
		if activity.Suspicious {
			suspiciousCount++
		}
	}

	analysisID := "multi_" + time.Now().Format("20060102150405")

	c.JSON(http.StatusOK, MultiAnalyzeResponse{
		Machines:        machines,
		CrossMachine:    crossMachine,
		LateralMovement: lateral,
		Summary:         generateMultiSummary(len(machines), suspiciousCount, len(lateral)),
		SuspiciousCount: suspiciousCount,
		AnalysisID:      analysisID,
	})
}

// Lateral godoc
// @Summary 检测横向移动
// @Description 检测可能的横向移动活动
// @Tags multi
// @Produce json
// @Success 200 {object} map[string]interface{} "lateral_movement": []LateralMovement, "count": int
// @Failure 500 {object} ErrorResponse
// @Router /api/multi/lateral [get]
func (h *MultiHandler) Lateral(c *gin.Context) {
	lateral, err := h.detectLateralMovement()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"lateral_movement": lateral,
		"count":            len(lateral),
	})
}

// GetInfo godoc
// @Summary 获取多机分析服务信息
// @Description 返回多机分析服务的状态和可用端点
// @Tags multi
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/multi [get]
func (h *MultiHandler) GetInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "multi",
		"status":  "operational",
		"endpoints": []string{
			"POST /api/multi/analyze",
			"GET /api/multi/lateral",
		},
	})
}

func (h *MultiHandler) getMachineContexts() ([]MachineInfo, error) {
	rows, err := h.db.Query(`
		SELECT machine_id, machine_name, ip_address, domain, role, os_version, last_seen
		FROM machine_context
		ORDER BY last_seen DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var machines []MachineInfo
	for rows.Next() {
		var m MachineInfo
		if err := rows.Scan(&m.ID, &m.Name, &m.IP, &m.Domain, &m.Role, &m.OSVersion, &m.LastSeen); err != nil {
			continue
		}
		machines = append(machines, m)
	}

	if machines == nil {
		machines = []MachineInfo{}
	}
	return machines, nil
}

func (h *MultiHandler) analyzeCrossMachineActivity() ([]CrossMachineActivity, error) {
	rows, err := h.db.Query(`
		SELECT computer, user, event_id, timestamp, ip_address, message
		FROM events
		WHERE event_id IN (4624, 4625, 4648, 4672, 4728, 4729, 4732, 4756, 4757)
		AND timestamp > datetime('now', '-7 days')
		ORDER BY timestamp DESC
		LIMIT 5000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	loginCounts := make(map[string]map[string]int)
	userMachines := make(map[string][]string)

	for rows.Next() {
		var computer, user, timestamp, ipAddress, message string
		var eventID int64
		if err := rows.Scan(&computer, &user, &eventID, &timestamp, &ipAddress, &message); err != nil {
			continue
		}

		if loginCounts[user] == nil {
			loginCounts[user] = make(map[string]int)
		}
		loginCounts[user][computer]++
		if !containsString(userMachines[user], computer) {
			userMachines[user] = append(userMachines[user], computer)
		}
	}

	var activities []CrossMachineActivity
	for user, comps := range userMachines {
		if len(comps) >= 2 {
			totalLogins := 0
			for _, count := range loginCounts[user] {
				totalLogins += count
			}

			severity := "low"
			suspicious := false
			recommendation := "Normal user activity pattern"
			if len(comps) >= 5 {
				severity = "high"
				suspicious = true
				recommendation = "Investigate: User logged into multiple machines simultaneously"
			} else if len(comps) >= 3 {
				severity = "medium"
				suspicious = true
				recommendation = "Review: User accessed multiple machines"
			}

			activities = append(activities, CrossMachineActivity{
				User:           user,
				MachineCount:   len(comps),
				Machines:       comps,
				LoginCount:     totalLogins,
				Suspicious:     suspicious,
				Severity:       severity,
				Recommendation: recommendation,
			})
		}
	}

	if activities == nil {
		activities = []CrossMachineActivity{}
	}
	return activities, nil
}

func (h *MultiHandler) detectLateralMovement() ([]LateralMovement, error) {
	rows, err := h.db.Query(`
		SELECT computer, user, event_id, timestamp, ip_address, message
		FROM events
		WHERE event_id IN (4624, 4625, 4648, 4672, 4688, 4697, 4698)
		AND timestamp > datetime('now', '-24 hours')
		ORDER BY timestamp DESC
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var movements []LateralMovement
	for rows.Next() {
		var computer, user, timestamp, ipAddress, message string
		var eventID int64
		if err := rows.Scan(&computer, &user, &eventID, &timestamp, &ipAddress, &message); err != nil {
			continue
		}

		severity := "low"
		description := "Normal authentication event"
		mitre := []string{}

		switch eventID {
		case 4624:
			if ipAddress != "" && ipAddress != "127.0.0.1" && ipAddress != "::1" {
				severity = "medium"
				description = "Successful login from external IP"
				mitre = []string{"T1078", "Valid Accounts"}
			}
		case 4625:
			severity = "medium"
			description = "Failed login attempt"
			mitre = []string{"T1110", "Brute Force"}
		case 4648:
			severity = "high"
			description = "Explicit credentials used for logon"
			mitre = []string{"T1078", "Valid Accounts"}
		case 4672:
			severity = "high"
			description = "Special privileges assigned to new logon"
			mitre = []string{"T1068", "Exploitation for Privilege Escalation"}
		case 4688:
			severity = "medium"
			description = "Process creation detected"
			mitre = []string{"T1059", "Command and Scripting Interpreter"}
		case 4697:
			severity = "high"
			description = "Windows service installed"
			mitre = []string{"T1543", "Create/Modify System Process"}
		case 4698:
			severity = "medium"
			description = "Scheduled task created"
			mitre = []string{"T1053", "Scheduled Transfer/Job"}
		}

		if severity != "low" || eventID == 4624 {
			sourceMachine := "unknown"
			if ipAddress != "" && ipAddress != "127.0.0.1" && ipAddress != "::1" {
				sourceMachine = ipAddress + " (external)"
			} else if eventID == 4648 {
				sourceMachine = "remote host (explicit credentials)"
			}
			movements = append(movements, LateralMovement{
				SourceMachine: sourceMachine,
				TargetMachine: computer,
				User:          user,
				EventID:       int(eventID),
				Timestamp:     timestamp,
				IPAddress:     ipAddress,
				Severity:      severity,
				Description:   description,
				MITREAttack:   mitre,
			})
		}
	}

	if movements == nil {
		movements = []LateralMovement{}
	}
	return movements, nil
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateMultiSummary(machineCount, suspiciousCount, lateralCount int) string {
	if machineCount == 0 {
		return "No machine data available. Import event logs from multiple machines to enable cross-machine analysis."
	}
	if suspiciousCount == 0 && lateralCount == 0 {
		return "No suspicious cross-machine activity detected."
	}
	return "Analysis found " + itoa(suspiciousCount) + " suspicious activities and " + itoa(lateralCount) + " lateral movement indicators."
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

// SetupMultiRoutes godoc
// @Summary 设置多机分析路由
// @Description 配置多机关联分析相关的API路由
// @Tags multi
// @Router /api/multi [get]
// @Router /api/multi/analyze [post]
// @Router /api/multi/lateral [get]
func SetupMultiRoutes(r *gin.Engine, h *MultiHandler) {
	multi := r.Group("/api/multi")
	{
		multi.GET("", h.GetInfo)
		multi.POST("/analyze", h.Analyze)
		multi.GET("/lateral", h.Lateral)
	}
}
