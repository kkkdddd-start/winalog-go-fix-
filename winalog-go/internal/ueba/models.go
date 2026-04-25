package ueba

import (
	"strconv"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AnomalyType string

const (
	AnomalyTypeImpossibleTravel    AnomalyType = "impossible_travel"
	AnomalyTypeAbnormalBehavior    AnomalyType = "abnormal_behavior"
	AnomalyTypeAbnormalHours       AnomalyType = "abnormal_hours"
	AnomalyTypeUnusualHours        AnomalyType = "unusual_hours"
	AnomalyTypeNewLocation         AnomalyType = "new_location"
	AnomalyTypePrivilegeEscalation AnomalyType = "privilege_escalation"
	AnomalyTypeBruteForce          AnomalyType = "brute_force"
	AnomalyTypeDataExfiltration    AnomalyType = "data_exfiltration"
)

type AnomalyResult struct {
	Type        AnomalyType            `json:"type"`
	User        string                 `json:"user,omitempty"`
	Entity      string                 `json:"entity,omitempty"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
	EventIDs    []int64                `json:"event_ids,omitempty"`
	StartTime   time.Time              `json:"start_time,omitempty"`
	EndTime     time.Time              `json:"end_time,omitempty"`
}

type LoginLocation struct {
	User     string
	IP       string
	Computer string
	Time     time.Time
}

type BehaviorProfile struct {
	UserID          string           `json:"user_id"`
	LoginLocations  []*LoginLocation `json:"login_locations"`
	ActivityPattern map[string]int   `json:"activity_pattern"`
	RiskScore       float64          `json:"risk_score"`
	LastUpdated     time.Time        `json:"last_updated"`
	Anomalies       []*AnomalyResult `json:"anomalies,omitempty"`
}

type UEBAReport struct {
	GeneratedAt       time.Time        `json:"generated_at"`
	ProfilesAnalyzed  int              `json:"profiles_analyzed"`
	AnomaliesDetected int              `json:"anomalies_detected"`
	HighRiskUsers     []string         `json:"high_risk_users"`
	MediumRiskUsers   []string         `json:"medium_risk_users"`
	Anomalies         []*AnomalyResult `json:"anomalies"`
}

func NewUEBAReport() *UEBAReport {
	return &UEBAReport{
		GeneratedAt:       time.Now(),
		ProfilesAnalyzed:  0,
		AnomaliesDetected: 0,
		HighRiskUsers:     make([]string, 0),
		MediumRiskUsers:   make([]string, 0),
		Anomalies:         make([]*AnomalyResult, 0),
	}
}

func (r *UEBAReport) AddAnomaly(anomaly *AnomalyResult) {
	r.Anomalies = append(r.Anomalies, anomaly)
	r.AnomaliesDetected++

	switch anomaly.Severity {
	case "high":
		if !contains(r.HighRiskUsers, anomaly.User) {
			r.HighRiskUsers = append(r.HighRiskUsers, anomaly.User)
		}
	case "medium":
		if !contains(r.MediumRiskUsers, anomaly.User) {
			r.MediumRiskUsers = append(r.MediumRiskUsers, anomaly.User)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (r *AnomalyResult) ToAlert() *types.Alert {
	return &types.Alert{
		RuleName:    string(r.Type),
		Severity:    types.Severity(r.Severity),
		Message:     r.Description,
		EventIDs:    make([]int32, 0),
		FirstSeen:   r.StartTime,
		LastSeen:    r.EndTime,
		Count:       1,
		MITREAttack: []string{},
		Resolved:    false,
		Notes:       formatAnomalyDetails(r.Details),
		RuleScore:   r.Score,
	}
}

func formatAnomalyDetails(details map[string]interface{}) string {
	if details == nil {
		return ""
	}
	result := ""
	for k, v := range details {
		result += k + ": " + formatValue(v) + "\n"
	}
	return result
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case []int:
		return fmtIntSlice(val)
	default:
		return ""
	}
}

func fmtIntSlice(s []int) string {
	result := "["
	for i, v := range s {
		if i > 0 {
			result += ", "
		}
		result += strconv.Itoa(v)
	}
	result += "]"
	return result
}
