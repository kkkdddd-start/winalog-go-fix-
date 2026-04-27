package reports

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/reports/template"
	"github.com/kkkdddd-start/winalog-go/internal/version"
)

type HTMLReport struct {
	*Report
}

type ReportTranslations struct {
	Language string
	Strings  map[string]string
}

func NewHTMLReport(report *Report) *HTMLReport {
	return &HTMLReport{Report: report}
}

func (r *HTMLReport) getTranslations() ReportTranslations {
	lang := r.Report.Language
	if lang == "" {
		lang = "en"
	}

	en := map[string]string{
		"navbar_title":              "WinLogAnalyzer Security Report",
		"generated":                "Generated",
		"total_events":             "Total Events",
		"total_alerts":             "Total Alerts",
		"critical_events":          "Critical Events",
		"high_alerts":              "High Alerts",
		"analysis_period":          "Analysis Period",
		"to":                      "to",
		"days":                    "days",
		"system_info":              "System Information",
		"hostname":                 "Hostname",
		"domain":                  "Domain",
		"os":                      "OS",
		"architecture":             "Architecture",
		"cpu_cores":               "CPU Cores",
		"admin":                   "Admin",
		"yes":                     "Yes",
		"no":                      "No",
		"memory_total":             "Memory Total",
		"memory_free":             "Memory Free",
		"timezone":                "Timezone",
		"local_time":              "Local Time",
		"uptime":                  "Uptime",
		"seconds":                  "seconds",
		"top_processes":            "Top Processes",
		"pid":                     "PID",
		"name":                    "Name",
		"user":                    "User",
		"signed":                  "Signed",
		"network_connections":      "Network Connections",
		"protocol":                "Protocol",
		"local_address":            "Local Address",
		"remote_address":           "Remote Address",
		"state":                   "State",
		"process":                 "Process",
		"persistence_detections":   "Persistence Detections",
		"total_detections":         "Total Detections",
		"by_category":             "By Category",
		"category":                "Category",
		"count":                   "Count",
		"by_technique":            "By Technique",
		"technique":               "Technique",
		"detection_details":       "Detection Details",
		"time":                    "Time",
		"severity":                "Severity",
		"title":                   "Title",
		"description":             "Description",
		"events_by_level":          "Events by Level",
		"events_by_log_name":       "Events by Log Name",
		"top_event_ids":           "Top Event IDs",
		"event_id":                "Event ID",
		"percentage":              "Percentage",
		"login_statistics":         "Login Statistics",
		"successful_logins":        "Successful Logins",
		"failed_logins":           "Failed Logins",
		"total_login_events":       "Total Login Events",
		"top_alerts":              "Top Alerts",
		"rule":                    "Rule",
		"message":                 "Message",
		"last_seen":               "Last Seen",
		"ip_addresses":            "IP Addresses",
		"users":                   "Users",
		"computers":               "Computers",
		"mitre_by_tactic":         "MITRE ATT&CK by Tactic",
		"tactic":                  "Tactic",
		"mitre_by_technique":      "MITRE ATT&CK by Technique",
		"executive_summary":        "Executive Summary",
		"risk_score":              "Risk Score",
		"risk_level":              "Risk Level",
		"resolved":                 "Resolved",
		"unresolved":              "Unresolved",
		"top_threat":              "Top Threat",
		"key_findings":            "Key Findings",
		"peak_activity":            "Peak Activity",
		"peak_hour":               "Peak Hour",
		"peak_day":                "Peak Day",
		"activity_distribution":    "Activity Distribution",
		"events_by_hour":          "Events by Hour",
		"events_by_day":           "Events by Day",
		"alerts_by_hour":          "Alerts by Hour",
		"alerts_by_day":           "Alerts by Day",
		"threat_landscape":         "Threat Landscape",
		"critical":                "Critical",
		"high":                    "High",
		"medium":                  "Medium",
		"low":                     "Low",
		"top_attack_vectors":       "Top Attack Vectors",
		"vector":                  "Vector",
		"affected_systems":         "Affected Systems",
		"attack_patterns":          "Attack Patterns (MITRE ATT&CK)",
		"indicators":              "Indicators",
		"recommendations":         "Recommendations",
		"priority":                "Priority",
		"actionable_steps":         "Actionable Steps",
		"compliance_status":        "Compliance Status",
		"passed_checks":           "Passed Checks",
		"failed_checks":           "Failed Checks",
		"warnings":               "Warnings",
		"event_timeline":          "Event Timeline",
		"timestamp":               "Timestamp",
		"type":                    "Type",
		"source":                  "Source",
		"footer":                  "WinLogAnalyzer v%s | Windows Security Log Analysis Report",
		"rule_explanation":        "Rule Explanation",
		"recommendation":          "Recommendation",
		"real_case":               "Real Case",
		"original_description":     "Original Description",
	}

	zh := map[string]string{
		"navbar_title":              "WinLogAnalyzer 安全报告",
		"generated":                "生成时间",
		"total_events":             "事件总数",
		"total_alerts":             "告警总数",
		"critical_events":          "严重事件",
		"high_alerts":              "高危告警",
		"analysis_period":          "分析时间段",
		"to":                      "至",
		"days":                    "天",
		"system_info":              "系统信息",
		"hostname":                 "主机名",
		"domain":                  "域",
		"os":                      "操作系统",
		"architecture":             "架构",
		"cpu_cores":               "CPU 核心数",
		"admin":                   "管理员",
		"yes":                     "是",
		"no":                      "否",
		"memory_total":             "总内存",
		"memory_free":             "可用内存",
		"timezone":                "时区",
		"local_time":              "本地时间",
		"uptime":                  "运行时间",
		"seconds":                  "秒",
		"top_processes":            "顶级进程",
		"pid":                     "进程 ID",
		"name":                    "名称",
		"user":                    "用户",
		"signed":                  "签名",
		"network_connections":      "网络连接",
		"protocol":                "协议",
		"local_address":            "本地地址",
		"remote_address":           "远程地址",
		"state":                   "状态",
		"process":                 "进程",
		"persistence_detections":   "持久化检测",
		"total_detections":         "检测总数",
		"by_category":             "按类别",
		"category":                "类别",
		"count":                   "数量",
		"by_technique":            "按技术",
		"technique":               "技术",
		"detection_details":       "检测详情",
		"time":                    "时间",
		"severity":                "严重程度",
		"title":                   "标题",
		"description":             "描述",
		"events_by_level":          "按级别显示事件",
		"events_by_log_name":       "按日志名称显示事件",
		"top_event_ids":           "热门事件 ID",
		"event_id":                "事件 ID",
		"percentage":              "百分比",
		"login_statistics":         "登录统计",
		"successful_logins":        "成功登录",
		"failed_logins":           "失败登录",
		"total_login_events":       "登录事件总数",
		"top_alerts":              "热门告警",
		"rule":                    "规则",
		"message":                 "消息",
		"last_seen":               "最后出现",
		"ip_addresses":            "IP 地址",
		"users":                   "用户",
		"computers":               "计算机",
		"mitre_by_tactic":         "MITRE ATT&CK 战术分布",
		"tactic":                  "战术",
		"mitre_by_technique":      "MITRE ATT&CK 技术分布",
		"executive_summary":        "执行摘要",
		"risk_score":              "风险评分",
		"risk_level":              "风险等级",
		"resolved":                 "已解决",
		"unresolved":              "未解决",
		"top_threat":              "主要威胁",
		"key_findings":            "关键发现",
		"peak_activity":            "峰值活动",
		"peak_hour":               "峰值小时",
		"peak_day":                "峰值日期",
		"activity_distribution":    "活动分布",
		"events_by_hour":          "每小时事件",
		"events_by_day":           "每日事件",
		"alerts_by_hour":          "每小时告警",
		"alerts_by_day":           "每日告警",
		"threat_landscape":         "威胁态势",
		"critical":                "严重",
		"high":                    "高",
		"medium":                  "中",
		"low":                     "低",
		"top_attack_vectors":       "主要攻击向量",
		"vector":                  "向量",
		"affected_systems":         "受影响系统",
		"attack_patterns":          "攻击模式 (MITRE ATT&CK)",
		"indicators":              "指标",
		"recommendations":         "建议",
		"priority":                "优先级",
		"actionable_steps":         "可操作步骤",
		"compliance_status":        "合规状态",
		"passed_checks":           "通过检查",
		"failed_checks":           "失败检查",
		"warnings":               "警告",
		"event_timeline":          "事件时间线",
		"timestamp":               "时间戳",
		"type":                    "类型",
		"source":                  "来源",
		"footer":                  "WinLogAnalyzer v%s | Windows 安全日志分析报告",
		"rule_explanation":        "规则解读",
		"recommendation":          "处置建议",
		"real_case":               "真实案例",
		"original_description":     "原始描述",
	}

	translations := en
	if lang == "zh" {
		translations = zh
	}

	return ReportTranslations{
		Language: lang,
		Strings:  translations,
	}
}

func (t ReportTranslations) T(key string) string {
	if val, ok := t.Strings[key]; ok {
		return val
	}
	return key
}

func (r *HTMLReport) Write(w io.Writer) error {
	tmpl, err := template.GetReportTemplate()
	if err != nil {
		return fmt.Errorf("failed to load template: %w", err)
	}

	trans := r.getTranslations()

	data := struct {
		*Report
		GeneratedAtStr string
		StartTimeStr   string
		EndTimeStr     string
		Version        string
		T              ReportTranslations
	}{
		Report:         r.Report,
		GeneratedAtStr: r.Report.GeneratedAt.Format(time.RFC1123),
		StartTimeStr:   r.Report.TimeRange.Start.Format(time.RFC1123),
		EndTimeStr:     r.Report.TimeRange.End.Format(time.RFC1123),
		Version:        version.Version,
		T:              trans,
	}

	return tmpl.ExecuteTemplate(w, "report", data)
}

type HTMLExporter struct {
	generator *Generator
}

func NewHTMLExporter(generator *Generator) *HTMLExporter {
	return &HTMLExporter{generator: generator}
}

func (e *HTMLExporter) Export(req *ReportRequest, w io.Writer) error {
	report, err := e.generator.Generate(req)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	htmlReport := NewHTMLReport(report)
	return htmlReport.Write(w)
}

func (e *HTMLExporter) ExportToFile(req *ReportRequest, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	return e.Export(req, file)
}
