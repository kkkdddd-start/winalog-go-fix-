package template

import (
	"embed"
	"html/template"
	"strings"
)

//go:embed *
var templateFS embed.FS

var cachedTemplate *template.Template

var i18nMap = map[string]map[string]string{
	"en": {
		"Security Report":    "Security Report",
		"Generated":          "Generated",
		"Analysis Period":    "Analysis Period",
		"to":                 "to",
		"days":               "days",
		"Total Events":       "Total Events",
		"Total Alerts":       "Total Alerts",
		"Critical Events":    "Critical Events",
		"High Alerts":        "High Alerts",
		"System Information": "System Information",
		"Hostname":           "Hostname",
		"Domain":             "Domain",
		"OS":                 "OS",
		"Architecture":       "Architecture",
		"CPU Cores":          "CPU Cores",
		"Admin":              "Admin",
		"Yes":                "Yes",
		"No":                 "No",
		"Memory Total":       "Memory Total",
		"Memory Free":        "Memory Free",
		"Timezone":           "Timezone",
		"Local Time":         "Local Time",
		"Uptime":             "Uptime",
		"seconds":            "seconds",
		"Top Processes":      "Top Processes",
		"PID":                "PID",
		"Name":               "Name",
		"User":               "User",
		"Signed":             "Signed",
	},
	"zh": {
		"Security Report":    "安全报告",
		"Generated":          "生成时间",
		"Analysis Period":    "分析时间段",
		"to":                 "至",
		"days":               "天",
		"Total Events":       "事件总数",
		"Total Alerts":       "告警总数",
		"Critical Events":    "严重事件",
		"High Alerts":        "高危告警",
		"System Information": "系统信息",
		"Hostname":           "主机名",
		"Domain":             "域",
		"OS":                 "操作系统",
		"Architecture":       "架构",
		"CPU Cores":          "CPU 核心数",
		"Admin":              "管理员",
		"Yes":                "是",
		"No":                 "否",
		"Memory Total":       "总内存",
		"Memory Free":        "可用内存",
		"Timezone":           "时区",
		"Local Time":         "本地时间",
		"Uptime":             "运行时间",
		"seconds":            "秒",
		"Top Processes":      "进程 TOP",
		"PID":                "进程ID",
		"Name":               "名称",
		"User":               "用户",
		"Signed":             "签名",
	},
}

func GetReportTemplate() (*template.Template, error) {
	if cachedTemplate != nil {
		return cachedTemplate, nil
	}

	funcMap := template.FuncMap{
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"percentage": func(part, total int64) float64 {
			if total == 0 {
				return 0
			}
			return float64(part) / float64(total) * 100
		},
		"toLower": func(s string) string {
			return strings.ToLower(s)
		},
		"i18n": func(key string) string {
			return key
		},
	}

	tmpl, err := template.New("report.html").Funcs(funcMap).ParseFS(templateFS, "report.html")
	if err != nil {
		return nil, err
	}

	cachedTemplate = tmpl
	return cachedTemplate, nil
}

func MustGetReportTemplate() *template.Template {
	tmpl, err := GetReportTemplate()
	if err != nil {
		panic("failed to load report template: " + err.Error())
	}
	return tmpl
}
