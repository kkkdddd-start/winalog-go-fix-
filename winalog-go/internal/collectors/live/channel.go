package live

import (
	"fmt"
	"strings"
)

type ChannelConfig struct {
	Name        string
	Description string
	EventIDs    string
	Enabled     bool
}

func DefaultChannels() []ChannelConfig {
	return []ChannelConfig{
		{
			Name:        "Security",
			Description: "安全日志",
			EventIDs:    "4624,4625,4672,4688,4698",
			Enabled:     true,
		},
		{
			Name:        "System",
			Description: "系统日志",
			EventIDs:    "6005,6006,7045",
			Enabled:     false,
		},
		{
			Name:        "Application",
			Description: "应用程序",
			EventIDs:    "1000,1001",
			Enabled:     false,
		},
		{
			Name:        "Microsoft-Windows-PowerShell/Operational",
			Description: "PowerShell",
			EventIDs:    "4103,4104",
			Enabled:     false,
		},
		{
			Name:        "Microsoft-Windows-Sysmon/Operational",
			Description: "Sysmon",
			EventIDs:    "1,3,6,7,8,11",
			Enabled:     false,
		},
		{
			Name:        "Microsoft-Windows-Windows Defender/Operational",
			Description: "Windows Defender",
			EventIDs:    "1001,1002",
			Enabled:     false,
		},
	}
}

func BuildEventQuery(channelName string, eventIDs string) string {
	if eventIDs == "" {
		return "*"
	}

	ids := strings.Split(eventIDs, ",")
	var conditions []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			conditions = append(conditions, fmt.Sprintf("EventID=%s", id))
		}
	}

	if len(conditions) == 0 {
		return ""
	}

	return fmt.Sprintf("*[System[%s]]", strings.Join(conditions, " or "))
}
