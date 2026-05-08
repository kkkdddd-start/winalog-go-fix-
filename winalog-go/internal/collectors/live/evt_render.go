//go:build windows

package live

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"go.uber.org/zap"
)

type FullEventXML struct {
	XMLName       xml.Name     `xml:"Event"`
	System        SystemXML    `xml:"System"`
	EventData     EventDataXML `xml:"EventData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

func ParseEventXML(xmlContent string) *types.Event {
	event := &types.Event{
		Level:      types.EventLevelInfo,
		ImportTime: time.Now(),
		RawXML:     &xmlContent,
	}

	var xmlData FullEventXML
	if err := xml.Unmarshal([]byte(xmlContent), &xmlData); err != nil {
		observability.Warn("XML parse error",
			zap.String("module", "evt_render"),
			zap.Error(err))
		return event
	}

	// System 字段映射
	event.EventID = int32(xmlData.System.EventID)
	event.WindowsRecordID = xmlData.System.EventRecordID
	event.Source = xmlData.System.Provider.Name
	event.LogName = xmlData.System.Channel
	event.Computer = xmlData.System.Computer

	if xmlData.System.Security.UserID != "" {
		event.User = &xmlData.System.Security.UserID
	}

	// 时间解析
	if xmlData.System.TimeCreated.SystemTime != "" {
		if t, err := parseEventTime(xmlData.System.TimeCreated.SystemTime); err == nil {
			event.Timestamp = t
		}
	}

	// 级别解析
	event.Level = parseLevel(fmt.Sprintf("%d", xmlData.System.Level))

	// Message 构建：优先 RenderingInfo.Message，回退 EventData 拼接
	if xmlData.RenderingInfo.Message != "" {
		event.Message = xmlData.RenderingInfo.Message
	} else {
		var msgParts []string
		for _, d := range xmlData.EventData.Data {
			if d.Name != "" && d.Value != "" {
				msgParts = append(msgParts, d.Name+"="+d.Value)
			} else if d.Value != "" {
				msgParts = append(msgParts, d.Value)
			}
		}
		event.Message = strings.Join(msgParts, "; ")
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	return event
}

func parseLevel(s string) types.EventLevel {
	var level int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			level = level*10 + int(c-'0')
		}
	}
	switch level {
	case 1:
		return types.EventLevelCritical
	case 2:
		return types.EventLevelError
	case 3:
		return types.EventLevelWarning
	case 4:
		return types.EventLevelInfo
	case 5:
		return types.EventLevelVerbose
	default:
		return types.EventLevelInfo
	}
}

type SystemXML struct {
	Provider      ProviderXML   `xml:"Provider"`
	EventID       uint64        `xml:"EventID"`
	Level         uint8         `xml:"Level"`
	Keywords      string        `xml:"Keywords"`
	TimeCreated   SystemTimeXML `xml:"TimeCreated"`
	EventRecordID uint64        `xml:"EventRecordID"`
	ProcessID     uint32        `xml:"Execution/ProcessID"`
	ThreadID      uint32        `xml:"Execution/ThreadID"`
	Channel       string        `xml:"Channel"`
	Computer      string        `xml:"Computer"`
	Security      UserIDXML     `xml:"Security"`
}

type ProviderXML struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type SystemTimeXML struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type UserIDXML struct {
	UserID string `xml:"UserID,attr"`
}

type EventDataXML struct {
	Data []EventDataItemXML `xml:"Data"`
}

type EventDataItemXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func parseEventTime(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05.999Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, nil
}
