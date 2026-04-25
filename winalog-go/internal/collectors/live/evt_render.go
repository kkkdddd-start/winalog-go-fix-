//go:build windows

package live

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func ParseEventXML(xmlContent string) *types.Event {
	event := &types.Event{
		Level:      types.EventLevelInfo,
		ImportTime: time.Now(),
		RawXML:     &xmlContent,
	}

	lines := strings.Split(xmlContent, "<")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "?xml") {
			continue
		}

		if strings.HasPrefix(line, "Event>") {
			line = strings.TrimPrefix(line, "Event>")
		}

		if strings.HasPrefix(line, "Provider ") {
			if idx := strings.Index(line, "Name="); idx != -1 {
				val := extractQuotedValue(line[idx+5:])
				if val != "" {
					event.Source = val
				}
			}
		}

		if strings.HasPrefix(line, "System>") {
			continue
		}

		if strings.HasPrefix(line, "EventID>") {
			val := strings.TrimSuffix(strings.TrimPrefix(line, "EventID>"), "</EventID")
			val = strings.TrimSpace(val)
			if id := parseEventID(val); id != 0 {
				event.EventID = id
			}
		}

		if strings.HasPrefix(line, "Level>") {
			val := strings.TrimSuffix(strings.TrimPrefix(line, "Level>"), "</Level")
			val = strings.TrimSpace(val)
			if val != "" {
				event.Level = parseLevel(val)
			}
		}

		if strings.HasPrefix(line, "Channel>") {
			val := strings.TrimSuffix(strings.TrimPrefix(line, "Channel>"), "</Channel")
			val = strings.TrimSpace(val)
			if val != "" {
				event.LogName = val
			}
		}

		if strings.HasPrefix(line, "Computer>") {
			val := strings.TrimSuffix(strings.TrimPrefix(line, "Computer>"), "</Computer")
			val = strings.TrimSpace(val)
			if val != "" {
				event.Computer = val
			}
		}

		if strings.HasPrefix(line, "TimeCreated ") {
			if idx := strings.Index(line, "SystemTime="); idx != -1 {
				val := extractQuotedValue(line[idx+11:])
				if val != "" {
					if t, err := parseEventTime(val); err == nil {
						event.Timestamp = t
					}
				}
			}
		}

		if strings.HasPrefix(line, "Data ") {
			if idx := strings.Index(line, "Name="); idx != -1 {
				name := extractQuotedValue(line[idx+5:])
				val := extractDataValue(line)
				event.Message = buildMessage(event.Message, name, val)
			}
		} else if strings.HasPrefix(line, "Data>") {
			val := strings.TrimPrefix(line, "Data>")
			val = strings.TrimSuffix(val, "</Data")
			val = strings.TrimSpace(val)
			event.Message = buildMessage(event.Message, "", val)
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	return event
}

func extractQuotedValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return ""
	}
	quote := s[0]
	if quote != '"' && quote != '\'' {
		if idx := strings.IndexAny(s, " \"'<>"); idx != -1 {
			s = s[:idx]
		}
		return strings.TrimSpace(s)
	}
	s = s[1:]
	if idx := strings.Index(string(s), string(quote)); idx != -1 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

func extractDataValue(line string) string {
	if idx := strings.Index(line, ">"); idx != -1 {
		val := strings.TrimPrefix(line[idx:], ">")
		val = strings.TrimSuffix(val, "</Data")
		return strings.TrimSpace(val)
	}
	return ""
}

func parseEventID(s string) int32 {
	var id int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			id = id*10 + int64(c-'0')
		}
	}
	return int32(id)
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

func getElementText(decoder *xml.Decoder, start xml.StartElement) string {
	var text string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.CharData:
			text = string(t)
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				break
			}
		}
		if text != "" {
			break
		}
	}
	return strings.TrimSpace(text)
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

func parseUint(s string, result interface{}) (int, error) {
	var val uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			continue
		}
		val = val*10 + uint64(c-'0')
	}

	switch r := result.(type) {
	case *uint8:
		*r = uint8(val)
	case *uint16:
		*r = uint16(val)
	case *uint32:
		*r = uint32(val)
	case *uint64:
		*r = val
	}
	return 0, nil
}

func buildMessage(existing, name, value string) string {
	if name != "" && value != "" {
		return existing + name + "=" + value + "; "
	}
	if value != "" {
		return existing + value + "; "
	}
	return existing
}
