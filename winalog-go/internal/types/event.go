package types

import (
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

type EventLevel string

const (
	EventLevelCritical EventLevel = "Critical"
	EventLevelError    EventLevel = "Error"
	EventLevelWarning  EventLevel = "Warning"
	EventLevelInfo     EventLevel = "Info"
	EventLevelVerbose  EventLevel = "Verbose"
)

func (l EventLevel) String() string {
	return string(l)
}

func (l EventLevel) IsValid() bool {
	switch l {
	case EventLevelCritical, EventLevelError, EventLevelWarning, EventLevelInfo, EventLevelVerbose:
		return true
	default:
		return false
	}
}

func EventLevelFromInt(level int) EventLevel {
	switch level {
	case 1:
		return EventLevelCritical
	case 2:
		return EventLevelError
	case 3:
		return EventLevelWarning
	case 4:
		return EventLevelInfo
	case 5:
		return EventLevelVerbose
	default:
		return EventLevelInfo
	}
}

type Event struct {
	ID              int64                  `json:"id" db:"id"`
	Timestamp       time.Time              `json:"timestamp" db:"timestamp"`
	EventID         int32                  `json:"event_id" db:"event_id"`
	Level           EventLevel             `json:"level" db:"level"`
	Source          string                 `json:"source" db:"source"`
	LogName         string                 `json:"log_name" db:"log_name"`
	Computer        string                 `json:"computer" db:"computer"`
	User            *string                `json:"user,omitempty" db:"user"`
	UserSID         *string                `json:"user_sid,omitempty" db:"user_sid"`
	Message         string                 `json:"message" db:"message"`
	RawXML          *string                `json:"raw_xml,omitempty" db:"raw_xml"`
	SessionID       *string                `json:"session_id,omitempty" db:"session_id"`
	IPAddress       *string                `json:"ip_address,omitempty" db:"ip_address"`
	ImportTime      time.Time              `json:"import_time" db:"import_time"`
	ImportID        int64                  `json:"import_id,omitempty" db:"import_id"`
	ExtractedFields map[string]interface{} `json:"extracted_fields,omitempty" db:"-"`
}

func (e *Event) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"timestamp":   e.Timestamp,
		"event_id":    e.EventID,
		"level":       e.Level,
		"source":      e.Source,
		"log_name":    e.LogName,
		"computer":    e.Computer,
		"message":     e.Message,
		"import_time": e.ImportTime,
	}
	if e.User != nil {
		m["user"] = *e.User
	}
	if e.UserSID != nil {
		m["user_sid"] = *e.UserSID
	}
	if e.RawXML != nil {
		m["raw_xml"] = *e.RawXML
	}
	if e.SessionID != nil {
		m["session_id"] = *e.SessionID
	}
	if e.IPAddress != nil {
		m["ip_address"] = *e.IPAddress
	}
	if e.ImportID > 0 {
		m["import_id"] = e.ImportID
	}
	if e.ExtractedFields != nil {
		for k, v := range e.ExtractedFields {
			m[k] = v
		}
	}
	return m
}

func (e *Event) ToSlice() []interface{} {
	return []interface{}{
		e.ID,
		e.Timestamp,
		e.EventID,
		e.Level,
		e.Source,
		e.LogName,
		e.Computer,
		e.User,
		e.UserSID,
		e.Message,
		e.RawXML,
		e.SessionID,
		e.IPAddress,
		e.ImportTime,
		e.ImportID,
	}
}

var EventColumns = []string{
	"id",
	"timestamp",
	"event_id",
	"level",
	"source",
	"log_name",
	"computer",
	"user",
	"user_sid",
	"message",
	"raw_xml",
	"session_id",
	"ip_address",
	"import_time",
	"import_id",
}

func ScanEvent(row interface{ Scan(...interface{}) error }) (*Event, error) {
	var e Event
	var user, userSID, rawXML, sessionID, ipAddress sql.NullString
	var importID sql.NullInt64
	var timestampStr, importTimeStr string

	err := row.Scan(
		&e.ID,
		&timestampStr,
		&e.EventID,
		&e.Level,
		&e.Source,
		&e.LogName,
		&e.Computer,
		&user,
		&userSID,
		&e.Message,
		&rawXML,
		&sessionID,
		&ipAddress,
		&importTimeStr,
		&importID,
	)
	if err != nil {
		return nil, err
	}

	if timestampStr != "" {
		if ts, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			e.Timestamp = ts
		}
	}

	if importTimeStr != "" {
		if it, err := time.Parse(time.RFC3339, importTimeStr); err == nil {
			e.ImportTime = it
		}
	}

	if user.Valid {
		e.User = &user.String
	}
	if userSID.Valid {
		e.UserSID = &userSID.String
	}
	if rawXML.Valid {
		e.RawXML = &rawXML.String
	}
	if sessionID.Valid {
		e.SessionID = &sessionID.String
	}
	if ipAddress.Valid {
		e.IPAddress = &ipAddress.String
	}
	if importID.Valid {
		e.ImportID = importID.Int64
	}

	return &e, nil
}

type EventIDCount struct {
	EventID int32 `json:"event_id" db:"event_id"`
	Count   int64 `json:"count" db:"count"`
}

type LevelDistribution struct {
	Level EventLevel `json:"level" db:"level"`
	Count int64      `json:"count" db:"count"`
}

type LogNameDistribution struct {
	LogName string `json:"log_name" db:"log_name"`
	Count   int64  `json:"count" db:"count"`
}

func (e *Event) SetExtractedField(key string, value interface{}) {
	if e.ExtractedFields == nil {
		e.ExtractedFields = make(map[string]interface{})
	}
	e.ExtractedFields[key] = value
}

func (e *Event) GetExtractedField(key string) interface{} {
	if e.ExtractedFields == nil {
		return nil
	}
	return e.ExtractedFields[key]
}

func (e *Event) GetLogonType() int {
	if v := e.GetExtractedField("LogonType"); v != nil {
		if f, ok := v.(float64); ok {
			return int(f)
		}
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

func (e *Event) GetTargetUserName() string {
	if v := e.GetExtractedField("TargetUserName"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if e.User != nil {
		return *e.User
	}
	return ""
}

func (e *Event) GetSubjectUserName() string {
	if v := e.GetExtractedField("SubjectUserName"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Event) GetProcessId() string {
	if v := e.GetExtractedField("ProcessId"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Event) GetProcessName() string {
	if v := e.GetExtractedField("ProcessName"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Event) GetCommandLine() string {
	if v := e.GetExtractedField("CommandLine"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Event) GetServiceName() string {
	if v := e.GetExtractedField("ServiceName"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Event) GetDestPort() int {
	if v := e.GetExtractedField("DestPort"); v != nil {
		if f, ok := v.(float64); ok {
			return int(f)
		}
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

func (e *Event) ParseRawXML() error {
	if e.RawXML == nil || *e.RawXML == "" {
		return nil
	}

	decoder := xml.NewDecoder(strings.NewReader(*e.RawXML))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			var data string
			if err := decoder.DecodeElement(&data, &elem); err == nil {
				e.SetExtractedField(elem.Name.Local, data)
			}
		}
	}
	return nil
}

func (e *Event) ExtractKeyFields() map[string]string {
	fields := make(map[string]string)

	keyGetters := []struct {
		key    string
		getter func() string
	}{
		{"TargetUserName", e.GetTargetUserName},
		{"SubjectUserName", e.GetSubjectUserName},
		{"LogonType", func() string { return fmt.Sprintf("%d", e.GetLogonType()) }},
		{"ProcessName", e.GetProcessName},
		{"ProcessId", e.GetProcessId},
		{"CommandLine", e.GetCommandLine},
		{"ServiceName", e.GetServiceName},
		{"DestPort", func() string { return fmt.Sprintf("%d", e.GetDestPort()) }},
	}

	for _, kg := range keyGetters {
		if v := kg.getter(); v != "" {
			fields[kg.key] = v
		}
	}

	return fields
}

func IsExternalIP(ip string) bool {
	if ip == "" || ip == "-" || ip == "127.0.0.1" || ip == "::1" || ip == "::" {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true
	}
	firstOctet := 0
	for _, c := range parts[0] {
		if c >= '0' && c <= '9' {
			firstOctet = firstOctet*10 + int(c-'0')
		}
	}
	if firstOctet == 10 {
		return false
	}
	if firstOctet == 192 && parts[1] == "168" {
		return false
	}
	if firstOctet == 172 {
		secondOctet := 0
		for _, c := range parts[1] {
			if c >= '0' && c <= '9' {
				secondOctet = secondOctet*10 + int(c-'0')
			}
		}
		if secondOctet >= 16 && secondOctet <= 31 {
			return false
		}
	}
	return true
}
