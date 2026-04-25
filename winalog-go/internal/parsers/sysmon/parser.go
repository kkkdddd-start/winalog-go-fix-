package sysmon

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func init() {
	parsers.GetGlobalRegistry().Register(NewSysmonParser())
}

type SysmonParser struct{}

func NewSysmonParser() *SysmonParser {
	return &SysmonParser{}
}

func (p *SysmonParser) Priority() int {
	return 70
}

func (p *SysmonParser) CanParse(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.Contains(name, "sysmon") || strings.Contains(name, "microsoft-windows-sysmon")
}

func (p *SysmonParser) GetType() string {
	return "sysmon"
}

func (p *SysmonParser) Parse(path string) <-chan *types.Event {
	return p.ParseWithError(path).Events
}

func (p *SysmonParser) ParseWithError(path string) parsers.ParseResult {
	events := make(chan *types.Event, 1000)
	errChan := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errChan)

		sysmonEvents, err := p.parseSysmon(path)
		if err != nil {
			errChan <- err
			return
		}

		for _, e := range sysmonEvents {
			events <- e
		}
	}()

	return parsers.ParseResult{
		Events: events,
		ErrCh:  errChan,
	}
}

func (p *SysmonParser) ParseBatch(path string) ([]*types.Event, error) {
	return p.parseSysmon(path)
}

type SysmonEvent struct {
	EventID             int
	Schema              string
	Image               string
	ImageLoaded         string
	CommandLine         string
	TargetFilename      string
	Hashes              map[string]string
	ParentImage         string
	ParentCommandLine   string
	UserName            string
	Computer            string
	TimeCreated         time.Time
	Signed              bool
	Signature           string
	SignatureStatus     string
	ProcessId           string
	SourceImage         string
	SourceProcessId     string
	TargetImage         string
	TargetProcessId     string
	GrantedAccess       string
	CallTrace           string
	Protocol            string
	SourcePort          int
	DestinationPort     int
	SourceHostname      string
	DestinationHostname string
	QueryName           string
	QueryResults        string
	QueryStatus         string
	PipeName            string
	RuleName            string
	EventType           string
}

func (p *SysmonParser) parseSysmon(path string) ([]*types.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	events := make([]*types.Event, 0)

	var wrapper struct {
		XMLName xml.Name `xml:"Event"`
		System  struct {
			XMLName  xml.Name `xml:"System"`
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			EventID     string `xml:"EventID"`
			TimeCreated string `xml:"TimeCreated"`
			Computer    string `xml:"Computer"`
		} `xml:"System"`
		EventData struct {
			XMLName xml.Name `xml:"EventData"`
			Data    []struct {
				Name  string `xml:"Name,attr"`
				Value string `xml:",chardata"`
			} `xml:"Data"`
		} `xml:"EventData"`
	}

	decoder := xml.NewDecoder(file)
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "Event" {
				wrapper = struct {
					XMLName xml.Name `xml:"Event"`
					System  struct {
						XMLName  xml.Name `xml:"System"`
						Provider struct {
							Name string `xml:"Name,attr"`
						} `xml:"Provider"`
						EventID     string `xml:"EventID"`
						TimeCreated string `xml:"TimeCreated"`
						Computer    string `xml:"Computer"`
					} `xml:"System"`
					EventData struct {
						XMLName xml.Name `xml:"EventData"`
						Data    []struct {
							Name  string `xml:"Name,attr"`
							Value string `xml:",chardata"`
						} `xml:"Data"`
					} `xml:"EventData"`
				}{}

				if err := decoder.DecodeElement(&wrapper, &elem); err != nil {
					continue
				}

				event := p.convertToEvent(wrapper)
				if event != nil {
					events = append(events, event)
				}
			}
		}
	}

	return events, nil
}

func (p *SysmonParser) convertToEvent(wrapper struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		XMLName  xml.Name `xml:"System"`
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		TimeCreated string `xml:"TimeCreated"`
		Computer    string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		XMLName xml.Name `xml:"EventData"`
		Data    []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}) *types.Event {
	event := &types.Event{
		Source:     "Sysmon",
		LogName:    "Microsoft-Windows-Sysmon/Operational",
		Computer:   wrapper.System.Computer,
		ImportTime: time.Now(),
	}

	if wrapper.System.Provider.Name != "" {
		event.Source = wrapper.System.Provider.Name
	}

	if t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", wrapper.System.TimeCreated); err == nil {
		event.Timestamp = t
	} else {
		event.Timestamp = time.Now()
	}

	var eventID int
	fmt.Sscanf(wrapper.System.EventID, "%d", &eventID)
	event.EventID = int32(eventID)

	event.Level = p.getLevelForEventID(eventID)

	dataMap := make(map[string]string)
	for _, d := range wrapper.EventData.Data {
		dataMap[d.Name] = d.Value
	}

	event.Message = p.buildMessage(eventID, dataMap)

	rawXML, _ := xml.Marshal(wrapper)
	xmlStr := string(rawXML)
	event.RawXML = &xmlStr

	return event
}

func (p *SysmonParser) getLevelForEventID(eventID int) types.EventLevel {
	switch eventID {
	case 1: // Process Create
		return types.EventLevelInfo
	case 2: // File Creation Time Changed
		return types.EventLevelWarning
	case 3: // Network Connection
		return types.EventLevelInfo
	case 5: // Process Terminated
		return types.EventLevelInfo
	case 7: // Image Loaded
		return types.EventLevelInfo
	case 8: // CreateRemoteThread
		return types.EventLevelWarning
	case 10: // Process Access
		return types.EventLevelWarning
	case 11: // File Created
		return types.EventLevelInfo
	case 12, 13, 14: // Registry Events
		return types.EventLevelInfo
	case 15: // File Stream Created
		return types.EventLevelWarning
	case 17, 18: // Pipe Events
		return types.EventLevelInfo
	case 19, 20, 21: // WMI Events
		return types.EventLevelWarning
	case 22: // DNS Query
		return types.EventLevelInfo
	case 23, 24, 25, 26: // File/Clipboard/Tampering
		return types.EventLevelWarning
	case 29: // Process Injection
		return types.EventLevelError
	default:
		return types.EventLevelInfo
	}
}

func (p *SysmonParser) buildMessage(eventID int, data map[string]string) string {
	switch eventID {
	case 1:
		return fmt.Sprintf("Process Create: %s %s (PID: %s)",
			data["Image"], data["CommandLine"], data["ProcessId"])
	case 2:
		return fmt.Sprintf("File Creation Time Changed: %s", data["TargetFilename"])
	case 3:
		return fmt.Sprintf("Network Connection: %s:%s -> %s:%s [%s]",
			data["SourceHostname"], data["SourcePort"], data["DestinationHostname"], data["DestinationPort"], data["Protocol"])
	case 4:
		return fmt.Sprintf("Sysmon Service State Changed: %s", data["State"])
	case 5:
		return fmt.Sprintf("Process Terminated: %s (PID: %s)", data["Image"], data["ProcessId"])
	case 6:
		return fmt.Sprintf("Driver Loaded: %s [Hash: %s] [Signed: %s]",
			data["ImageLoaded"], data["Hashes"], data["Signature"])
	case 7:
		return p.buildImageLoadedMessage(data)
	case 8:
		return p.buildCreateRemoteThreadMessage(data)
	case 9:
		return fmt.Sprintf("Raw Access Read: %s by %s", data["Image"], data["Device"])
	case 10:
		return p.buildProcessAccessMessage(data)
	case 11:
		return fmt.Sprintf("File Created: %s", data["TargetFilename"])
	case 12:
		return fmt.Sprintf("Registry Object Added/Deleted: %s", data["TargetObject"])
	case 13:
		return fmt.Sprintf("Registry Value Set: %s = %s", data["TargetObject"], data["Details"])
	case 14:
		return fmt.Sprintf("Registry Object Renamed: %s -> %s", data["OldTargetObject"], data["NewTargetObject"])
	case 15:
		return fmt.Sprintf("File Stream Created: %s in %s", data["TargetFilename"], data["RuleName"])
	case 16:
		return "Sysmon Service Configuration Changed"
	case 17:
		return fmt.Sprintf("Pipe Created: %s", data["PipeName"])
	case 18:
		return fmt.Sprintf("Pipe Connected: %s", data["PipeName"])
	case 19:
		return fmt.Sprintf("WMI Event Filter: %s", data["EventNamespace"])
	case 20:
		return fmt.Sprintf("WMI Consumer: %s", data["Consumer"])
	case 21:
		return fmt.Sprintf("WMI Consumer Filter Binding: %s -> %s", data["Filter"], data["Consumer"])
	case 22:
		return p.buildDNSQueryMessage(data)
	case 23:
		return fmt.Sprintf("File Delete: %s [Hash: %s]", data["TargetFilename"], data["Hashes"])
	case 24:
		return fmt.Sprintf("Clipboard Changed: %s -> %s", data["SourceImage"], data["DestinationImage"])
	case 25:
		return fmt.Sprintf("Process Tampering: %s [%s]", data["Image"], data["Type"])
	case 26:
		return fmt.Sprintf("File Delete Logged: %s [Hash: %s]", data["TargetFilename"], data["Hashes"])
	case 27:
		return fmt.Sprintf("File Block: %s", data["TargetFilename"])
	case 28:
		return fmt.Sprintf("File Block Executable: %s", data["TargetFilename"])
	case 29:
		return fmt.Sprintf("Process Injection: %s -> %s [%s]", data["SourceImage"], data["TargetImage"], data["Type"])
	case 30:
		return fmt.Sprintf("File Created with Alternate Data Stream: %s -> %s", data["TargetFilename"], data["AlternateDataStream"])
	case 31:
		return fmt.Sprintf("Sysmon Config Changed: %s", data["Name"])
	case 32:
		return fmt.Sprintf("Access Key: %s [%s]", data["TargetObject"], data["ProcessName"])
	case 33:
		return fmt.Sprintf("Registry Event: %s", data["TargetObject"])
	case 34:
		return fmt.Sprintf("Registry Event via ETW: %s", data["TargetObject"])
	case 35:
		return fmt.Sprintf("Sysmon Polling Detected: %s", data["TargetObject"])
	default:
		return fmt.Sprintf("Sysmon Event %d", eventID)
	}
}

func (p *SysmonParser) buildImageLoadedMessage(data map[string]string) string {
	imageLoaded := data["ImageLoaded"]
	signature := data["Signature"]
	signatureStatus := data["SignatureStatus"]
	hashes := data["Hashes"]

	msg := fmt.Sprintf("Image Loaded: %s", imageLoaded)

	if signature != "" {
		msg += fmt.Sprintf(" [Signature: %s]", signature)
	}

	if signatureStatus != "" {
		msg += fmt.Sprintf(" [%s]", signatureStatus)
	}

	if hashes != "" {
		msg += fmt.Sprintf(" [Hash: %s]", hashes)
	}

	if p.isSuspiciousImageLoadedPath(imageLoaded) {
		msg += " [SUSPICIOUS PATH]"
	}

	return msg
}

func (p *SysmonParser) buildProcessAccessMessage(data map[string]string) string {
	sourceImage := data["SourceImage"]
	targetImage := data["TargetImage"]
	grantedAccess := data["GrantedAccess"]
	callTrace := data["CallTrace"]

	msg := fmt.Sprintf("Process Access: %s -> %s", sourceImage, targetImage)

	if grantedAccess != "" {
		accessDesc := p.decodeGrantedAccess(grantedAccess)
		msg += fmt.Sprintf(" [Access: %s (%s)]", grantedAccess, accessDesc)
	}

	if callTrace != "" && p.isSuspiciousCallTrace(callTrace) {
		msg += " [SUSPICIOUS CALL TRACE]"
	}

	return msg
}

func (p *SysmonParser) buildCreateRemoteThreadMessage(data map[string]string) string {
	sourceImage := data["SourceImage"]
	targetImage := data["TargetImage"]
	targetProcessId := data["TargetProcessId"]
	startAddress := data["StartAddress"]

	msg := fmt.Sprintf("CreateRemoteThread: %s -> %s (PID: %s)", sourceImage, targetImage, targetProcessId)

	if startAddress != "" {
		msg += fmt.Sprintf(" [StartAddress: %s]", startAddress)
	}

	if p.isSuspiciousRemoteThread(targetImage, startAddress) {
		msg += " [SUSPICIOUS TARGET]"
	}

	return msg
}

func (p *SysmonParser) buildDNSQueryMessage(data map[string]string) string {
	queryName := data["QueryName"]
	queryResults := data["QueryResults"]
	queryStatus := data["QueryStatus"]

	msg := fmt.Sprintf("DNS Query: %s", queryName)

	if queryResults != "" {
		msg += fmt.Sprintf(" -> %s", queryResults)
	}

	if queryStatus != "" && queryStatus != "0" {
		msg += fmt.Sprintf(" [Status: %s]", queryStatus)
	}

	if p.isSuspiciousDNSQuery(queryName) {
		msg += " [SUSPICIOUS DOMAIN]"
	}

	return msg
}

func (p *SysmonParser) isSuspiciousImageLoadedPath(imagePath string) bool {
	suspiciousPatterns := []string{
		"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
		"\\Temp\\", "\\AppData\\",
		"\\\\", "http://", "https://",
		":\\Windows\\Temp\\",
		":\\Users\\",
		"\\Downloads\\",
	}

	upperPath := strings.ToUpper(imagePath)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(upperPath, strings.ToUpper(pattern)) {
			return true
		}
	}

	return false
}

func (p *SysmonParser) isSuspiciousCallTrace(callTrace string) bool {
	suspiciousPatterns := []string{
		"ntdll.dll",
		"LSASRV.dll",
		"msvcrt.dll",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToUpper(callTrace), pattern) {
			return true
		}
	}

	return false
}

func (p *SysmonParser) isSuspiciousRemoteThread(targetImage string, startAddress string) bool {
	upperTarget := strings.ToUpper(targetImage)

	if strings.Contains(upperTarget, "LSASS") && startAddress != "" {
		return true
	}

	return false
}

func (p *SysmonParser) isSuspiciousDNSQuery(queryName string) bool {
	suspiciousDomains := []string{
		".tk", ".ml", ".ga", ".cf", ".gq",
		"pastebin", "githubusercontent",
		"cobaltstrike", "metasploit",
	}

	upperQuery := strings.ToLower(queryName)
	for _, domain := range suspiciousDomains {
		if strings.Contains(upperQuery, domain) {
			return true
		}
	}

	return false
}

func (p *SysmonParser) decodeGrantedAccess(accessMask string) string {
	accessMap := map[string]string{
		"0x00000000": "None",
		"0x00000001": "DELETE",
		"0x00000002": "READ_CONTROL",
		"0x00000010": "WRITE_DAC",
		"0x00000020": "WRITE_OWNER",
		"0x00000040": "SYNCHRONIZE",
		"0x00010000": "PROCESS_ALL_ACCESS",
		"0x00020000": "STANDARD_RIGHTS_REQUIRED",
		"0x00040000": "STANDARD_RIGHTS_ALL",
		"0x00100000": "TOKEN_ASSIGN_PRIMARY",
		"0x00200000": "TOKEN_DUPLICATE",
		"0x00800000": "PROCESS_ALL_ACCESS",
	}

	if desc, ok := accessMap[accessMask]; ok {
		return desc
	}

	if strings.HasPrefix(accessMask, "0x1F0") {
		return "AllAccess"
	}
	if strings.HasPrefix(accessMask, "0x1F") {
		return "FullAccess"
	}

	return "Unknown"
}
