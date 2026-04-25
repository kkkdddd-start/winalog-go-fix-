package iis

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func init() {
	parsers.GetGlobalRegistry().Register(NewIISParser())
}

type IISParser struct {
	Format string
}

func NewIISParser() *IISParser {
	return &IISParser{
		Format: "w3c",
	}
}

func (p *IISParser) Priority() int {
	return 60
}

func (p *IISParser) CanParse(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := scanner.Text()
		if strings.HasPrefix(line, "#Software: Microsoft IIS") ||
			strings.HasPrefix(line, "#Fields:") {
			return true
		}
	}
	return false
}

func (p *IISParser) GetType() string {
	return "iis"
}

func (p *IISParser) Parse(path string) <-chan *types.Event {
	return p.ParseWithError(path).Events
}

func (p *IISParser) ParseWithError(path string) parsers.ParseResult {
	events := make(chan *types.Event, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errChan)

		iisEvents, err := p.parseIIS(path)
		if err != nil {
			errChan <- err
			return
		}

		for _, e := range iisEvents {
			events <- e
		}
	}()

	return parsers.ParseResult{Events: events, ErrCh: errChan}
}

func (p *IISParser) ParseBatch(path string) ([]*types.Event, error) {
	return p.parseIIS(path)
}

type IISLog struct {
	Date      time.Time
	Time      time.Time
	ClientIP  string
	UserName  string
	Method    string
	URIStem   string
	URIQuery  string
	Status    int
	BytesSent int64
	UserAgent string
	Referer   string
}

var (
	iisW3CHeaderRegex = regexp.MustCompile(`^#Fields:\s+(.+)$`)
	iisDateRegex      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
)

var KnownAttackPatterns = map[string]string{
	"/wp-login.php":  "WordPress Login Scan",
	"/admin":         "Admin Path Access",
	"/phpmyadmin":    "PHPMyAdmin Access",
	"/xmlrpc.php":    "XML-RPC Attack",
	"/.env":          "Environment File Access",
	"/config.php":    "Config File Access",
	"/web.config":    "Web Config Access",
	"/aspnet_client": "ASP.NET Client Access",
	"/cgi-bin":       "CGI Bin Access",
	"/console":       "Management Console Access",
	"/api/jsonws":    "JSON Web Service",
	"/muieblack":     "PHPMyAdmin Scanner",
	"union select":   "SQL Injection Attempt",
	"union+select":   "SQL Injection Attempt",
	"exec(":          "Command Injection Attempt",
	"eval(":          "Code Injection Attempt",
	"<script>":       "XSS Attempt",
	"../":            "Path Traversal Attempt",
	"..\\":           "Path Traversal Attempt",
}

func (p *IISParser) parseIIS(path string) ([]*types.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var columns []string
	events := make([]*types.Event, 0)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "#") {
			if matches := iisW3CHeaderRegex.FindStringSubmatch(line); len(matches) > 1 {
				columns = parseIISColumns(matches[1])
			}
			continue
		}

		if !iisDateRegex.MatchString(line) {
			continue
		}

		event := p.parseLogLine(line, columns)
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func parseIISColumns(header string) []string {
	return strings.Split(header, " ")
}

func (p *IISParser) parseLogLine(line string, columns []string) *types.Event {
	fields := parseIISFields(line)
	if len(fields) < 5 {
		return nil
	}

	event := &types.Event{
		Source:     "IIS",
		LogName:    "IIS",
		Level:      types.EventLevelInfo,
		ImportTime: time.Now(),
	}

	var dateStr, timeStr, clientIP, method, uriStem, uriQuery, userName, userAgent, host string
	var status, port int
	var bytesSent int64

	for i, col := range columns {
		if i >= len(fields) {
			break
		}
		value := fields[i]
		colLower := strings.ToLower(col)

		switch colLower {
		case "date":
			dateStr = value
		case "time":
			timeStr = value
		case "s-ip":
			event.Computer = value
		case "cs-method":
			method = value
		case "cs-uri-stem":
			uriStem = value
		case "cs-uri-query":
			uriQuery = value
		case "s-port":
			port, _ = strconv.Atoi(value)
		case "c-ip":
			clientIP = value
			ip := value
			event.IPAddress = &ip
		case "cs-username":
			userName = value
		case "cs(User-Agent)":
			userAgent = strings.Trim(value, `"`)
		case "cs(Referer)":
			_ = value
		case "sc-status":
			status, _ = strconv.Atoi(value)
		case "sc-bytes":
			bytesSent, _ = strconv.ParseInt(value, 10, 64)
		case "cs-bytes":
			_ = value
		case "time-taken":
			_ = value
		case "cs-host":
			host = value
		case "cs(Cookie)":
			_ = value
		case "cs(Content-Type)":
			_ = value
		}
	}

	if dateStr != "" && timeStr != "" {
		dt, err := time.Parse("2006-01-02 15:04:05", dateStr+" "+timeStr)
		if err == nil {
			event.Timestamp = dt
		}
	}

	event.Message = buildIISMessage(method, uriStem, uriQuery, port, status, clientIP, userAgent, bytesSent, host)

	if status >= 400 {
		if status >= 500 {
			event.Level = types.EventLevelError
		} else {
			event.Level = types.EventLevelWarning
		}
	}

	if attackDesc := detectIISAttack(uriStem, uriQuery, userAgent); attackDesc != "" {
		event.Level = types.EventLevelWarning
		event.Message += " [POTENTIAL ATTACK: " + attackDesc + "]"
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if event.User == nil && userName != "" && userName != "-" {
		event.User = &userName
	}

	return event
}

func parseIISFields(line string) []string {
	fields := make([]string, 0)
	var inQuote bool
	var current strings.Builder

	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ' ' && !inQuote {
			fields = append(fields, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func buildIISMessage(method, uriStem, uriQuery string, port, status int, clientIP, userAgent string, bytesSent int64, host string) string {
	msg := method + " " + uriStem
	if uriQuery != "-" && uriQuery != "" {
		msg += "?" + uriQuery
	}
	if host != "" {
		msg = host + msg
	}
	msg += fmt.Sprintf(" (Port: %d) - Status: %d", port, status)
	if clientIP != "" && clientIP != "-" {
		msg += " - Client: " + clientIP
	}
	if userAgent != "" && userAgent != "-" {
		msg += " - UA: " + userAgent
	}
	if bytesSent > 0 {
		msg += fmt.Sprintf(" [Bytes: %d]", bytesSent)
	}
	return msg
}

func detectIISAttack(uriStem, uriQuery, userAgent string) string {
	combined := strings.ToLower(uriStem + " " + uriQuery + " " + userAgent)
	for pattern, desc := range KnownAttackPatterns {
		if strings.Contains(combined, strings.ToLower(pattern)) {
			return desc
		}
	}
	return ""
}
