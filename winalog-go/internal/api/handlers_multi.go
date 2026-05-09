package api

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

const lateralMovementWindow = 30 * time.Minute

type LoginEvent struct {
	Computer   string
	User       string
	EventID    int64
	Timestamp  string
	IPAddress  string
	ParsedTime time.Time
}

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
	SourceIPs      []string `json:"source_ips"`
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

type LateralMovementChain struct {
	User        string           `json:"user"`
	Steps       []MovementStep   `json:"steps"`
	Duration    string           `json:"duration"`
	MachineCount int             `json:"machine_count"`
	Severity    string           `json:"severity"`
	Description string           `json:"description"`
	MITREAttack []string         `json:"mitre_attack"`
}

type MovementStep struct {
	Timestamp   string `json:"timestamp"`
	Machine     string `json:"machine"`
	EventID     int    `json:"event_id"`
	IPAddress   string `json:"ip_address"`
	Description string `json:"description"`
}

type MultiAnalyzeResponse struct {
	Machines             []MachineInfo          `json:"machines"`
	CrossMachine         []CrossMachineActivity `json:"cross_machine_activity"`
	LateralMovement      []LateralMovement      `json:"lateral_movement"`
	LateralMovementChains []LateralMovementChain `json:"lateral_movement_chains"`
	Summary              string                 `json:"summary"`
	SuspiciousCount      int                    `json:"suspicious_count"`
	AnalysisID           string                 `json:"analysis_id"`
}

type MultiAnalyzeRequest struct {
	Hours     int    `json:"hours"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Limit     int    `json:"limit"`
}

func NewMultiHandler(db *storage.DB) *MultiHandler {
	return &MultiHandler{db: db}
}

func (h *MultiHandler) Analyze(c *gin.Context) {
	var req MultiAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if c.Request.ContentLength > 0 {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("invalid request body: %v", err)})
			return
		}
		req = MultiAnalyzeRequest{Hours: 24, Limit: 5000}
	}

	hours := req.Hours
	if hours <= 0 {
		hours = 24
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 5000
	}

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	if req.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, req.StartTime); err == nil {
			startTime = t
		}
	}
	if req.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, req.EndTime); err == nil {
			endTime = t
		}
	}

	machines, err := h.getMachineContexts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	crossMachine, err := h.analyzeCrossMachineActivity(startTime, endTime, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	lateralEvents, lateralChains, err := h.detectLateralMovement(startTime, endTime, limit)
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
	suspiciousCount += len(lateralChains)

	analysisID := generateAnalysisID()

	c.JSON(http.StatusOK, MultiAnalyzeResponse{
		Machines:              machines,
		CrossMachine:          crossMachine,
		LateralMovement:       lateralEvents,
		LateralMovementChains: lateralChains,
		Summary:               generateMultiSummary(len(machines), suspiciousCount, len(lateralChains)),
		SuspiciousCount:       suspiciousCount,
		AnalysisID:            analysisID,
	})
}

func (h *MultiHandler) Lateral(c *gin.Context) {
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)
	lateralEvents, lateralChains, err := h.detectLateralMovement(startTime, endTime, 1000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"lateral_movement":        lateralEvents,
		"lateral_movement_chains": lateralChains,
		"chain_count":             len(lateralChains),
		"event_count":             len(lateralEvents),
	})
}

func (h *MultiHandler) GetInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "multi",
		"status":  "operational",
		"endpoints": []string{
			"POST /api/multi/analyze",
			"GET /api/multi/lateral",
			"POST /api/multi/export",
		},
	})
}

func (h *MultiHandler) Export(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	hoursStr := c.DefaultQuery("hours", "24")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("invalid hours parameter: %s", hoursStr)})
		return
	}
	if hours <= 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "hours must be a positive integer"})
		return
	}
	deep := c.DefaultQuery("deep", "false") == "true"

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	machines, err := h.getMachineContexts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	crossMachine, err := h.analyzeCrossMachineActivity(startTime, endTime, 5000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	lateralEvents, lateralChains, err := h.detectLateralMovement(startTime, endTime, 5000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	if format == "json" {
		h.exportJSON(c, machines, crossMachine, lateralEvents, lateralChains, deep)
	} else {
		h.exportCSV(c, machines, crossMachine, lateralEvents, lateralChains, deep)
	}
}

func (h *MultiHandler) exportJSON(c *gin.Context, machines []MachineInfo, crossMachine []CrossMachineActivity, lateral []LateralMovement, lateralChains []LateralMovementChain, deep bool) {
	response := gin.H{
		"machines":              machines,
		"cross_machine":         crossMachine,
		"lateral_movement":      lateral,
		"lateral_movement_chains": lateralChains,
		"export_time":           time.Now().Format(time.RFC3339),
	}

	if deep {
		evidence := make(map[string][]interface{})
		for _, chain := range lateralChains {
			key := fmt.Sprintf("chain_%s_%s", chain.User, chain.Description)
			stepData := make([]interface{}, 0, len(chain.Steps))
			for _, step := range chain.Steps {
				stepData = append(stepData, gin.H{
					"timestamp": step.Timestamp,
					"machine":   step.Machine,
					"event_id":  step.EventID,
					"ip":        step.IPAddress,
				})
			}
			evidence[key] = stepData
		}
		for _, l := range lateral {
			key := fmt.Sprintf("event_%s_%s", l.SourceMachine, l.TargetMachine)
			evidence[key] = append(evidence[key], gin.H{
				"user":       l.User,
				"event_id":   l.EventID,
				"timestamp":  l.Timestamp,
				"ip_address": l.IPAddress,
				"severity":   l.Severity,
				"mitre":      l.MITREAttack,
			})
		}
		response["evidence_details"] = evidence
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	filename := fmt.Sprintf("multi_analysis_export_%s.json", time.Now().Format("20060102_150405"))
	if deep {
		filename = fmt.Sprintf("multi_analysis_deep_export_%s.json", time.Now().Format("20060102_150405"))
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/json")
	c.Data(http.StatusOK, "application/json", data)
}

func (h *MultiHandler) exportCSV(c *gin.Context, machines []MachineInfo, crossMachine []CrossMachineActivity, lateral []LateralMovement, lateralChains []LateralMovementChain, deep bool) {
	filename := fmt.Sprintf("multi_analysis_export_%s.csv", time.Now().Format("20060102_150405"))
	if deep {
		filename = fmt.Sprintf("multi_analysis_deep_export_%s.csv", time.Now().Format("20060102_150405"))
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "text/csv; charset=utf-8")

	w := csv.NewWriter(c.Writer)

	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

	if err := w.Write([]string{"=== Machine Inventory ==="}); err != nil {
		log.Printf("CSV write error: %v", err)
		return
	}
	w.Write([]string{"ID", "Name", "IP", "Domain", "Role", "OS Version", "Last Seen"})
	for _, m := range machines {
		w.Write([]string{m.ID, m.Name, m.IP, m.Domain, m.Role, m.OSVersion, m.LastSeen})
	}

	w.Write([]string{""})

	w.Write([]string{"=== Cross-Machine Activity ==="})
	w.Write([]string{"User", "Machine Count", "Machines", "Source IPs", "Login Count", "Suspicious", "Severity", "Recommendation"})
	for _, a := range crossMachine {
		w.Write([]string{
			a.User,
			strconv.Itoa(a.MachineCount),
			strings.Join(a.Machines, "; "),
			strings.Join(a.SourceIPs, "; "),
			strconv.Itoa(a.LoginCount),
			strconv.FormatBool(a.Suspicious),
			a.Severity,
			a.Recommendation,
		})
	}

	w.Write([]string{""})

	w.Write([]string{"=== Lateral Movement Chains ==="})
	w.Write([]string{"User", "Machine Count", "Duration", "Severity", "Description", "MITRE ATT&CK", "Steps"})
	for _, chain := range lateralChains {
		steps := make([]string, 0, len(chain.Steps))
		for _, s := range chain.Steps {
			steps = append(steps, fmt.Sprintf("[%s] %s (%s)", s.Timestamp, s.Machine, s.IPAddress))
		}
		w.Write([]string{
			chain.User,
			strconv.Itoa(chain.MachineCount),
			chain.Duration,
			chain.Severity,
			chain.Description,
			strings.Join(chain.MITREAttack, "; "),
			strings.Join(steps, " -> "),
		})
	}

	if deep {
		w.Write([]string{""})
		w.Write([]string{"=== Lateral Movement Evidence Details ==="})
		w.Write([]string{"Chain User", "Step Time", "Machine", "Event ID", "IP Address", "Description"})
		for _, chain := range lateralChains {
			for _, step := range chain.Steps {
				w.Write([]string{
					chain.User,
					step.Timestamp,
					step.Machine,
					strconv.Itoa(step.EventID),
					step.IPAddress,
					step.Description,
				})
			}
		}
	} else {
		w.Write([]string{""})
		w.Write([]string{"=== Lateral Movement Events ==="})
		w.Write([]string{"Source Machine", "Target Machine", "User", "Event ID", "Timestamp", "IP Address", "Severity", "Description", "MITRE ATT&CK"})
		for _, l := range lateral {
			w.Write([]string{
				l.SourceMachine,
				l.TargetMachine,
				l.User,
				strconv.Itoa(l.EventID),
				l.Timestamp,
				l.IPAddress,
				l.Severity,
				l.Description,
				strings.Join(l.MITREAttack, "; "),
			})
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		log.Printf("CSV flush error: %v", err)
	}
}

func (h *MultiHandler) getMachineContexts() ([]MachineInfo, error) {
	rows, err := h.db.Query(`
		SELECT id, hostname, ip_address, domain, role, os_version, last_seen
		FROM machine_assets
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var machines []MachineInfo
	var scanErrors int
	for rows.Next() {
		var m MachineInfo
		if err := rows.Scan(&m.ID, &m.Name, &m.IP, &m.Domain, &m.Role, &m.OSVersion, &m.LastSeen); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("getMachineContexts: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}
		m.Name = strings.ToLower(m.Name)
		machines = append(machines, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("machine_assets query iteration error: %w", err)
	}

	if scanErrors > 5 {
		log.Printf("getMachineContexts: total %d rows skipped due to scan errors", scanErrors)
	}

	if machines == nil {
		machines = []MachineInfo{}
	}
	return machines, nil
}

func (h *MultiHandler) analyzeCrossMachineActivity(startTime, endTime time.Time, limit int) ([]CrossMachineActivity, error) {
	rows, err := h.db.Query(`
		SELECT computer, user, event_id, timestamp, ip_address, message
		FROM events
		WHERE event_id IN (4624, 4625, 4648, 4672, 4728, 4729, 4732, 4756, 4757)
		AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC
		LIMIT ?
	`, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type userActivity struct {
		machines  map[string]int
		sourceIPs map[string]struct{}
		totalLogins int
	}
	userData := make(map[string]*userActivity)

	var scanErrors int
	for rows.Next() {
		var computer, user, timestamp, ipAddress, message string
		var eventID int64
		if err := rows.Scan(&computer, &user, &eventID, &timestamp, &ipAddress, &message); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("analyzeCrossMachineActivity: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}

		if user == "" || computer == "" {
			continue
		}

		computer = strings.ToLower(computer)
		user = strings.ToLower(user)

		if userData[user] == nil {
			userData[user] = &userActivity{
				machines:  make(map[string]int),
				sourceIPs: make(map[string]struct{}),
			}
		}
		ua := userData[user]
		ua.machines[computer]++
		ua.totalLogins++
		if ipAddress != "" && ipAddress != "127.0.0.1" && ipAddress != "::1" {
			ua.sourceIPs[ipAddress] = struct{}{}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cross-machine query iteration error: %w", err)
	}

	if scanErrors > 5 {
		log.Printf("analyzeCrossMachineActivity: total %d rows skipped due to scan errors", scanErrors)
	}

	var activities []CrossMachineActivity
	for user, ua := range userData {
		if len(ua.machines) < 2 {
			continue
		}

		machineList := make([]string, 0, len(ua.machines))
		for m := range ua.machines {
			machineList = append(machineList, m)
		}
		sort.Strings(machineList)

		ipList := make([]string, 0, len(ua.sourceIPs))
		for ip := range ua.sourceIPs {
			ipList = append(ipList, ip)
		}
		sort.Strings(ipList)

		severity := "low"
		suspicious := false
		recommendation := "Normal user activity pattern"

		if len(ua.machines) >= 5 {
			severity = "high"
			suspicious = true
			recommendation = "Investigate: User logged into multiple machines simultaneously"
		} else if len(ua.machines) >= 3 {
			severity = "medium"
			suspicious = true
			recommendation = "Review: User accessed multiple machines"
		}

		if len(ua.sourceIPs) == 1 && len(ua.machines) >= 3 {
			severity = "high"
			suspicious = true
			recommendation = "Critical: All logins from single source IP - possible jump server attack"
		}

		activities = append(activities, CrossMachineActivity{
			User:           user,
			MachineCount:   len(ua.machines),
			Machines:       machineList,
			SourceIPs:      ipList,
			LoginCount:     ua.totalLogins,
			Suspicious:     suspicious,
			Severity:       severity,
			Recommendation: recommendation,
		})
	}

	if activities == nil {
		activities = []CrossMachineActivity{}
	}
	return activities, nil
}

func (h *MultiHandler) detectLateralMovement(startTime, endTime time.Time, limit int) ([]LateralMovement, []LateralMovementChain, error) {
	assets, err := h.getMachineContexts()
	if err != nil {
		log.Printf("detectLateralMovement: failed to get machine contexts: %v", err)
		assets = []MachineInfo{}
	}

	ipToHosts := make(map[string][]string)
	ipCollisionWarnings := make(map[string][]string)
	for _, a := range assets {
		if a.IP != "" {
			ip := a.IP
			host := a.Name
			if existing, ok := ipToHosts[ip]; ok {
				if !slices.Contains(existing, host) {
					ipToHosts[ip] = append(existing, host)
					ipCollisionWarnings[ip] = append(ipCollisionWarnings[ip], host)
				}
			} else {
				ipToHosts[ip] = []string{host}
			}
		}
	}
	for ip, hosts := range ipCollisionWarnings {
		log.Printf("IP collision detected: %s maps to multiple hosts: %v", ip, hosts)
	}

	resolveIP := func(ip string) string {
		if ip == "" || ip == "127.0.0.1" || ip == "::1" {
			return ""
		}
		if hosts, ok := ipToHosts[ip]; ok {
			return hosts[0]
		}
		return ip
	}

	var allEvents []LoginEvent
	var scanErrors int

	rows, err := h.db.Query(`
		SELECT computer, user, event_id, timestamp, ip_address, message
		FROM events
		WHERE event_id IN (4624, 4648, 4672, 4688, 4697, 4698)
		AND timestamp BETWEEN ? AND ?
		ORDER BY user, timestamp ASC
		LIMIT ?
	`, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var computer, user, timestamp, ipAddress, message string
		var eventID int64
		if err := rows.Scan(&computer, &user, &eventID, &timestamp, &ipAddress, &message); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("detectLateralMovement: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}

		if user == "" || computer == "" {
			continue
		}

		computer = strings.ToLower(computer)
		user = strings.ToLower(user)

		var pt time.Time
		if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
			pt = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", timestamp); err == nil {
			pt = t
		}

		allEvents = append(allEvents, LoginEvent{
			Computer:   computer,
			User:       user,
			EventID:    eventID,
			Timestamp:  timestamp,
			IPAddress:  ipAddress,
			ParsedTime: pt,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("lateral movement query iteration error: %w", err)
	}

	if scanErrors > 5 {
		log.Printf("detectLateralMovement: total %d rows skipped due to scan errors", scanErrors)
	}

	userEvents := make(map[string][]LoginEvent)
	for _, e := range allEvents {
		userEvents[e.User] = append(userEvents[e.User], e)
	}

	var individualEvents []LateralMovement
	var chains []LateralMovementChain

	for user, events := range userEvents {
		if len(events) < 2 {
			continue
		}

		sort.Slice(events, func(i, j int) bool {
			return events[i].ParsedTime.Before(events[j].ParsedTime)
		})

		var currentChain []LoginEvent
		currentChain = append(currentChain, events[0])

		for i := 1; i < len(events); i++ {
			prev := currentChain[len(currentChain)-1]
			curr := events[i]

			timeDiff := curr.ParsedTime.Sub(prev.ParsedTime)
			if timeDiff <= 0 {
				timeDiff = -timeDiff
			}

			prevMachine := prev.Computer
			currMachine := curr.Computer
			if prev.IPAddress != "" && prev.IPAddress != "127.0.0.1" && prev.IPAddress != "::1" {
				if resolved := resolveIP(prev.IPAddress); resolved != "" {
					prevMachine = resolved
				}
			}

			if prevMachine != currMachine && timeDiff <= lateralMovementWindow {
				currentChain = append(currentChain, curr)
			} else {
				if len(currentChain) >= 2 {
					chains = append(chains, buildLateralChain(user, currentChain, ipToHosts))
				}
				currentChain = []LoginEvent{curr}
			}
		}

		if len(currentChain) >= 2 {
			chains = append(chains, buildLateralChain(user, currentChain, ipToHosts))
		}

		for _, e := range events {
			sourceMachine := "local"
			if e.IPAddress != "" && e.IPAddress != "127.0.0.1" && e.IPAddress != "::1" {
				if host := resolveIP(e.IPAddress); host != "" {
					sourceMachine = host
				} else {
					sourceMachine = e.IPAddress
				}
			}

			desc := eventDescriptions[e.EventID]
			if desc == "" {
				desc = "Security event"
			}

			mitre := eventMITRE[e.EventID]
			if mitre == nil {
				mitre = []string{}
			}

			individualEvents = append(individualEvents, LateralMovement{
				SourceMachine: sourceMachine,
				TargetMachine: e.Computer,
				User:          user,
				EventID:       int(e.EventID),
				Timestamp:     e.Timestamp,
				IPAddress:     e.IPAddress,
				Severity:      "medium",
				Description:   desc,
				MITREAttack:   mitre,
			})
		}
	}

	if individualEvents == nil {
		individualEvents = []LateralMovement{}
	}
	if chains == nil {
		chains = []LateralMovementChain{}
	}

	return individualEvents, chains, nil
}

func buildLateralChain(user string, events []LoginEvent, ipToHosts map[string][]string) LateralMovementChain {
	steps := make([]MovementStep, 0, len(events))
	uniqueMachines := make(map[string]struct{})

	for _, e := range events {
		sourceMachine := e.Computer
		if e.IPAddress != "" && e.IPAddress != "127.0.0.1" && e.IPAddress != "::1" {
			if hosts, ok := ipToHosts[e.IPAddress]; ok {
				sourceMachine = hosts[0]
			} else {
				sourceMachine = e.IPAddress
			}
		}

		desc := eventDescriptions[e.EventID]
		if desc == "" {
			desc = "Security event"
		}

		steps = append(steps, MovementStep{
			Timestamp:   e.Timestamp,
			Machine:     e.Computer,
			EventID:     int(e.EventID),
			IPAddress:   e.IPAddress,
			Description: fmt.Sprintf("%s -> %s", sourceMachine, e.Computer),
		})
		uniqueMachines[e.Computer] = struct{}{}
	}

	duration := ""
	if len(events) >= 2 && !events[0].ParsedTime.IsZero() && !events[len(events)-1].ParsedTime.IsZero() {
		d := events[len(events)-1].ParsedTime.Sub(events[0].ParsedTime)
		duration = d.String()
	}

	severity := "medium"
	if len(uniqueMachines) >= 4 {
		severity = "critical"
	} else if len(uniqueMachines) >= 3 {
		severity = "high"
	}

	hasPrivEsc := false
	hasCredUse := false
	for _, e := range events {
		if e.EventID == 4672 || e.EventID == 4697 {
			hasPrivEsc = true
		}
		if e.EventID == 4648 {
			hasCredUse = true
		}
	}
	if hasPrivEsc || hasCredUse {
		severity = "high"
	}

	var mitreSet []string
	mitreSeen := make(map[string]struct{})
	for _, e := range events {
		if m, ok := eventMITRE[e.EventID]; ok {
			for _, tag := range m {
				if _, seen := mitreSeen[tag]; !seen {
					mitreSeen[tag] = struct{}{}
					mitreSet = append(mitreSet, tag)
				}
			}
		}
	}

	return LateralMovementChain{
		User:        user,
		Steps:       steps,
		Duration:    duration,
		MachineCount: len(uniqueMachines),
		Severity:    severity,
		Description: fmt.Sprintf("User %s accessed %d machines in %s", user, len(uniqueMachines), duration),
		MITREAttack: mitreSet,
	}
}

var eventDescriptions = map[int64]string{
	4624: "Successful network login",
	4648: "Explicit credentials used",
	4672: "Special privileges assigned",
	4688: "Process creation",
	4697: "Service installed",
	4698: "Scheduled task created",
}

var eventMITRE = map[int64][]string{
	4624: {"T1078", "Valid Accounts"},
	4648: {"T1078", "Valid Accounts"},
	4672: {"T1068", "Exploitation for Privilege Escalation"},
	4688: {"T1059", "Command and Scripting Interpreter"},
	4697: {"T1543", "Create or Modify System Process"},
	4698: {"T1053", "Scheduled Task/Job"},
}

func generateAnalysisID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("multi_%s_%s", time.Now().Format("20060102150405"), hex.EncodeToString(b))
}

func generateMultiSummary(machineCount, suspiciousCount, lateralChainCount int) string {
	if machineCount == 0 {
		return "No machine data available. Import event logs from multiple machines to enable cross-machine analysis."
	}
	if suspiciousCount == 0 && lateralChainCount == 0 {
		return "No suspicious cross-machine activity detected."
	}
	return fmt.Sprintf("Analysis found %d suspicious activities and %d lateral movement chains.", suspiciousCount, lateralChainCount)
}

func SetupMultiRoutes(r *gin.Engine, h *MultiHandler) {
	multi := r.Group("/api/multi")
	{
		multi.GET("", h.GetInfo)
		multi.POST("/analyze", h.Analyze)
		multi.GET("/lateral", h.Lateral)
		multi.POST("/export", h.Export)
	}
}
