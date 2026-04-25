package analyzers

import (
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func TestBruteForceAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewBruteForceAnalyzer()
	if got := a.Name(); got != "brute_force" {
		t.Errorf("Name() = %v, want %v", got, "brute_force")
	}
}

func TestBruteForceAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name     string
		events   []*types.Event
		wantLen  int
		wantHigh bool
	}{
		{
			name:     "no events",
			events:   []*types.Event{},
			wantLen:  0,
			wantHigh: false,
		},
		{
			name: "only normal login",
			events: []*types.Event{
				makeLoginEvent(4624, "user1", "192.168.1.1"),
			},
			wantLen:  0,
			wantHigh: false,
		},
		{
			name: "brute force with compromise",
			events: []*types.Event{
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4624, "user1", "192.168.1.1"),
			},
			wantLen:  1,
			wantHigh: true,
		},
		{
			name: "failed logins without success",
			events: []*types.Event{
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
			},
			wantLen:  0,
			wantHigh: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewBruteForceAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
			if tt.wantHigh && result.Severity != "high" && result.Severity != "critical" {
				t.Errorf("Analyze() got severity %v, want high or critical", result.Severity)
			}
		})
	}
}

func TestLoginAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewLoginAnalyzer()
	if got := a.Name(); got != "login" {
		t.Errorf("Name() = %v, want %v", got, "login")
	}
}

func TestLoginAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
		{
			name: "normal logins",
			events: []*types.Event{
				makeLoginEvent(4624, "user1", "192.168.1.1"),
				makeLoginEvent(4624, "user2", "192.168.1.2"),
			},
			wantLen: 0,
		},
		{
			name: "mixed logins",
			events: []*types.Event{
				makeLoginEvent(4624, "user1", "192.168.1.1"),
				makeLoginEvent(4625, "user1", "192.168.1.1"),
				makeLoginEvent(4624, "user2", "192.168.1.2"),
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewLoginAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestKerberosAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewKerberosAnalyzer()
	if got := a.Name(); got != "kerberos" {
		t.Errorf("Name() = %v, want %v", got, "kerberos")
	}
}

func TestKerberosAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
		{
			name: "normal kerberos",
			events: []*types.Event{
				makeKerberosEvent(4768, "user1", "DC01"),
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewKerberosAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestPowerShellAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewPowerShellAnalyzer()
	if got := a.Name(); got != "powershell" {
		t.Errorf("Name() = %v, want %v", got, "powershell")
	}
}

func TestPowerShellAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
		{
			name: "suspicious powershell",
			events: []*types.Event{
				makePowerShellEvent("Invoke-Mimikatz"),
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewPowerShellAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestDataExfiltrationAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewDataExfiltrationAnalyzer()
	if got := a.Name(); got != "data_exfiltration" {
		t.Errorf("Name() = %v, want %v", got, "data_exfiltration")
	}
}

func TestDataExfiltrationAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewDataExfiltrationAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestLateralMovementAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewLateralMovementAnalyzer()
	if got := a.Name(); got != "lateral_movement" {
		t.Errorf("Name() = %v, want %v", got, "lateral_movement")
	}
}

func TestLateralMovementAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewLateralMovementAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestPersistenceAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewPersistenceAnalyzer()
	if got := a.Name(); got != "persistence" {
		t.Errorf("Name() = %v, want %v", got, "persistence")
	}
}

func TestPersistenceAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
		{
			name: "suspicious service",
			events: []*types.Event{
				makeServiceEvent(4697, "RemoteService"),
			},
			wantLen: 1,
		},
		{
			name: "normal service",
			events: []*types.Event{
				makeServiceEvent(4697, "NormalService"),
			},
			wantLen: 1,
		},
		{
			name: "scheduled task",
			events: []*types.Event{
				makeTaskEvent(4698, "SuspiciousTask"),
			},
			wantLen: 1,
		},
		{
			name: "privileged group modification",
			events: []*types.Event{
				makeGroupEvent(4728, "Administrators"),
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewPersistenceAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestPrivilegeEscalationAnalyzer_Name(t *testing.T) {
	t.Helper()
	a := NewPrivilegeEscalationAnalyzer()
	if got := a.Name(); got != "privilege_escalation" {
		t.Errorf("Name() = %v, want %v", got, "privilege_escalation")
	}
}

func TestPrivilegeEscalationAnalyzer_Analyze(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		events  []*types.Event
		wantLen int
	}{
		{
			name:    "no events",
			events:  []*types.Event{},
			wantLen: 0,
		},
		{
			name: "suspicious process",
			events: []*types.Event{
				makeProcessEvent(4688, "cmd.exe"),
			},
			wantLen: 0,
		},
		{
			name: "multiple cmd processes",
			events: []*types.Event{
				makeProcessEvent(4688, "cmd.exe"),
				makeProcessEvent(4688, "cmd.exe"),
				makeProcessEvent(4688, "cmd.exe"),
				makeProcessEvent(4688, "cmd.exe"),
				makeProcessEvent(4688, "cmd.exe"),
			},
			wantLen: 2,
		},
		{
			name: "mimikatz detection",
			events: []*types.Event{
				makeProcessEvent(4688, "mimikatz.exe"),
			},
			wantLen: 1,
		},
		{
			name: "suspicious whoami",
			events: []*types.Event{
				makeProcessEvent(4688, "whoami.exe"),
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewPrivilegeEscalationAnalyzer()
			result, err := a.Analyze(tt.events)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if len(result.Findings) != tt.wantLen {
				t.Errorf("Analyze() got %v findings, want %v", len(result.Findings), tt.wantLen)
			}
		})
	}
}

func TestAnalyzerManager_Register(t *testing.T) {
	t.Helper()
	mgr := NewAnalyzerManager()
	a := NewBruteForceAnalyzer()
	mgr.Register(a)

	if len(mgr.analyzers) != 1 {
		t.Errorf("Register() did not register analyzer")
	}
}

func TestAnalyzerManager_Get(t *testing.T) {
	t.Helper()
	mgr := NewAnalyzerManager()
	mgr.Register(NewBruteForceAnalyzer())
	mgr.Register(NewLoginAnalyzer())

	tests := []struct {
		name   string
		key    string
		wantOk bool
	}{
		{"existing", "brute_force", true},
		{"existing", "login", true},
		{"non-existing", "nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := mgr.Get(tt.key)
			if ok != tt.wantOk {
				t.Errorf("Get(%v) = %v, want %v", tt.key, ok, tt.wantOk)
			}
		})
	}
}

func TestAnalyzerManager_List(t *testing.T) {
	t.Helper()
	mgr := NewAnalyzerManager()
	mgr.Register(NewBruteForceAnalyzer())
	mgr.Register(NewLoginAnalyzer())

	names := mgr.List()
	if len(names) != 2 {
		t.Errorf("List() got %v names, want 2", len(names))
	}
}

func TestAnalyzerManager_AnalyzeAll(t *testing.T) {
	t.Helper()
	mgr := NewAnalyzerManager()
	mgr.Register(NewBruteForceAnalyzer())
	mgr.Register(NewLoginAnalyzer())

	events := []*types.Event{
		makeLoginEvent(4624, "user1", "192.168.1.1"),
	}

	results, err := mgr.AnalyzeAll(events)
	if err != nil {
		t.Fatalf("AnalyzeAll() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("AnalyzeAll() got %v results, want 2", len(results))
	}
}

func TestResult_CalculateOverallScore(t *testing.T) {
	t.Helper()
	tests := []struct {
		name     string
		findings []Finding
		want     float64
	}{
		{
			name:     "no findings",
			findings: []Finding{},
			want:     0,
		},
		{
			name: "single finding",
			findings: []Finding{
				{Score: 80},
			},
			want: 80,
		},
		{
			name: "multiple findings",
			findings: []Finding{
				{Score: 60},
				{Score: 80},
				{Score: 100},
			},
			want: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{Findings: tt.findings}
			if got := r.CalculateOverallScore(); got != tt.want {
				t.Errorf("CalculateOverallScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResult_AddFinding(t *testing.T) {
	t.Helper()
	r := NewResult("test", nil, "", "medium", 50)
	r.AddFinding(Finding{Score: 80})
	if len(r.Findings) != 1 {
		t.Errorf("AddFinding() did not add finding")
	}
}

func BenchmarkBruteForceAnalyzer_Analyze(b *testing.B) {
	b.Helper()
	a := NewBruteForceAnalyzer()
	events := makeEvents(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze(events)
	}
}

func BenchmarkLoginAnalyzer_Analyze(b *testing.B) {
	b.Helper()
	a := NewLoginAnalyzer()
	events := makeEvents(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze(events)
	}
}

func BenchmarkPersistenceAnalyzer_Analyze(b *testing.B) {
	b.Helper()
	a := NewPersistenceAnalyzer()
	events := makePersistenceEvents(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze(events)
	}
}

func BenchmarkPrivilegeEscalationAnalyzer_Analyze(b *testing.B) {
	b.Helper()
	a := NewPrivilegeEscalationAnalyzer()
	events := makePrivilegeEvents(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze(events)
	}
}

func makeLoginEvent(eventID int32, user, ip string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      &user,
		IPAddress: &ip,
		Computer:  "WORKSTATION1",
		Message:   "Test login event",
	}
}

func makeKerberosEvent(eventID int32, user, computer string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      &user,
		Computer:  computer,
		Message:   "Test Kerberos event",
	}
}

func makePowerShellEvent(command string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   4103,
		Timestamp: time.Now(),
		User:      strPtr("user1"),
		Computer:  "WORKSTATION1",
		Message:   "ScriptBlockText: " + command,
	}
}

func makeServiceEvent(eventID int32, serviceName string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      strPtr("SYSTEM"),
		Computer:  "SERVER01",
		Message:   "Service Name: " + serviceName,
	}
}

func makeTaskEvent(eventID int32, taskName string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      strPtr("admin"),
		Computer:  "SERVER01",
		Message:   "Task Name: " + taskName,
	}
}

func makeGroupEvent(eventID int32, groupName string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      strPtr("admin"),
		Computer:  "DC01",
		Message:   "Target Group: " + groupName,
	}
}

func makeProcessEvent(eventID int32, processName string) *types.Event {
	return &types.Event{
		ID:        1,
		EventID:   eventID,
		Timestamp: time.Now(),
		User:      strPtr("user"),
		Computer:  "WORKSTATION1",
		Message:   "New Process Name: " + processName,
	}
}

func makeEvents(n int) []*types.Event {
	events := make([]*types.Event, n)
	for i := 0; i < n; i++ {
		user := "user"
		ip := "192.168.1.1"
		events[i] = &types.Event{
			ID:        int64(i),
			EventID:   4624,
			Timestamp: time.Now(),
			User:      &user,
			IPAddress: &ip,
			Computer:  "WORKSTATION1",
		}
	}
	return events
}

func makePersistenceEvents(n int) []*types.Event {
	events := make([]*types.Event, 0, n)
	for i := 0; i < n; i++ {
		user := "SYSTEM"
		switch i % 4 {
		case 0:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4697,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "SERVER01",
				Message:   "Service Name: RemoteService",
			})
		case 1:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4698,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "SERVER01",
				Message:   "Task Name: SuspiciousTask",
			})
		case 2:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4728,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "DC01",
				Message:   "Target Group: Administrators",
			})
		default:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4720,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "DC01",
				Message:   "New Account Creation",
			})
		}
	}
	return events
}

func makePrivilegeEvents(n int) []*types.Event {
	events := make([]*types.Event, 0, n)
	for i := 0; i < n; i++ {
		user := "user"
		switch i % 5 {
		case 0:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4688,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "WORKSTATION1",
				Message:   "New Process Name: cmd.exe",
			})
		case 1:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4672,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "WORKSTATION1",
				Message:   "Special Privileges: SeSecurityPrivilege",
			})
		case 2:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4688,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "WORKSTATION1",
				Message:   "New Process Name: mimikatz.exe",
			})
		default:
			events = append(events, &types.Event{
				ID:        int64(i),
				EventID:   4673,
				Timestamp: time.Now(),
				User:      &user,
				Computer:  "WORKSTATION1",
				Message:   "Sensitive Privilege Use: SeTcbPrivilege",
			})
		}
	}
	return events
}

func strPtr(s string) *string {
	return &s
}
