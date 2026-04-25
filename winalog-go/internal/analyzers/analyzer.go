package analyzers

import (
	"fmt"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AnalyzerConfig struct {
	EventIDs   []int32        `json:"event_ids"`
	Patterns   []string       `json:"patterns"`
	Whitelist  []string       `json:"whitelist"`
	Thresholds map[string]int `json:"thresholds"`
}

type AnalyzerError struct {
	AnalyzerName string
	Err          error
}

type AnalyzerErrors struct {
	Errors []AnalyzerError
}

func (e *AnalyzerErrors) Error() string {
	if len(e.Errors) == 1 {
		return fmt.Sprintf("analyzer %s failed: %v", e.Errors[0].AnalyzerName, e.Errors[0].Err)
	}
	return fmt.Sprintf("%d analyzers failed", len(e.Errors))
}

type AnalyzerResult struct {
	AnalyzerName string
	Result       *Result
	Error        error
}

type Analyzer interface {
	Name() string
	Analyze(events []*types.Event) (*Result, error)
}

type Result struct {
	Type      string    `json:"type"`
	Findings  []Finding `json:"findings"`
	Summary   string    `json:"summary"`
	Severity  string    `json:"severity"`
	Score     float64   `json:"score"`
	Timestamp int64     `json:"timestamp"`
}

type Finding struct {
	Description string                 `json:"description"`
	Evidence    []EvidenceItem         `json:"evidence,omitempty"`
	RuleName    string                 `json:"rule_name,omitempty"`
	MitreAttack string                 `json:"mitre_attack,omitempty"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type EvidenceItem struct {
	EventID   int32  `json:"event_id"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Computer  string `json:"computer"`
	Message   string `json:"message"`
}

type BaseAnalyzer struct {
	name string
}

func (a *BaseAnalyzer) Name() string {
	return a.name
}

func NewResult(analyzerType string, findings []Finding, summary string, severity string, score float64) *Result {
	return &Result{
		Type:     analyzerType,
		Findings: findings,
		Summary:  summary,
		Severity: severity,
		Score:    score,
	}
}

func (r *Result) AddFinding(finding Finding) {
	r.Findings = append(r.Findings, finding)
}

var severityWeights = map[string]float64{
	"critical": 1.5,
	"high":     1.2,
	"medium":   1.0,
	"low":      0.8,
	"info":     0.5,
}

func (r *Result) CalculateOverallScore() float64 {
	if len(r.Findings) == 0 {
		return 0
	}

	var totalScore float64
	var totalWeight float64
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

	type scoreWithSeverity struct {
		score    float64
		severity string
	}
	scorer := make([]scoreWithSeverity, 0, len(r.Findings))

	for _, f := range r.Findings {
		weight := severityWeights[f.Severity]
		if weight == 0 {
			weight = 1.0
		}
		totalScore += f.Score * weight
		totalWeight += weight
		scorer = append(scorer, scoreWithSeverity{f.Score, f.Severity})
	}

	if totalWeight == 0 {
		return 0
	}

	avgScore := totalScore / totalWeight

	maxScore := 0.0
	maxSeverityRank := 999
	for _, s := range scorer {
		if s.score > maxScore {
			maxScore = s.score
			severityRank := severityOrder[s.severity]
			if severityRank < maxSeverityRank {
				maxSeverityRank = severityRank
			}
		}
	}

	weightFactor := 1.0
	if maxSeverityRank == 0 {
		weightFactor = 1.5
	} else if maxSeverityRank == 1 {
		weightFactor = 1.2
	}

	finalScore := avgScore
	if maxScore*weightFactor > avgScore*1.5 {
		finalScore = maxScore * weightFactor
	}

	if finalScore > 100 {
		finalScore = 100
	}

	return finalScore
}

type AnalyzerManager struct {
	analyzers map[string]Analyzer
	configs   map[string]*AnalyzerConfig
}

func NewAnalyzerManager() *AnalyzerManager {
	return &AnalyzerManager{
		analyzers: make(map[string]Analyzer),
		configs:   make(map[string]*AnalyzerConfig),
	}
}

func (m *AnalyzerManager) Register(analyzer Analyzer) {
	m.analyzers[analyzer.Name()] = analyzer
}

func (m *AnalyzerManager) Get(name string) (Analyzer, bool) {
	analyzer, ok := m.analyzers[name]
	return analyzer, ok
}

func (m *AnalyzerManager) List() []string {
	names := make([]string, 0, len(m.analyzers))
	for name := range m.analyzers {
		names = append(names, name)
	}
	return names
}

func (m *AnalyzerManager) SetConfig(name string, config *AnalyzerConfig) {
	m.configs[name] = config
}

func (m *AnalyzerManager) GetConfig(name string) *AnalyzerConfig {
	if config, ok := m.configs[name]; ok {
		return config
	}
	return &AnalyzerConfig{}
}

func (m *AnalyzerManager) GetAllConfigs() map[string]*AnalyzerConfig {
	return m.configs
}

func (m *AnalyzerManager) SetDefaultConfigs() {
	m.configs["brute_force"] = &AnalyzerConfig{
		EventIDs:   []int32{4625, 4624},
		Patterns:   []string{},
		Whitelist:  []string{},
		Thresholds: map[string]int{"failed_threshold": 5, "success_threshold": 1},
	}
	m.configs["login"] = &AnalyzerConfig{
		EventIDs:  []int32{4624, 4625},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["kerberos"] = &AnalyzerConfig{
		EventIDs:  []int32{4768, 4769, 4771, 4770},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["powershell"] = &AnalyzerConfig{
		EventIDs:  []int32{4103, 4104},
		Patterns:  []string{"powershell", "Invoke-", "cmd.exe"},
		Whitelist: []string{},
	}
	m.configs["data_exfiltration"] = &AnalyzerConfig{
		EventIDs:  []int32{4624, 4688, 4663},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["lateral_movement"] = &AnalyzerConfig{
		EventIDs:  []int32{4624, 4688, 4648},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["persistence"] = &AnalyzerConfig{
		EventIDs:  []int32{4720, 4697, 7045, 4698, 4728, 4729, 4732, 4733, 4756, 4757},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["privilege_escalation"] = &AnalyzerConfig{
		EventIDs:  []int32{4672, 4673, 4674, 4688},
		Patterns:  []string{},
		Whitelist: []string{},
	}
	m.configs["dc"] = &AnalyzerConfig{
		EventIDs:  []int32{4720, 4726, 4728, 4729, 4732, 4733, 4746, 4747, 4756, 4757, 5136, 4662, 5139, 5140, 4670, 4741},
		Patterns:  []string{},
		Whitelist: []string{},
	}
}

func (m *AnalyzerManager) AnalyzeAll(events []*types.Event) ([]*Result, error) {
	results := make([]*Result, 0, len(m.analyzers))
	var errors []AnalyzerError

	for name, analyzer := range m.analyzers {
		result, err := analyzer.Analyze(events)
		if err != nil {
			errors = append(errors, AnalyzerError{
				AnalyzerName: name,
				Err:          err,
			})
			continue
		}
		results = append(results, result)
	}

	if len(errors) > 0 {
		return results, &AnalyzerErrors{Errors: errors}
	}
	return results, nil
}

func NewDefaultManager() *AnalyzerManager {
	mgr := NewAnalyzerManager()
	mgr.Register(NewBruteForceAnalyzer())
	mgr.Register(NewLoginAnalyzer())
	mgr.Register(NewKerberosAnalyzer())
	mgr.Register(NewPowerShellAnalyzer())
	mgr.Register(NewDataExfiltrationAnalyzer())
	mgr.Register(NewLateralMovementAnalyzer())
	mgr.Register(NewPersistenceAnalyzer())
	mgr.Register(NewPrivilegeEscalationAnalyzer())
	mgr.Register(NewDCAnalyzer())

	mgr.SetDefaultConfigs()
	return mgr
}
