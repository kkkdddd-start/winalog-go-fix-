package storage

import (
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type EventRepository interface {
	Insert(*types.Event) error
	InsertBatch([]*types.Event) error
	GetByID(int64) (*types.Event, error)
	Search(*types.SearchRequest) ([]*types.Event, int64, error)
	DeleteByImportID(int64) error
	DeleteOldEvents(age string) (int64, error)
	GetByTimeRange(start, end string) ([]*types.Event, error)
	GetEventIDsByImportID(importID int64) ([]int64, error)
}

type AlertRepository interface {
	Insert(*types.Alert) error
	Update(*types.Alert) error
	GetByID(int64) (*types.Alert, error)
	List(query *AlertQuery) ([]*types.Alert, int64, error)
	Resolve(id int64, notes string) error
	Delete(int64) error
	MarkFalsePositive(id int64, reason string) error
	GetUnresolved() ([]*types.Alert, error)
	GetByRuleName(ruleName string) ([]*types.Alert, error)
	CountBySeverity() (map[string]int64, error)
	CountByStatus() (map[string]int64, error)
	CountByRule() ([]*types.RuleCount, error)
}

type AlertQuery struct {
	Page      int
	PageSize  int
	Severity  string
	Resolved  *bool
	RuleName  string
	StartTime string
	EndTime   string
}

type ImportLogRepository interface {
	Insert(*ImportLog) (int64, error)
	Update(*ImportLog) error
	GetByID(int64) (*ImportLog, error)
	List(limit int) ([]*ImportLog, error)
	GetRecentImports(days int) ([]*ImportLog, error)
	Delete(id int64) error
}

type ImportLog struct {
	ID             int64
	FilePath       string
	FileHash       string
	EventsCount    int
	ImportTime     string
	ImportDuration int
	Status         string
	ErrorMessage   string
}

type MachineContextRepository interface {
	Insert(*MachineContext) error
	Update(*MachineContext) error
	GetByMachineID(machineID string) (*MachineContext, error)
	List() ([]*MachineContext, error)
	Delete(machineID string) error
}

type MachineContext struct {
	ID        int64
	MachineID string
	Name      string
	IPAddress string
	Domain    string
	Role      string
	FirstSeen string
	LastSeen  string
	OSVersion string
}

type CorrelationResultRepository interface {
	Insert(*types.CorrelationResult) error
	GetByID(id string) (*types.CorrelationResult, error)
	ListByTimeRange(start, end string) ([]*types.CorrelationResult, error)
	Delete(id string) error
}

type TimelineRepository interface {
	Insert(*TimelineEvent) error
	InsertBatch([]*TimelineEvent) error
	Query(query *TimelineQuery) ([]*TimelineEvent, error)
	DeleteOldEvents(age string) (int64, error)
}

type TimelineEvent struct {
	ID            int64
	EventID       int64
	Timestamp     string
	EventType     string
	Category      string
	Severity      string
	Source        string
	LogName       string
	Computer      string
	User          string
	Message       string
	MITREAttack   string
	AttackChainID string
}

type TimelineQuery struct {
	StartTime     string
	EndTime       string
	Categories    []string
	Severities    []string
	Computers     []string
	MITREAttack   []string
	AttackChainID string
	Limit         int
	Offset        int
}

type EvidenceChainRepository interface {
	Insert(*EvidenceChain) error
	GetByEvidenceID(evidenceID string) (*EvidenceChain, error)
	GetChain(evidenceID string) ([]*EvidenceChain, error)
}

type EvidenceChain struct {
	ID           int64
	EvidenceID   string
	Timestamp    string
	Operator     string
	Action       string
	InputHash    string
	OutputHash   string
	PreviousHash string
}

type EvidenceFileRepository interface {
	Insert(*EvidenceFile) error
	GetByHash(hash string) (*EvidenceFile, error)
	ListByEvidenceID(evidenceID string) ([]*EvidenceFile, error)
}

type EvidenceFile struct {
	ID          int64
	FilePath    string
	FileHash    string
	EvidenceID  string
	CollectedAt string
	Collector   string
}
