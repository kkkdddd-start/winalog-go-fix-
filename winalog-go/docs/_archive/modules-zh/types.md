# Types 模块

**路径**: `internal/types/`

核心类型定义。

## Event 事件

```go
type EventLevel int

const (
    EventLevelCritical EventLevel = 1
    EventLevelError    EventLevel = 2
    EventLevelWarning  EventLevel = 3
    EventLevelInfo     EventLevel = 4
    EventLevelVerbose  EventLevel = 5
)

func (l EventLevel) String() string
func (l EventLevel) MarshalJSON() ([]byte, error)
func (l *EventLevel) UnmarshalJSON(data []byte) error
```

```go
type Event struct {
    ID         int64      `json:"id" db:"id"`
    Timestamp  time.Time  `json:"timestamp" db:"timestamp"`
    EventID    int32      `json:"event_id" db:"event_id"`
    Level      EventLevel `json:"level" db:"level"`
    Source     string     `json:"source" db:"source"`
    LogName    string     `json:"log_name" db:"log_name"`
    Computer   string     `json:"computer" db:"computer"`
    User       *string    `json:"user,omitempty" db:"user"`
    UserSID    *string    `json:"user_sid,omitempty" db:"user_sid"`
    Message    string     `json:"message" db:"message"`
    RawXML     *string    `json:"raw_xml,omitempty" db:"raw_xml"`
    SessionID  *string    `json:"session_id,omitempty" db:"session_id"`
    IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
    ImportTime time.Time  `json:"import_time" db:"import_time"`
    ImportID   int64      `json:"import_id,omitempty" db:"import_id"`
}
```

### Event 辅助方法

```go
// 转换为 Map
func (e *Event) ToMap() map[string]interface{}

// 转换为 Slice
func (e *Event) ToSlice() []interface{}

// 从 Row 扫描
func ScanEvent(row interface{ Scan(...interface{}) error }) (*Event, error)
```

### Event 列定义

```go
var EventColumns = []string{
    "id", "timestamp", "event_id", "level", "source", "log_name",
    "computer", "user", "user_sid", "message", "raw_xml", "session_id",
    "ip_address", "import_time", "import_id",
}
```

## Alert 告警

```go
type Alert struct {
    ID          int64      `json:"id"`
    RuleName    string     `json:"rule_name"`
    Severity    Severity   `json:"severity"`
    Message     string     `json:"message"`
    EventIDs    []int32   `json:"event_ids"`
    FirstSeen   time.Time  `json:"first_seen"`
    LastSeen    time.Time  `json:"last_seen"`
    Count       int        `json:"count"`
    MITREAttack []string   `json:"mitre_attack,omitempty"`
    Resolved    bool       `json:"resolved"`
    ResolvedTime *time.Time `json:"resolved_time,omitempty"`
    Notes       string     `json:"notes,omitempty"`
    FalsePositive bool     `json:"false_positive"`
    LogName     string     `json:"log_name,omitempty"`
    RuleScore   float64    `json:"rule_score"`
}
```

## Severity 严重级别

```go
type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

## SearchRequest / SearchResponse

```go
type SearchRequest struct {
    Keywords   string
    EventIDs   []int32
    Levels     []int
    LogNames   []string
    Computers  []string
    StartTime  *time.Time
    EndTime    *time.Time
    SortOrder  string  // "asc" 或 "desc"
    Page       int
    PageSize   int
}

type SearchResponse struct {
    Events     []*Event
    Total      int64
    Page       int
    PageSize   int
    TotalPages int
    QueryTime  int64  // 毫秒
}
```

## AlertStats / AlertTrend

```go
type AlertStats struct {
    Total       int64
    BySeverity  map[string]int64
    ByRule      map[string]int64
    ByHour      map[int]int64
    LastUpdated time.Time
}

type AlertTrend struct {
    Hourly []HourlyCount
    Daily  []DailyCount
}

type HourlyCount struct {
    Hour  int   `json:"hour"`
    Count int64 `json:"count"`
}

type DailyCount struct {
    Date  string `json:"date"`
    Count int64  `json:"count"`
}
```

## TimeRange

```go
type TimeRange struct {
    Start time.Time `json:"start"`
    End   time.Time `json:"end"`
}
```

## ImportError

```go
type ImportError struct {
    FilePath string `json:"file_path"`
    Error    string `json:"error"`
}
```

## System 系统信息

```go
type SystemInfo struct {
    Hostname   string `json:"hostname"`
    Domain     string `json:"domain"`
    OSVersion  string `json:"os_version"`
    OSBuild    string `json:"os_build"`
    MachineID  string `json:"machine_id"`
    TimeZone   string `json:"time_zone"`
    IsDC       bool   `json:"is_dc"`
    IsServer   bool   `json:"is_server"`
}

type ProcessInfo struct {
    PID        uint32 `json:"pid"`
    Name       string `json:"name"`
    Path       string `json:"path"`
    CommandLine string `json:"command_line"`
    User       string `json:"user"`
    SessionID  uint32 `json:"session_id"`
    MD5        string `json:"md5,omitempty"`
}

type NetworkInfo struct {
    AdapterName string `json:"adapter_name"`
    MACAddress string `json:"mac_address"`
    IPAddresses []string `json:"ip_addresses"`
    DefaultGateway string `json:"default_gateway"`
    DNSServers  []string `json:"dns_servers"`
}
```

## Helper 函数

```go
// ptrStr 返回字符串指针
func ptrStr(s string) *string

// strPtr 返回指针指向的字符串，空指针返回空字符串
func strPtr(s *string) string

// timePtr 返回时间戳指针
func timePtr(t time.Time) *time.Time
```
