package types

import (
	"time"
)

type ImportResult struct {
	Success        bool
	TotalFiles     int
	FilesImported  int
	FilesFailed    int
	EventsImported int64
	EventsFailed   int64
	Duration       time.Duration
	Errors         []*ImportError
}

type ImportError struct {
	FilePath string `json:"file_path"`
	Error    string `json:"error"`
}

type SearchRequest struct {
	Keywords    string     `json:"keywords"`
	KeywordMode string     `json:"keyword_mode"`
	Regex       bool       `json:"regex"`
	EventIDs    []int32    `json:"event_ids"`
	Levels      []int      `json:"levels"`
	LogNames    []string   `json:"log_names"`
	Sources     []string   `json:"sources"`
	Users       []string   `json:"users"`
	Computers   []string   `json:"computers"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
	Page        int        `json:"page"`
	PageSize    int        `json:"page_size"`
	SortBy      string     `json:"sort_by"`
	SortOrder   string     `json:"sort_order"`
	Highlight   bool       `json:"highlight"`
}

type SearchResponse struct {
	Events     []*Event `json:"events"`
	Total      int64    `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalPages int      `json:"total_pages"`
	QueryTime  int64    `json:"query_time_ms"`
}

type CollectResult struct {
	Success    bool
	OutputPath string
	FileCount  int
	TotalSize  int64
	Duration   time.Duration
	Hash       string
	Errors     []error
}

type CollectOptions struct {
	OutputPath        string
	IncludeLogs       bool
	IncludePrefetch   bool
	IncludeShimcache  bool
	IncludeAmcache    bool
	IncludeUserassist bool
	IncludeRegistry   bool
	IncludeTasks      bool
	IncludeSystemInfo bool
	Compress          bool
	CompressLevel     int
	CalculateHash     bool
	Password          string
	ExcludePatterns   string
	Workers           int
}

type VerifyResult struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256"`
	Expected string `json:"expected,omitempty"`
	Match    bool   `json:"match"`
}

type AnalyzeResult struct {
	Type    string      `json:"type"`
	Results interface{} `json:"results"`
	Summary string      `json:"summary"`
}

type HealthStatus struct {
	Status    string        `json:"status"`
	Database  string        `json:"database"`
	Storage   string        `json:"storage"`
	Uptime    time.Duration `json:"uptime"`
	Timestamp time.Time     `json:"timestamp"`
}

type Pagination struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
}

func (p *Pagination) GetOffset() int {
	return (p.Page - 1) * p.PageSize
}

func (p *Pagination) GetTotalPages() int {
	if p.PageSize <= 0 {
		return 0
	}
	return int((p.Total + int64(p.PageSize) - 1) / int64(p.PageSize))
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func NewTimeRange(start, end time.Time) *TimeRange {
	return &TimeRange{
		Start: start,
		End:   end,
	}
}

func (tr *TimeRange) Contains(t time.Time) bool {
	return t.After(tr.Start) && t.Before(tr.End)
}

func (tr *TimeRange) Overlaps(other *TimeRange) bool {
	return tr.Start.Before(other.End) && tr.End.After(other.Start)
}
