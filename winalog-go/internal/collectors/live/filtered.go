package live

import (
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type EventFilter interface {
	Accept(event *types.Event) bool
	Name() string
}

type LevelFilter struct {
	name   string
	levels []string
}

func NewLevelFilter(levels ...string) *LevelFilter {
	return &LevelFilter{
		name:   "level_filter",
		levels: levels,
	}
}

func (f *LevelFilter) Accept(event *types.Event) bool {
	if len(f.levels) == 0 {
		return true
	}
	for _, level := range f.levels {
		if string(event.Level) == level {
			return true
		}
	}
	return false
}

func (f *LevelFilter) Name() string {
	return f.name
}

type EventIDFilter struct {
	name     string
	eventIDs []int32
}

func NewEventIDFilter(eventIDs ...int32) *EventIDFilter {
	return &EventIDFilter{
		name:     "event_id_filter",
		eventIDs: eventIDs,
	}
}

func (f *EventIDFilter) Accept(event *types.Event) bool {
	if len(f.eventIDs) == 0 {
		return true
	}
	for _, eid := range f.eventIDs {
		if event.EventID == eid {
			return true
		}
	}
	return false
}

func (f *EventIDFilter) Name() string {
	return f.name
}

type SourceFilter struct {
	name    string
	sources []string
}

func NewSourceFilter(sources ...string) *SourceFilter {
	return &SourceFilter{
		name:    "source_filter",
		sources: sources,
	}
}

func (f *SourceFilter) Accept(event *types.Event) bool {
	if len(f.sources) == 0 {
		return true
	}
	for _, source := range f.sources {
		if event.Source == source {
			return true
		}
	}
	return false
}

func (f *SourceFilter) Name() string {
	return f.name
}

type LogNameFilter struct {
	name     string
	logNames []string
}

func NewLogNameFilter(logNames ...string) *LogNameFilter {
	return &LogNameFilter{
		name:     "log_name_filter",
		logNames: logNames,
	}
}

func (f *LogNameFilter) Accept(event *types.Event) bool {
	if len(f.logNames) == 0 {
		return true
	}
	for _, logName := range f.logNames {
		if event.LogName == logName {
			return true
		}
	}
	return false
}

func (f *LogNameFilter) Name() string {
	return f.name
}

type TimeRangeFilter struct {
	name      string
	startTime int64
	endTime   int64
}

func NewTimeRangeFilter(start, end int64) *TimeRangeFilter {
	return &TimeRangeFilter{
		name:      "time_range_filter",
		startTime: start,
		endTime:   end,
	}
}

func (f *TimeRangeFilter) Accept(event *types.Event) bool {
	timestamp := event.Timestamp.Unix()
	if timestamp < f.startTime {
		return false
	}
	if f.endTime > 0 && timestamp > f.endTime {
		return false
	}
	return true
}

func (f *TimeRangeFilter) Name() string {
	return f.name
}

type KeywordFilter struct {
	name     string
	keywords []string
}

func NewKeywordFilter(keywords ...string) *KeywordFilter {
	return &KeywordFilter{
		name:     "keyword_filter",
		keywords: keywords,
	}
}

func (f *KeywordFilter) Accept(event *types.Event) bool {
	if len(f.keywords) == 0 {
		return true
	}
	msgLower := strings.ToLower(event.Message)
	for _, keyword := range f.keywords {
		if strings.Contains(msgLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func (f *KeywordFilter) Name() string {
	return f.name
}

type CompositeFilter struct {
	name    string
	filters []EventFilter
}

func NewCompositeFilter(filters ...EventFilter) *CompositeFilter {
	return &CompositeFilter{
		name:    "composite_filter",
		filters: filters,
	}
}

func (f *CompositeFilter) Accept(event *types.Event) bool {
	for _, filter := range f.filters {
		if !filter.Accept(event) {
			return false
		}
	}
	return true
}

func (f *CompositeFilter) Name() string {
	return f.name
}

func (f *CompositeFilter) AddFilter(filter EventFilter) {
	f.filters = append(f.filters, filter)
}

func (f *CompositeFilter) RemoveFilter(name string) {
	newFilters := make([]EventFilter, 0)
	for _, filter := range f.filters {
		if filter.Name() != name {
			newFilters = append(newFilters, filter)
		}
	}
	f.filters = newFilters
}
