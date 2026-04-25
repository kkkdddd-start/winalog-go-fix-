package rules

import "strings"

type FilterMatcher struct {
	eventIDSet  map[int32]bool
	levelSet    map[string]bool
	logNameSet  map[string]bool
	sourceSet   map[string]bool
	computerSet map[string]bool
}

func NewFilterMatcher(f *Filter) *FilterMatcher {
	m := &FilterMatcher{
		eventIDSet:  make(map[int32]bool, len(f.EventIDs)),
		levelSet:    make(map[string]bool, len(f.Levels)),
		logNameSet:  make(map[string]bool, len(f.LogNames)),
		sourceSet:   make(map[string]bool, len(f.Sources)),
		computerSet: make(map[string]bool, len(f.Computers)),
	}

	for _, eid := range f.EventIDs {
		m.eventIDSet[eid] = true
	}
	for _, lvl := range f.Levels {
		m.levelSet[strings.ToLower(lvl)] = true
	}
	for _, ln := range f.LogNames {
		m.logNameSet[ln] = true
	}
	for _, src := range f.Sources {
		m.sourceSet[src] = true
	}
	for _, comp := range f.Computers {
		m.computerSet[comp] = true
	}

	return m
}

func (m *FilterMatcher) MatchEventID(eid int32) bool {
	if len(m.eventIDSet) == 0 {
		return true
	}
	return m.eventIDSet[eid]
}

func (m *FilterMatcher) MatchLevel(level string) bool {
	if len(m.levelSet) == 0 {
		return true
	}
	return m.levelSet[strings.ToLower(level)]
}

func (m *FilterMatcher) MatchLogName(logName string) bool {
	if len(m.logNameSet) == 0 {
		return true
	}
	return m.logNameSet[logName]
}

func (m *FilterMatcher) MatchSource(source string) bool {
	if len(m.sourceSet) == 0 {
		return true
	}
	return m.sourceSet[source]
}

func (m *FilterMatcher) MatchComputer(computer string) bool {
	if len(m.computerSet) == 0 {
		return true
	}
	return m.computerSet[computer]
}
