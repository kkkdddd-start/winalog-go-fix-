package parsers

import (
	"sort"
	"sync"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type ParseResult struct {
	Events  <-chan *types.Event
	ErrCh   <-chan error
	Error   error
}

type Parser interface {
	CanParse(path string) bool
	Parse(path string) <-chan *types.Event
	ParseWithError(path string) ParseResult
	ParseBatch(path string) ([]*types.Event, error)
	GetType() string
	Priority() int
}

type ParserRegistry struct {
	mu       sync.RWMutex
	parsers  map[string]Parser
	priority []Parser
}

func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]Parser),
	}
}

var (
	globalRegistry *ParserRegistry
	globalOnce     sync.Once
)

func GetGlobalRegistry() *ParserRegistry {
	globalOnce.Do(func() {
		globalRegistry = NewParserRegistry()
	})
	return globalRegistry
}

func (r *ParserRegistry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()

	parserType := p.GetType()
	if _, exists := r.parsers[parserType]; exists {
		return
	}

	r.parsers[parserType] = p
	r.rebuildPriority()
}

func (r *ParserRegistry) rebuildPriority() {
	r.priority = make([]Parser, 0, len(r.parsers))
	for _, p := range r.parsers {
		r.priority = append(r.priority, p)
	}
	sort.Slice(r.priority, func(i, j int) bool {
		return r.priority[i].Priority() > r.priority[j].Priority()
	})
}

func (r *ParserRegistry) Get(path string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.priority {
		if p.CanParse(path) {
			return p
		}
	}
	return nil
}

func (r *ParserRegistry) GetByType(parserType string) Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.parsers[parserType]
}

func (r *ParserRegistry) List() []Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Parser, 0, len(r.parsers))
	for _, p := range r.parsers {
		result = append(result, p)
	}
	return result
}

func (r *ParserRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.parsers))
	for t := range r.parsers {
		types = append(types, t)
	}
	return types
}
