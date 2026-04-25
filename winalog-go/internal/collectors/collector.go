package collectors

import (
	"context"
	"fmt"
	"time"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]interface{}, error)
	RequiresAdmin() bool
}

type CollectorInfo struct {
	Name          string
	Description   string
	RequiresAdmin bool
	Version       string
}

type BaseCollector struct {
	info CollectorInfo
}

func (c *BaseCollector) Name() string {
	return c.info.Name
}

func (c *BaseCollector) RequiresAdmin() bool {
	return c.info.RequiresAdmin
}

type CollectResult struct {
	Collector string
	Data      []interface{}
	Duration  time.Duration
	Error     error
	Timestamp time.Time
}

func NewCollectResult(collector string, data []interface{}, duration time.Duration, err error) *CollectResult {
	return &CollectResult{
		Collector: collector,
		Data:      data,
		Duration:  duration,
		Error:     err,
		Timestamp: time.Now(),
	}
}

type MultiCollector struct {
	collectors []Collector
}

func NewMultiCollector(collectors ...Collector) *MultiCollector {
	return &MultiCollector{
		collectors: collectors,
	}
}

func (mc *MultiCollector) Add(c Collector) {
	mc.collectors = append(mc.collectors, c)
}

func (mc *MultiCollector) Collect(ctx context.Context) ([]*CollectResult, error) {
	results := make([]*CollectResult, 0, len(mc.collectors))

	for _, c := range mc.collectors {
		start := time.Now()
		data, err := c.Collect(ctx)
		results = append(results, NewCollectResult(c.Name(), data, time.Since(start), err))
	}

	return results, nil
}

func (mc *MultiCollector) CollectParallel(ctx context.Context, workers int) ([]*CollectResult, error) {
	if workers <= 0 {
		workers = len(mc.collectors)
	}

	type result struct {
		res *CollectResult
		err error
	}

	resultChan := make(chan result, len(mc.collectors))
	sem := make(chan struct{}, workers)

	for _, c := range mc.collectors {
		go func(collector Collector) {
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			data, err := collector.Collect(ctx)
			resultChan <- result{
				res: NewCollectResult(collector.Name(), data, time.Since(start), err),
				err: err,
			}
		}(c)
	}

	var results []*CollectResult
	var errs []error
	for i := 0; i < len(mc.collectors); i++ {
		r := <-resultChan
		if r.res != nil {
			results = append(results, r.res)
		}
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}

	close(resultChan)

	if len(errs) > 0 {
		return results, fmt.Errorf("%d collectors failed: %v", len(errs), errs)
	}
	return results, nil
}

func (mc *MultiCollector) List() []CollectorInfo {
	infos := make([]CollectorInfo, 0, len(mc.collectors))
	for _, c := range mc.collectors {
		infos = append(infos, CollectorInfo{
			Name:          c.Name(),
			RequiresAdmin: c.RequiresAdmin(),
		})
	}
	return infos
}
