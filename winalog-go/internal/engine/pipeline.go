package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Pipeline struct {
	workers    int
	batchSize  int
	eventChan  chan *types.Event
	errorChan  chan error
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	processed  int64
	failed     int64
}

type PipelineConfig struct {
	Workers    int
	BatchSize  int
	BufferSize int
}

type PipelineResult struct {
	TotalProcessed int64
	TotalFailed    int64
	Errors         []error
}

func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10000
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 100000
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Pipeline{
		workers:   cfg.Workers,
		batchSize: cfg.BatchSize,
		eventChan: make(chan *types.Event, cfg.BufferSize),
		errorChan: make(chan error, 100),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (p *Pipeline) Start(eventHandler func([]*types.Event) error) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i, eventHandler)
	}
}

func (p *Pipeline) worker(id int, handler func([]*types.Event) error) {
	defer p.wg.Done()

	batch := make([]*types.Event, 0, p.batchSize)
	ticker := newPacer()
	defer func() {
		if ticker.stopCh != nil {
			close(ticker.stopCh)
		}
	}()

	for {
		select {
		case <-p.ctx.Done():
			if len(batch) > 0 {
				if err := handler(batch); err != nil {
					for range batch {
						p.errorChan <- err
						atomic.AddInt64(&p.failed, 1)
					}
				}
			}
			return

		case event, ok := <-p.eventChan:
			if !ok {
				if len(batch) > 0 {
					if err := handler(batch); err != nil {
						for range batch {
							p.errorChan <- err
							atomic.AddInt64(&p.failed, 1)
						}
					}
				}
				return
			}

			batch = append(batch, event)
			atomic.AddInt64(&p.processed, 1)

			if len(batch) >= p.batchSize {
				if err := handler(batch); err != nil {
					for range batch {
						p.errorChan <- err
						atomic.AddInt64(&p.failed, 1)
					}
				}
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				if err := handler(batch); err != nil {
					for range batch {
						p.errorChan <- err
						atomic.AddInt64(&p.failed, 1)
					}
				}
				batch = batch[:0]
			}
		}
	}
}

type pacer struct {
	C      <-chan struct{}
	stopCh chan struct{}
}

func newPacer() *pacer {
	c := make(chan struct{}, 1)
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case c <- struct{}{}:
				default:
				}
			case <-stopCh:
				return
			}
		}
	}()
	return &pacer{C: c, stopCh: stopCh}
}

func (p *Pipeline) Submit(event *types.Event) bool {
	select {
	case p.eventChan <- event:
		return true
	case <-p.ctx.Done():
		return false
	default:
		return false
	}
}

func (p *Pipeline) SubmitBatch(events []*types.Event) int {
	submitted := 0
	for _, event := range events {
		if p.Submit(event) {
			submitted++
		}
	}
	return submitted
}

func (p *Pipeline) Stop() {
	p.cancel()
	close(p.eventChan)
	p.wg.Wait()
	close(p.errorChan)
}

func (p *Pipeline) Wait() {
	p.wg.Wait()
}

func (p *Pipeline) GetResult() *PipelineResult {
	return &PipelineResult{
		TotalProcessed: atomic.LoadInt64(&p.processed),
		TotalFailed:    atomic.LoadInt64(&p.failed),
		Errors:         p.collectErrors(),
	}
}

func (p *Pipeline) collectErrors() []error {
	var errors []error
	for {
		select {
		case err := <-p.errorChan:
			errors = append(errors, err)
		default:
			return errors
		}
	}
}

func (p *Pipeline) IsCancelled() bool {
	return p.ctx.Err() != nil
}
