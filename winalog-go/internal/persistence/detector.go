//go:build windows

package persistence

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

type DetectorConfig struct {
	Enabled               bool     `json:"enabled"`
	EventIDs              []int32  `json:"event_ids"`
	Paths                 []string `json:"paths,omitempty"`
	Patterns              []string `json:"patterns,omitempty"`
	Whitelist            []string `json:"whitelist,omitempty"`
	BuiltinWhitelist     []string `json:"builtin_whitelist,omitempty"`
	BuiltinDllWhitelist  []string `json:"builtin_dll_whitelist,omitempty"`
	BuiltinClsidsWhitelist []string `json:"builtin_clsids_whitelist,omitempty"`
}

type ConfigurableDetector interface {
	Detector
	SetConfig(config *DetectorConfig) error
	GetConfig() *DetectorConfig
}

type Detector interface {
	Name() string
	Detect(ctx context.Context) ([]*Detection, error)
	RequiresAdmin() bool
	GetTechnique() Technique
}

type DetectorInfo struct {
	Name          string
	Description   string
	Technique     Technique
	RequiresAdmin bool
}

type DetectionEngine struct {
	detectors     map[string]Detector
	configs       map[string]*DetectorConfig
	result        *DetectionResult
	mu            sync.RWMutex
	adminRequired bool
}

func NewDetectionEngine() *DetectionEngine {
	return &DetectionEngine{
		detectors: make(map[string]Detector),
		configs:   make(map[string]*DetectorConfig),
		result:    NewDetectionResult(),
	}
}

func (e *DetectionEngine) Register(d Detector) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detectors[d.Name()] = d
	if d.RequiresAdmin() {
		e.adminRequired = true
	}
}

func (e *DetectionEngine) RegisterAll(detectors []Detector) {
	for _, d := range detectors {
		e.Register(d)
	}
}

func (e *DetectionEngine) Detect(ctx context.Context) *DetectionResult {
	e.mu.Lock()
	detectorCount := len(e.detectors)
	log.Printf("[DEBUG] DetectionEngine.Detect started with %d detectors", detectorCount)

	e.result = NewDetectionResult()

	// 拷贝 detector 引用后立即释放锁
	detectors := make(map[string]Detector, len(e.detectors))
	for k, v := range e.detectors {
		detectors[k] = v
	}
	e.mu.Unlock()

	var wg sync.WaitGroup
	resultChan := make(chan *Detection, 100)
	errorChan := make(chan string, 10)

	for name, d := range detectors {
		wg.Add(1)
		log.Printf("[DEBUG] Running detector: %s", name)
		go func(name string, d Detector) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[ERROR] Detector %s panicked: %v", name, r)
					errorChan <- fmt.Sprintf("%s: panic: %v", name, r)
				}
				wg.Done()
			}()

			detections, err := d.Detect(ctx)
			if err != nil {
				log.Printf("[ERROR] Detector %s failed: %v", name, err)
				errorChan <- fmt.Sprintf("%s: %v", name, err)
				return
			}

			log.Printf("[DEBUG] Detector %s returned %d detections", name, len(detections))

			for _, det := range detections {
				if det.ID == "" {
					det.ID = uuid.New().String()
				}
				if det.Time.IsZero() {
					det.Time = time.Now()
				}
				resultChan <- det
			}
		}(name, d)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// 用局部锁保护 result 写入，不阻塞全局锁
	var resultMu sync.Mutex
	for det := range resultChan {
		resultMu.Lock()
		e.result.Add(det)
		resultMu.Unlock()
	}

	for errMsg := range errorChan {
		resultMu.Lock()
		e.result.Errors = append(e.result.Errors, errMsg)
		e.result.ErrorCount++
		resultMu.Unlock()
	}

	resultMu.Lock()
	e.result.EndTime = time.Now()
	e.result.Duration = e.result.EndTime.Sub(e.result.StartTime)
	resultMu.Unlock()

	log.Printf("[INFO] DetectionEngine.Detect completed: total=%d, errors=%d, duration=%v",
		e.result.TotalCount, e.result.ErrorCount, e.result.Duration)

	return e.result
}

func (e *DetectionEngine) DetectCategory(ctx context.Context, category string) *DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := NewDetectionResult()

	for _, d := range e.detectors {
		detections, err := d.Detect(ctx)
		if err != nil {
			continue
		}

		for _, det := range detections {
			if det.Category == category {
				if det.ID == "" {
					det.ID = uuid.New().String()
				}
				result.Add(det)
			}
		}
	}

	return result
}

func (e *DetectionEngine) DetectTechnique(ctx context.Context, technique Technique) *DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := NewDetectionResult()

	for _, d := range e.detectors {
		if d.GetTechnique() != technique {
			continue
		}

		detections, err := d.Detect(ctx)
		if err != nil {
			continue
		}

		for _, det := range detections {
			if det.ID == "" {
				det.ID = uuid.New().String()
			}
			result.Add(det)
		}
	}

	return result
}

func (e *DetectionEngine) ListDetectors() []DetectorInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	infos := make([]DetectorInfo, 0, len(e.detectors))
	for _, d := range e.detectors {
		infos = append(infos, DetectorInfo{
			Name:          d.Name(),
			Technique:     d.GetTechnique(),
			RequiresAdmin: d.RequiresAdmin(),
		})
	}
	return infos
}

func (e *DetectionEngine) SetDetectorConfig(name string, config *DetectorConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	d, exists := e.detectors[name]
	if !exists {
		return fmt.Errorf("detector not found: %s", name)
	}

	cd, ok := d.(ConfigurableDetector)
	if !ok {
		return fmt.Errorf("detector does not support configuration: %s", name)
	}

	if err := cd.SetConfig(config); err != nil {
		return fmt.Errorf("failed to set config for %s: %w", name, err)
	}

	e.configs[name] = config
	return nil
}

func (e *DetectionEngine) GetDetectorConfig(name string) *DetectorConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if config, exists := e.configs[name]; exists {
		return config
	}

	d, exists := e.detectors[name]
	if !exists {
		return nil
	}

	cd, ok := d.(ConfigurableDetector)
	if !ok {
		return nil
	}

	return cd.GetConfig()
}

func (e *DetectionEngine) GetAllDetectorConfigs() map[string]*DetectorConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	configs := make(map[string]*DetectorConfig)
	for name, d := range e.detectors {
		cd, ok := d.(ConfigurableDetector)
		if ok {
			configs[name] = cd.GetConfig()
		}
	}
	return configs
}

func (e *DetectionEngine) IsDetectorEnabled(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	config, exists := e.configs[name]
	if !exists {
		return true
	}
	return config.Enabled
}

func (e *DetectionEngine) RequiresAdmin() bool {
	return e.adminRequired
}

func (e *DetectionEngine) GetResult() *DetectionResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.result
}

func RunAllDetectors(ctx context.Context) *DetectionResult {
	engine := NewDetectionEngine()
	registerAllDetectors(engine)
	return engine.Detect(ctx)
}

func DetectByCategory(ctx context.Context, category string) *DetectionResult {
	engine := NewDetectionEngine()
	registerAllDetectors(engine)
	return engine.DetectCategory(ctx, category)
}

func DetectByTechnique(ctx context.Context, technique Technique) *DetectionResult {
	engine := NewDetectionEngine()
	registerAllDetectors(engine)
	return engine.DetectTechnique(ctx, technique)
}

func AllDetectors() []Detector {
	return []Detector{
		NewRunKeyDetector(),
		NewUserInitDetector(),
		NewStartupFolderDetector(),
		NewAccessibilityDetector(),
		NewCOMHijackDetector(),
		NewIFEODetector(),
		NewAppInitDetector(),
		NewWMIPersistenceDetector(),
		NewServicePersistenceDetector(),
		NewLSAPersistenceDetector(),
		NewWinsockDetector(),
		NewBHODetector(),
		NewPrintMonitorDetector(),
		NewBootExecuteDetector(),
		NewETWDetector(),
		NewScheduledTaskDetector(),
		NewAppCertDllsDetector(),
	}
}

func registerAllDetectors(engine *DetectionEngine) {
	for _, d := range AllDetectors() {
		engine.Register(d)
	}
}

func RunAllDetectorsWithProgress(ctx context.Context, progressChan chan<- string) *DetectionResult {
	engine := NewDetectionEngine()
	registerAllDetectors(engine)

	detectors := engine.ListDetectors()
	total := len(detectors)

	result := NewDetectionResult()
	var wg sync.WaitGroup
	resultChan := make(chan *Detection, 100)
	errorChan := make(chan string, 10)

	for i, info := range detectors {
		// 在锁内获取 detector 引用，避免并发读 map
		engine.mu.RLock()
		d := engine.detectors[info.Name]
		engine.mu.RUnlock()

		wg.Add(1)
		detectorName := info.Name
		go func(idx int, name string, d Detector) {
			defer wg.Done()

			progressChan <- fmt.Sprintf("Running %s (%d/%d)", name, idx+1, total)

			detections, err := d.Detect(ctx)
			if err != nil {
				errorChan <- fmt.Sprintf("%s: %v", name, err)
				return
			}

			for _, det := range detections {
				if det.ID == "" {
					det.ID = uuid.New().String()
				}
				if det.Time.IsZero() {
					det.Time = time.Now()
				}
				resultChan <- det
			}
		}(i, detectorName, d)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	for det := range resultChan {
		result.Add(det)
	}

	for errMsg := range errorChan {
		result.Errors = append(result.Errors, errMsg)
		result.ErrorCount++
	}

	progressChan <- "complete"
	return result
}
