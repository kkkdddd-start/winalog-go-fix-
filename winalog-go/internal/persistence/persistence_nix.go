//go:build !windows

package persistence

import (
	"context"
	"fmt"
	"sync"
)

type DetectorConfig struct {
	Enabled               bool
	EventIDs              []int32
	Paths                []string
	Patterns             []string
	Whitelist            []string
	BuiltinWhitelist     []string
	BuiltinDllWhitelist  []string
	BuiltinClsidsWhitelist []string
}

type Detector interface {
	Name() string
	Detect(ctx context.Context) ([]*Detection, error)
	RequiresAdmin() bool
	GetTechnique() Technique
}

type ConfigurableDetector interface {
	Detector
	SetConfig(config *DetectorConfig) error
	GetConfig() *DetectorConfig
}

type DetectorInfo struct {
	Name          string
	Description   string
	Technique     Technique
	RequiresAdmin bool
}

type DetectionEngine struct {
	mu sync.RWMutex
}

func NewDetectionEngine() *DetectionEngine {
	return &DetectionEngine{}
}

func (e *DetectionEngine) Detect(ctx context.Context) *DetectionResult {
	return NewDetectionResult()
}

func (e *DetectionEngine) DetectCategory(ctx context.Context, category string) *DetectionResult {
	return NewDetectionResult()
}

func (e *DetectionEngine) DetectTechnique(ctx context.Context, technique Technique) *DetectionResult {
	return NewDetectionResult()
}

func (e *DetectionEngine) Register(d Detector) {}

func (e *DetectionEngine) RegisterAll(detectors []Detector) {}

func (e *DetectionEngine) ListDetectors() []DetectorInfo {
	return nil
}

func (e *DetectionEngine) SetDetectorConfig(name string, config *DetectorConfig) error {
	return fmt.Errorf("not supported on this platform")
}

func (e *DetectionEngine) GetDetectorConfig(name string) *DetectorConfig {
	return nil
}

func (e *DetectionEngine) GetAllDetectorConfigs() map[string]*DetectorConfig {
	return make(map[string]*DetectorConfig)
}

func RunAllDetectors(ctx context.Context) *DetectionResult {
	return NewDetectionResult()
}

func DetectByCategory(ctx context.Context, category string) *DetectionResult {
	return NewDetectionResult()
}

func DetectByTechnique(ctx context.Context, technique Technique) *DetectionResult {
	return NewDetectionResult()
}

func AllDetectors() []Detector {
	return nil
}
