package monitor

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const DefaultPollInterval = 5 * time.Second

type ConfigManager struct {
	mu              sync.RWMutex
	config          *MonitorConfig
	configPath      string
	changeCallbacks []func(*MonitorConfig)
}

func NewConfigManager(configPath string) *ConfigManager {
	cfg := &ConfigManager{
		configPath: configPath,
	}
	cfg.config = cfg.load()
	if cfg.config == nil {
		cfg.config = &MonitorConfig{
			ProcessEnabled: false,
			NetworkEnabled: false,
			PollInterval:   DefaultPollInterval,
		}
	}
	return cfg
}

func (cm *ConfigManager) load() *MonitorConfig {
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return nil
	}

	var config MonitorConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	if config.PollInterval == 0 {
		config.PollInterval = DefaultPollInterval
	}

	return &config
}

func (cm *ConfigManager) save() error {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cm.configPath, data, 0644)
}

func (cm *ConfigManager) Get() *MonitorConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	config := *cm.config
	return &config
}

func (cm *ConfigManager) Update(newConfig *MonitorConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if newConfig.PollInterval > 0 {
		cm.config.PollInterval = newConfig.PollInterval
	}

	if newConfig.ProcessEnabled {
		cm.config.ProcessEnabled = true
	} else {
		cm.config.ProcessEnabled = false
	}
	if newConfig.NetworkEnabled {
		cm.config.NetworkEnabled = true
	} else {
		cm.config.NetworkEnabled = false
	}

	if err := cm.save(); err != nil {
		return err
	}

	for _, cb := range cm.changeCallbacks {
		cb(cm.config)
	}

	return nil
}

func (cm *ConfigManager) UpdateFromRequest(req *MonitorConfigRequest) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if req.ProcessEnabled != nil {
		cm.config.ProcessEnabled = *req.ProcessEnabled
	}
	if req.NetworkEnabled != nil {
		cm.config.NetworkEnabled = *req.NetworkEnabled
	}
	if req.PollInterval != nil {
		interval := time.Duration(*req.PollInterval) * time.Second
		if interval > 0 {
			cm.config.PollInterval = interval
		}
	}

	if err := cm.save(); err != nil {
		return err
	}

	for _, cb := range cm.changeCallbacks {
		cb(cm.config)
	}

	return nil
}

func (cm *ConfigManager) OnConfigChange(callback func(*MonitorConfig)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.changeCallbacks = append(cm.changeCallbacks, callback)
}

type MonitorConfigRequest struct {
	ProcessEnabled *bool `json:"process_enabled,omitempty"`
	NetworkEnabled *bool `json:"network_enabled,omitempty"`
	PollInterval   *int  `json:"poll_interval,omitempty"`
}
