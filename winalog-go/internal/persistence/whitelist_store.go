package persistence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type WhitelistStore struct {
	mu       sync.RWMutex
	dir      string
	data     map[string]*UserWhitelistConfig
	filePath string
}

type UserWhitelistConfig struct {
	UserWhitelist        []string `json:"user_whitelist"`
	BuiltinDllWhitelist  []string `json:"builtin_dll_whitelist,omitempty"`
	BuiltinClsidsWhitelist []string `json:"builtin_clsids_whitelist,omitempty"`
}

var defaultWhitelistStore *WhitelistStore
var storeOnce sync.Once

func GetWhitelistStore() *WhitelistStore {
	storeOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dir := filepath.Join(home, ".winalog")
		defaultWhitelistStore = &WhitelistStore{
			dir:      dir,
			filePath: filepath.Join(dir, "whitelist.json"),
			data:     make(map[string]*UserWhitelistConfig),
		}
		defaultWhitelistStore.Load()
	})
	return defaultWhitelistStore
}

func (s *WhitelistStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &s.data)
}

func (s *WhitelistStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0644)
}

func (s *WhitelistStore) Get(detectorName string) *UserWhitelistConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if cfg, exists := s.data[detectorName]; exists {
		return cfg
	}
	return nil
}

func (s *WhitelistStore) Set(detectorName string, cfg *UserWhitelistConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[detectorName] = cfg
	return s.Save()
}

func (s *WhitelistStore) GetUserWhitelist(detectorName string) []string {
	cfg := s.Get(detectorName)
	if cfg == nil {
		return nil
	}
	return cfg.UserWhitelist
}

func (s *WhitelistStore) SetUserWhitelist(detectorName string, whitelist []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.data[detectorName]
	if cfg == nil {
		cfg = &UserWhitelistConfig{}
		s.data[detectorName] = cfg
	}
	cfg.UserWhitelist = whitelist

	return s.Save()
}

func (s *WhitelistStore) GetBuiltinDllWhitelist(detectorName string) []string {
	cfg := s.Get(detectorName)
	if cfg == nil {
		return nil
	}
	return cfg.BuiltinDllWhitelist
}

func (s *WhitelistStore) SetBuiltinDllWhitelist(detectorName string, whitelist []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.data[detectorName]
	if cfg == nil {
		cfg = &UserWhitelistConfig{}
		s.data[detectorName] = cfg
	}
	cfg.BuiltinDllWhitelist = whitelist

	return s.Save()
}

func (s *WhitelistStore) GetBuiltinClsidsWhitelist(detectorName string) []string {
	cfg := s.Get(detectorName)
	if cfg == nil {
		return nil
	}
	return cfg.BuiltinClsidsWhitelist
}

func (s *WhitelistStore) SetBuiltinClsidsWhitelist(detectorName string, whitelist []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.data[detectorName]
	if cfg == nil {
		cfg = &UserWhitelistConfig{}
		s.data[detectorName] = cfg
	}
	cfg.BuiltinClsidsWhitelist = whitelist

	return s.Save()
}