package alerts

import (
	"sync"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AlertUpgradeCache struct {
	mu    sync.RWMutex
	rules map[string]*types.AlertUpgradeRule
}

func NewAlertUpgradeCache() *AlertUpgradeCache {
	return &AlertUpgradeCache{
		rules: make(map[string]*types.AlertUpgradeRule),
	}
}

func (c *AlertUpgradeCache) Add(rule *types.AlertUpgradeRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[rule.Name] = rule
}

func (c *AlertUpgradeCache) Check(alert *types.Alert) (bool, *types.AlertUpgradeRule) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, rule := range c.rules {
		if c.matches(rule, alert) {
			return true, rule
		}
	}
	return false, nil
}

func (c *AlertUpgradeCache) matches(rule *types.AlertUpgradeRule, alert *types.Alert) bool {
	if rule.Name != "" && rule.Name != alert.RuleName {
		return false
	}

	if rule.NewSeverity != "" && rule.NewSeverity != alert.Severity {
		return false
	}

	if rule.Threshold > 0 && alert.Count < rule.Threshold {
		return false
	}

	return true
}

func (c *AlertUpgradeCache) Remove(ruleName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rules, ruleName)
}

func (c *AlertUpgradeCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = make(map[string]*types.AlertUpgradeRule)
}

func (c *AlertUpgradeCache) List() []*types.AlertUpgradeRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*types.AlertUpgradeRule, 0, len(c.rules))
	for _, rule := range c.rules {
		result = append(result, rule)
	}
	return result
}

func (c *AlertUpgradeCache) Update(rule *types.AlertUpgradeRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[rule.Name] = rule
}
