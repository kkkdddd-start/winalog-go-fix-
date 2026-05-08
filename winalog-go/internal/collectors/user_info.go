//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
	"go.uber.org/zap"
)

type UserInfoCollector struct {
	BaseCollector
}

func NewUserInfoCollector() *UserInfoCollector {
	return &UserInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "user_info",
				Description:   "Collect user account information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *UserInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	users, err := c.collectUserInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(users))
	for i, u := range users {
		interfaces[i] = u
	}
	return interfaces, nil
}

func (c *UserInfoCollector) collectUserInfo() ([]*types.UserAccount, error) {
	users := make([]*types.UserAccount, 0)

	cmd := `Get-LocalUser | Select-Object Name, SID, Enabled, LastLogon, PasswordRequired, PasswordAge, PasswordExpires, FullName, Description, HomeDirectory, ProfilePath | ConvertTo-Json -Compress`

	observability.Info("Collecting local users with command: Get-LocalUser",
		zap.String("module", "user_info"))

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		observability.Warn("Get-LocalUser failed or returned empty, trying alternative method",
			zap.String("module", "user_info"),
			zap.Error(result.Error))
		return c.collectUserInfoAlternative()
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" || output == "[]" {
		observability.Warn("Get-LocalUser returned empty result, trying alternative method",
			zap.String("module", "user_info"))
		return c.collectUserInfoAlternative()
	}

	observability.DebugPrintf("[DEBUG] Get-LocalUser raw output length: %d", len(output))

	var userRawList []struct {
		Name             string      `json:"Name"`
		SID              interface{} `json:"SID"`
		Enabled          bool        `json:"Enabled"`
		LastLogon        string      `json:"LastLogon"`
		PasswordRequired bool        `json:"PasswordRequired"`
		PasswordAge      int64       `json:"PasswordAge"`
		PasswordExpires  string      `json:"PasswordExpires"`
		FullName         string      `json:"FullName"`
		Description      string      `json:"Description"`
		HomeDirectory    string      `json:"HomeDirectory"`
		ProfilePath      string      `json:"ProfilePath"`
	}

	if err := json.Unmarshal([]byte(output), &userRawList); err != nil {
		var single struct {
			Name             string      `json:"Name"`
			SID              interface{} `json:"SID"`
			Enabled          bool        `json:"Enabled"`
			LastLogon        string      `json:"LastLogon"`
			PasswordRequired bool        `json:"PasswordRequired"`
			PasswordAge      int64       `json:"PasswordAge"`
			PasswordExpires  string      `json:"PasswordExpires"`
			FullName         string      `json:"FullName"`
			Description      string      `json:"Description"`
			HomeDirectory    string      `json:"HomeDirectory"`
			ProfilePath      string      `json:"ProfilePath"`
		}
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil && single.Name != "" {
			userRawList = []struct {
				Name             string      `json:"Name"`
				SID              interface{} `json:"SID"`
				Enabled          bool        `json:"Enabled"`
				LastLogon        string      `json:"LastLogon"`
				PasswordRequired bool        `json:"PasswordRequired"`
				PasswordAge      int64       `json:"PasswordAge"`
				PasswordExpires  string      `json:"PasswordExpires"`
				FullName         string      `json:"FullName"`
				Description      string      `json:"Description"`
				HomeDirectory    string      `json:"HomeDirectory"`
				ProfilePath      string      `json:"ProfilePath"`
			}{single}
		} else {
			observability.Warn("Failed to parse user JSON",
				zap.String("module", "user_info"),
				zap.Error(err))
			return c.collectUserInfoAlternative()
		}
	}

	parseCount := 0
	for _, userRaw := range userRawList {
		if userRaw.Name == "" {
			continue
		}

		sidStr := extractSIDValue(userRaw.SID)
		if sidStr == "" {
			observability.Warn("Failed to extract SID value for user",
				zap.String("module", "user_info"),
				zap.String("user", userRaw.Name))
			continue
		}

		user := &types.UserAccount{
			Name:        userRaw.Name,
			SID:         sidStr,
			Enabled:     userRaw.Enabled,
			Type:        "Local",
			LastLogin:   parseLastLogon(userRaw.LastLogon),
			PasswordExp: userRaw.PasswordExpires != "" && userRaw.PasswordExpires != "Never",
			HomeDir:     userRaw.HomeDirectory,
			ProfilePath: userRaw.ProfilePath,
		}

		if userRaw.FullName != "" {
			user.FullName = userRaw.FullName
		} else {
			user.FullName = userRaw.Description
		}

		if userRaw.PasswordAge > 0 {
			user.PasswordAge = time.Duration(userRaw.PasswordAge) * 24 * time.Hour
		}

		users = append(users, user)
		parseCount++
	}

	observability.Info("Get-LocalUser parsed users",
		zap.String("module", "user_info"),
		zap.Int("count", parseCount))

	if parseCount == 0 {
		return c.collectUserInfoAlternative()
	}

	return users, nil
}

func (c *UserInfoCollector) collectUserInfoAlternative() ([]*types.UserAccount, error) {
	users := make([]*types.UserAccount, 0)

	cmd := `Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name, SID, Disabled, LastLogon, Description | ConvertTo-Json -Compress`

	observability.Info("Collecting users with alternative command: Get-WmiObject Win32_UserAccount",
		zap.String("module", "user_info"))

	result := utils.RunPowerShell(cmd)
	if !result.Success() || result.Output == "" {
		observability.Warn("Alternative method also failed",
			zap.String("module", "user_info"),
			zap.Error(result.Error))
		return users, nil
	}

	output := strings.TrimSpace(result.Output)
	if output == "" || output == "null" || output == "[]" {
		observability.Info("Alternative method returned empty result",
			zap.String("module", "user_info"))
		return users, nil
	}

	var userRawList []struct {
		Name        string `json:"Name"`
		SID         string `json:"SID"`
		Disabled    bool   `json:"Disabled"`
		LastLogon   string `json:"LastLogon"`
		Description string `json:"Description"`
	}

	if err := json.Unmarshal([]byte(output), &userRawList); err != nil {
		var single struct {
			Name        string `json:"Name"`
			SID         string `json:"SID"`
			Disabled    bool   `json:"Disabled"`
			LastLogon   string `json:"LastLogon"`
			Description string `json:"Description"`
		}
		if err2 := json.Unmarshal([]byte(output), &single); err2 == nil && single.Name != "" {
			userRawList = []struct {
				Name        string `json:"Name"`
				SID         string `json:"SID"`
				Disabled    bool   `json:"Disabled"`
				LastLogon   string `json:"LastLogon"`
				Description string `json:"Description"`
			}{single}
		}
	}

	parseCount := 0
	for _, userRaw := range userRawList {
		if userRaw.Name == "" {
			continue
		}

		users = append(users, &types.UserAccount{
			Name:        userRaw.Name,
			SID:         userRaw.SID,
			Enabled:     !userRaw.Disabled,
			Type:        "Local",
			LastLogin:   parseLastLogon(userRaw.LastLogon),
			PasswordExp: false,
			FullName:    userRaw.Description,
		})
		parseCount++
	}

	observability.Info("Alternative method parsed users",
		zap.String("module", "user_info"),
		zap.Int("count", parseCount))
	return users, nil
}

func parseLastLogon(lastLogon string) time.Time {
	if lastLogon == "" || lastLogon == "N/A" || lastLogon == "Never" {
		return time.Time{}
	}

	lastLogon = strings.TrimSpace(lastLogon)

	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		time.RFC3339,
		"1/2/2006 3:04:05 PM",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, lastLogon); err == nil {
			return t
		}
	}
	return time.Time{}
}

func extractSIDValue(sid interface{}) string {
	if sid == nil {
		return ""
	}

	switch v := sid.(type) {
	case string:
		return v
	case map[string]interface{}:
		if val, ok := v["Value"].(string); ok {
			return val
		}
		for _, val := range v {
			if s, ok := val.(string); ok {
				return s
			}
		}
	}
	return ""
}

func ListLocalUsers() ([]*types.UserAccount, error) {
	collector := NewUserInfoCollector()
	return collector.collectUserInfo()
}
