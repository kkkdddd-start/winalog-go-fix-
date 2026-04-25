package collectors

import (
	"context"
	"os"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type EnvInfoCollector struct {
	BaseCollector
}

func NewEnvInfoCollector() *EnvInfoCollector {
	return &EnvInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "env_info",
				Description:   "Collect environment variables",
				RequiresAdmin: false,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *EnvInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	envVars, err := c.collectEnvInfo()
	if err != nil {
		return nil, err
	}

	interfaces := make([]interface{}, len(envVars))
	for i, e := range envVars {
		interfaces[i] = e
	}
	return interfaces, nil
}

func (c *EnvInfoCollector) collectEnvInfo() ([]*types.EnvInfo, error) {
	envVars := make([]*types.EnvInfo, 0)

	importantVars := []string{
		"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR",
		"TEMP", "TMP", "USERPROFILE", "USERNAME",
		"LOGONSERVER", "USERDOMAIN", "COMPUTERNAME",
		"PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
		"OS", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
	}

	for _, name := range importantVars {
		value := os.Getenv(name)
		if value != "" {
			envVar := &types.EnvInfo{
				Key:   name,
				Value: value,
				Type:  "User",
			}
			envVars = append(envVars, envVar)
		}
	}

	return envVars, nil
}

type EnvVariable struct {
	Name  string
	Value string
	Type  string
}

func ListEnvironmentVariables() ([]EnvVariable, error) {
	env := os.Environ()
	vars := make([]EnvVariable, 0, len(env))

	for _, e := range env {
		parts := splitEnvVar(e)
		if len(parts) == 2 {
			vars = append(vars, EnvVariable{
				Name:  parts[0],
				Value: parts[1],
				Type:  "User",
			})
		}
	}

	return vars, nil
}

func splitEnvVar(e string) []string {
	for i := 0; i < len(e); i++ {
		if e[i] == '=' {
			return []string{e[:i], e[i+1:]}
		}
	}
	return nil
}

func GetEnvironmentVariable(name string) (string, error) {
	return os.Getenv(name), nil
}

func SetEnvironmentVariable(name, value string) error {
	return os.Setenv(name, value)
}

func CollectEnvInfo(ctx context.Context) ([]*types.EnvInfo, error) {
	collector := NewEnvInfoCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, err
	}

	envVars := make([]*types.EnvInfo, 0, len(results))
	for _, r := range results {
		if e, ok := r.(*types.EnvInfo); ok {
			envVars = append(envVars, e)
		}
	}
	return envVars, nil
}
