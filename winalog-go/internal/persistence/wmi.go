//go:build windows

package persistence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
)

type WMIPersistenceDetector struct {
	config *DetectorConfig
}

func NewWMIPersistenceDetector() *WMIPersistenceDetector {
	return &WMIPersistenceDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4688, 5861},
		},
	}
}

func (d *WMIPersistenceDetector) Name() string {
	return "wmi_persistence_detector"
}

func (d *WMIPersistenceDetector) GetTechnique() Technique {
	return TechniqueT1546003
}

func (d *WMIPersistenceDetector) RequiresAdmin() bool {
	return true
}

func (d *WMIPersistenceDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	return nil
}

func (d *WMIPersistenceDetector) GetConfig() *DetectorConfig {
	return d.config
}

type CommandLineEventConsumer struct {
	Name        string
	CommandLine string
}

type ActiveScriptEventConsumer struct {
	Name           string
	ScriptFileName string
	ScriptText     string
}

type NTEventLogEventConsumer struct {
	Name     string
	Sources  []string
	Category string
}

type EventFilter struct {
	Name  string
	Query string
}

type FilterToConsumerBinding struct {
	FilterReference   string
	ConsumerReference string
}

type WMIEventConsumer struct {
	Name        string
	Type        string
	CommandLine string
	ScriptFile  string
}

type WMIEventFilter struct {
	Name      string
	Query     string
	Namespace string
}

type WMIBinding struct {
	FilterName   string
	ConsumerName string
	Namespace    string
}

func (d *WMIPersistenceDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	consumers, err := d.enumerateConsumers()
	if err == nil {
		for _, consumer := range consumers {
			det := d.analyzeConsumer(consumer)
			if det != nil {
				detections = append(detections, det)
			}
		}
	}

	filters, err := d.enumerateFilters()
	if err == nil {
		for _, filter := range filters {
			det := d.analyzeFilter(filter)
			if det != nil {
				detections = append(detections, det)
			}
		}
	}

	bindings, err := d.enumerateBindings()
	if err == nil {
		for _, binding := range bindings {
			det := d.analyzeBinding(binding)
			if det != nil {
				detections = append(detections, det)
			}
		}
	}

	return detections, nil
}

func (d *WMIPersistenceDetector) enumerateConsumers() ([]WMIEventConsumer, error) {
	consumers := make([]WMIEventConsumer, 0)

	var cmdConsumers []CommandLineEventConsumer
	err := wmi.QueryNamespace("SELECT Name, CommandLine FROM CommandLineEventConsumer", &cmdConsumers, "root\\subscription")
	if err == nil {
		for _, c := range cmdConsumers {
			consumers = append(consumers, WMIEventConsumer{
				Name:        c.Name,
				Type:        "CommandLineEventConsumer",
				CommandLine: c.CommandLine,
			})
		}
	}

	var scriptConsumers []ActiveScriptEventConsumer
	err = wmi.QueryNamespace("SELECT Name, ScriptFileName, ScriptText FROM ActiveScriptEventConsumer", &scriptConsumers, "root\\subscription")
	if err == nil {
		for _, c := range scriptConsumers {
			consumers = append(consumers, WMIEventConsumer{
				Name:       c.Name,
				Type:       "ActiveScriptEventConsumer",
				ScriptFile: c.ScriptFileName,
			})
		}
	}

	var logConsumers []NTEventLogEventConsumer
	err = wmi.QueryNamespace("SELECT Name, Sources, Category FROM NTEventLogEventConsumer", &logConsumers, "root\\subscription")
	if err == nil {
		for _, c := range logConsumers {
			consumers = append(consumers, WMIEventConsumer{
				Name: c.Name,
				Type: "NTEventLogEventConsumer",
			})
		}
	}

	return consumers, nil
}

func (d *WMIPersistenceDetector) enumerateFilters() ([]WMIEventFilter, error) {
	filters := make([]WMIEventFilter, 0)

	var wmiFilters []EventFilter
	err := wmi.QueryNamespace("SELECT Name, Query FROM __EventFilter", &wmiFilters, "root\\subscription")
	if err != nil {
		return filters, err
	}

	for _, f := range wmiFilters {
		filters = append(filters, WMIEventFilter{
			Name:      f.Name,
			Query:     f.Query,
			Namespace: "Root\\Subscription",
		})
	}

	return filters, nil
}

func (d *WMIPersistenceDetector) enumerateBindings() ([]WMIBinding, error) {
	bindings := make([]WMIBinding, 0)

	var wmiBindings []FilterToConsumerBinding
	err := wmi.QueryNamespace("SELECT FilterReference, ConsumerReference FROM __FilterToConsumerBinding", &wmiBindings, "root\\subscription")
	if err != nil {
		return bindings, err
	}

	for _, b := range wmiBindings {
		filterName := extractWMIPart(b.FilterReference)
		consumerName := extractWMIPart(b.ConsumerReference)

		bindings = append(bindings, WMIBinding{
			FilterName:   filterName,
			ConsumerName: consumerName,
			Namespace:    "Root\\Subscription",
		})
	}

	return bindings, nil
}

func (d *WMIPersistenceDetector) analyzeConsumer(consumer WMIEventConsumer) *Detection {
	if consumer.CommandLine != "" && d.isSuspiciousCommand(consumer.CommandLine) {
		return &Detection{
			Technique:   TechniqueT1546003,
			Category:    "WMI",
			Severity:    SeverityHigh,
			Time:        time.Now(),
			Title:       "Suspicious WMI Command Line Consumer",
			Description: "A WMI event consumer contains a suspicious command: " + consumer.CommandLine,
			Evidence: Evidence{
				Type:    EvidenceTypeWMI,
				Key:     "CommandLineEventConsumer",
				Command: consumer.CommandLine,
			},
			MITRERef:          []string{"T1546.003"},
			RecommendedAction: "Investigate the command and verify if it is legitimate. WMI consumers can be used for persistent code execution.",
			FalsePositiveRisk: "Medium",
		}
	}

	if consumer.ScriptFile != "" {
		return &Detection{
			Technique:   TechniqueT1546003,
			Category:    "WMI",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "WMI Script Consumer Detected",
			Description: "A WMI event consumer is using a script file: " + consumer.ScriptFile,
			Evidence: Evidence{
				Type:    EvidenceTypeWMI,
				Key:     "ActiveScriptEventConsumer",
				Command: consumer.ScriptFile,
			},
			MITRERef:          []string{"T1546.003"},
			RecommendedAction: "Verify the script content and author",
			FalsePositiveRisk: "Medium",
		}
	}

	return nil
}

func (d *WMIPersistenceDetector) analyzeFilter(filter WMIEventFilter) *Detection {
	if filter.Query == "" {
		return nil
	}

	suspiciousKeywords := []string{
		"select * from", "process",
		"logon", "startup",
		"__InstanceModificationEvent",
	}

	queryLower := strings.ToLower(filter.Query)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(queryLower, strings.ToLower(keyword)) {
			return &Detection{
				Technique:   TechniqueT1546003,
				Category:    "WMI",
				Severity:    SeverityLow,
				Time:        time.Now(),
				Title:       "WMI Event Filter with Process/Startup Query",
				Description: "A WMI event filter contains a potentially suspicious query: " + filter.Query,
				Evidence: Evidence{
					Type:  EvidenceTypeWMI,
					Key:   "EventFilter",
					Value: filter.Query,
				},
				MITRERef:          []string{"T1546.003"},
				RecommendedAction: "Verify the filter is legitimate",
				FalsePositiveRisk: "Medium",
			}
		}
	}

	return nil
}

func (d *WMIPersistenceDetector) analyzeBinding(binding WMIBinding) *Detection {
	if binding.FilterName == "" || binding.ConsumerName == "" {
		return nil
	}

	return &Detection{
		Technique:   TechniqueT1546003,
		Category:    "WMI",
		Severity:    SeverityMedium,
		Time:        time.Now(),
		Title:       "WMI Filter-Consumer Binding Detected",
		Description: "A WMI permanent event subscription has been created. Filter: " + binding.FilterName + ", Consumer: " + binding.ConsumerName,
		Evidence: Evidence{
			Type:  EvidenceTypeWMI,
			Key:   "__FilterToConsumerBinding",
			Value: binding.FilterName + " -> " + binding.ConsumerName,
		},
		MITRERef:          []string{"T1546.003"},
		RecommendedAction: "Investigate the WMI subscription to verify if it is legitimate. Permanent WMI subscriptions can provide persistent code execution.",
		FalsePositiveRisk: "Medium",
	}
}

func (d *WMIPersistenceDetector) isSuspiciousCommand(command string) bool {
	commandLower := strings.ToLower(command)

	suspicious := []string{
		"powershell", "cmd.exe", "wscript", "cscript",
		"rundll32", "regsvr32", "mshta",
		"\\\\unc\\", "\\\\127\\",
		"%temp%", "%appdata%",
		"net user", "net localgroup",
		"mimikatz", "pwdump",
		".ps1", ".vbs", ".js",
	}

	for _, indicator := range suspicious {
		if strings.Contains(commandLower, indicator) {
			return true
		}
	}

	return false
}

func CheckWMIPersistence() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewWMIPersistenceDetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}

func extractWMIPart(ref string) string {
	if ref == "" {
		return ""
	}

	parts := strings.Split(ref, "=")
	if len(parts) > 1 {
		return strings.Trim(parts[1], `"'`)
	}

	return ref
}
