package exporters

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AlertExporter struct {
	format string
}

func NewAlertExporter(format string) *AlertExporter {
	return &AlertExporter{format: format}
}

func (e *AlertExporter) Export(alerts []*types.Alert, writer io.Writer) error {
	switch e.format {
	case "csv":
		return e.exportCSV(alerts, writer)
	case "excel", "xlsx":
		return e.exportExcel(alerts, writer)
	case "json":
		return e.exportJSON(alerts, writer)
	default:
		return e.exportJSON(alerts, writer)
	}
}

func (e *AlertExporter) ContentType() string {
	switch e.format {
	case "csv":
		return "text/csv"
	case "excel", "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "json":
		return "application/json"
	default:
		return "application/json"
	}
}

func (e *AlertExporter) FileExtension() string {
	switch e.format {
	case "csv":
		return "csv"
	case "excel", "xlsx":
		return "xlsx"
	case "json":
		return "json"
	default:
		return "json"
	}
}

func (e *AlertExporter) exportCSV(alerts []*types.Alert, writer io.Writer) error {
	w := csv.NewWriter(writer)

	headers := []string{
		"ID",
		"RuleName",
		"Severity",
		"Message",
		"Count",
		"FirstSeen",
		"LastSeen",
		"Resolved",
		"ResolvedTime",
		"Notes",
		"Explanation",
		"Recommendation",
		"RealCase",
		"FalsePositive",
		"MitreAttack",
		"LogName",
		"RuleScore",
		"EventIDs",
		"EventDBIDs",
	}
	if err := w.Write(headers); err != nil {
		return err
	}

	for _, a := range alerts {
		row := []string{
			fmt.Sprintf("%d", a.ID),
			a.RuleName,
			string(a.Severity),
			a.Message,
			fmt.Sprintf("%d", a.Count),
			a.FirstSeen.Format(time.RFC3339),
			a.LastSeen.Format(time.RFC3339),
			fmt.Sprintf("%t", a.Resolved),
			formatTimePtr(a.ResolvedTime),
			a.Notes,
			a.Explanation,
			a.Recommendation,
			a.RealCase,
			fmt.Sprintf("%t", a.FalsePositive),
			strings.Join(a.MITREAttack, ";"),
			a.LogName,
			fmt.Sprintf("%.2f", a.RuleScore),
			formatInt32Slice(a.EventIDs),
			formatInt64Slice(a.EventDBIDs),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}

func (e *AlertExporter) exportJSON(alerts []*types.Alert, writer io.Writer) error {
	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func (e *AlertExporter) exportExcel(alerts []*types.Alert, writer io.Writer) error {
	return fmt.Errorf("excel export not yet implemented for alerts, use csv or json format")
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatInt32Slice(ids []int32) string {
	if len(ids) == 0 {
		return ""
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(strs, ";")
}

func formatInt64Slice(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(strs, ";")
}
