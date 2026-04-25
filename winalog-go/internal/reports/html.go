package reports

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/reports/template"
	"github.com/kkkdddd-start/winalog-go/internal/version"
)

type HTMLReport struct {
	*Report
}

func NewHTMLReport(report *Report) *HTMLReport {
	return &HTMLReport{Report: report}
}

func (r *HTMLReport) Write(w io.Writer) error {
	tmpl, err := template.GetReportTemplate()
	if err != nil {
		return fmt.Errorf("failed to load template: %w", err)
	}

	data := struct {
		*Report
		GeneratedAtStr string
		StartTimeStr   string
		EndTimeStr     string
		Version        string
	}{
		Report:         r.Report,
		GeneratedAtStr: r.Report.GeneratedAt.Format(time.RFC1123),
		StartTimeStr:   r.Report.TimeRange.Start.Format(time.RFC1123),
		EndTimeStr:     r.Report.TimeRange.End.Format(time.RFC1123),
		Version:        version.Version,
	}

	return tmpl.ExecuteTemplate(w, "report", data)
}

type HTMLExporter struct {
	generator *Generator
}

func NewHTMLExporter(generator *Generator) *HTMLExporter {
	return &HTMLExporter{generator: generator}
}

func (e *HTMLExporter) Export(req *ReportRequest, w io.Writer) error {
	report, err := e.generator.Generate(req)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	htmlReport := NewHTMLReport(report)
	return htmlReport.Write(w)
}

func (e *HTMLExporter) ExportToFile(req *ReportRequest, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	return e.Export(req, file)
}
