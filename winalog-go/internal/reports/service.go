package reports

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jung-kurt/gofpdf"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type ReportService struct {
	db        *storage.DB
	generator *Generator
}

func NewReportService(db *storage.DB) *ReportService {
	return &ReportService{
		db:        db,
		generator: NewGenerator(db),
	}
}

func (s *ReportService) Generate(req *ReportRequest) (*Report, error) {
	return s.generator.Generate(req)
}

func (s *ReportService) ExportHTML(req *ReportRequest, w io.Writer) error {
	report, err := s.Generate(req)
	if err != nil {
		return err
	}

	return s.ExportHTMLFromReport(report, w)
}

func (s *ReportService) ExportHTMLFromReport(report *Report, w io.Writer) error {
	htmlReport := NewHTMLReport(report)
	return htmlReport.Write(w)
}

func (s *ReportService) ExportJSON(req *ReportRequest) ([]byte, error) {
	report, err := s.Generate(req)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(report, "", "  ")
}

func (s *ReportService) ExportPDF(req *ReportRequest, w io.Writer) error {
	report, err := s.Generate(req)
	if err != nil {
		return err
	}

	return generatePDF(report, w)
}

func (s *ReportService) GenerateAsync(req *ReportRequest, callback func(*Report, error)) {
	go func() {
		report, err := s.Generate(req)
		callback(report, err)
	}()
}

func (s *ReportService) GenerateAsyncWithContext(ctx context.Context, req *ReportRequest, callback func(*Report, error)) {
	go func() {
		report, err := s.generator.GenerateWithContext(ctx, req)
		callback(report, err)
	}()
}

func generatePDF(report *Report, w io.Writer) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	pdf.SetFillColor(22, 33, 62)
	pdf.Rect(0, 0, 210, 40, "F")
	pdf.SetTextColor(0, 217, 255)
	pdf.SetFont("Arial", "B", 20)
	pdf.SetXY(15, 12)
	pdf.Cell(180, 10, report.Title)

	pdf.SetTextColor(136, 136, 136)
	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(15, 28)
	pdf.Cell(180, 6, fmt.Sprintf("Generated: %s", report.GeneratedAt.Format("2006-01-02 15:04:05")))

	pdf.SetTextColor(51, 51, 51)
	pdf.SetY(50)

	if report.Summary.TotalEvents > 0 {
		addSummaryToPDF(pdf, report.Summary)
	}

	if len(report.TopAlerts) > 0 {
		addAlertsToPDF(pdf, report.TopAlerts)
	}

	return pdf.Output(w)
}

func addSummaryToPDF(pdf *gofpdf.Fpdf, summary ReportSummary) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 217, 255)
	pdf.Cell(0, 10, "Security Summary")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(51, 51, 51)

	metrics := []struct {
		label string
		value int64
	}{
		{"Total Events", summary.TotalEvents},
		{"Total Alerts", summary.TotalAlerts},
		{"Critical Events", summary.CriticalEvents},
		{"High Alerts", summary.HighAlerts},
	}

	for _, m := range metrics {
		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(60, 7, m.label+":")
		pdf.SetFont("Arial", "", 10)
		pdf.Cell(0, 7, fmt.Sprintf("%d", m.value))
		pdf.Ln(7)
	}
	pdf.Ln(5)
}

func addAlertsToPDF(pdf *gofpdf.Fpdf, alerts []*types.Alert) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 217, 255)
	pdf.Cell(0, 10, "Alert Details")
	pdf.Ln(12)

	tableWidth := []float64{25, 40, 25, 70}
	headers := []string{"Severity", "Rule Name", "Count", "Message"}

	pdf.SetFont("Arial", "B", 9)
	pdf.SetFillColor(0, 217, 255)
	pdf.SetTextColor(255, 255, 255)
	for i, h := range headers {
		pdf.Cell(tableWidth[i], 8, h)
	}
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(51, 51, 51)
	fill := false
	for i, alert := range alerts {
		if i >= 20 {
			pdf.Cell(0, 7, "... and more alerts")
			break
		}
		if fill {
			pdf.SetFillColor(245, 245, 245)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.Cell(tableWidth[0], 6, string(alert.Severity))
		pdf.Cell(tableWidth[1], 6, truncateString(alert.RuleName, 25))
		pdf.Cell(tableWidth[2], 6, fmt.Sprintf("%d", alert.Count))
		pdf.Cell(tableWidth[3], 6, truncateString(alert.Message, 45))
		pdf.Ln(6)
		fill = !fill
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

type APIReportRequest struct {
	Type         string
	Format       string
	Language     string
	StartTime    string
	EndTime      string
	IncludeRaw   bool
	IncludeIOC   bool
	IncludeMITRE bool
	Compression  bool
	Title        string
	Description  string
}

func (s *ReportService) GenerateFromAPIRequest(apiReq *APIReportRequest) (*Report, error) {
	req := &ReportRequest{
		Type:         apiReq.Type,
		Title:        apiReq.Title,
		Format:       ReportFormat(apiReq.Format),
		Language:     apiReq.Language,
		IncludeRaw:   apiReq.IncludeRaw,
		IncludeIOC:   apiReq.IncludeIOC,
		IncludeMITRE: apiReq.IncludeMITRE,
	}

	if apiReq.StartTime != "" || apiReq.EndTime != "" {
		timeInput := apiReq.StartTime
		if apiReq.EndTime != "" {
			timeInput = apiReq.StartTime + "," + apiReq.EndTime
		}
		if tf, err := types.ParseTimeFilter(timeInput); err == nil && tf != nil {
			req.StartTime = tf.Start
			req.EndTime = tf.End
		}
	}

	return s.Generate(req)
}
