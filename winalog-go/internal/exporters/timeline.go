package exporters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/timeline"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type TimelineExporter struct {
	includeRaw   bool
	includeMITRE bool
	delimiter    rune
}

func NewTimelineExporter() *TimelineExporter {
	return &TimelineExporter{
		includeRaw:   false,
		includeMITRE: true,
		delimiter:    ',',
	}
}

func (e *TimelineExporter) SetDelimiter(d rune) {
	e.delimiter = d
}

func (e *TimelineExporter) SetIncludeRaw(include bool) {
	e.includeRaw = include
}

func (e *TimelineExporter) SetIncludeMITRE(include bool) {
	e.includeMITRE = include
}

func (e *TimelineExporter) Export(events []*types.Event, writer io.Writer) error {
	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)

	tl, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build timeline: %w", err)
	}

	return e.exportTimeline(tl, writer)
}

func (e *TimelineExporter) exportTimeline(tl *timeline.Timeline, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	csvWriter.Comma = e.delimiter

	header := e.getHeader()
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	for _, entry := range tl.Entries {
		row := e.entryToRow(entry)
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func (e *TimelineExporter) getHeader() []string {
	header := []string{
		"ID",
		"Timestamp",
		"EventID",
		"Level",
		"Category",
		"Source",
		"LogName",
		"Computer",
		"User",
		"Message",
		"AttackChain",
	}
	if e.includeMITRE {
		header = append(header, "MITREAttack")
	}
	if e.includeRaw {
		header = append(header, "RawXML")
	}
	return header
}

func (e *TimelineExporter) entryToRow(entry *timeline.TimelineEntry) []string {
	row := []string{
		fmt.Sprintf("%d", entry.ID),
		entry.Timestamp.Format(time.RFC3339),
		fmt.Sprintf("%d", entry.EventID),
		entry.Level,
		entry.Category,
		entry.Source,
		entry.LogName,
		entry.Computer,
		entry.User,
		entry.Message,
		entry.AttackChain,
	}
	if e.includeMITRE {
		row = append(row, strings.Join(entry.MITREAttack, ";"))
	}
	if e.includeRaw {
		row = append(row, entry.RawXML)
	}
	return row
}

func (e *TimelineExporter) ContentType() string {
	return "text/csv"
}

func (e *TimelineExporter) FileExtension() string {
	return "csv"
}

type TimelineJSONExporter struct {
	includeRaw   bool
	includeMITRE bool
	prettyPrint  bool
}

func NewTimelineJSONExporter() *TimelineJSONExporter {
	return &TimelineJSONExporter{
		includeRaw:   false,
		includeMITRE: true,
		prettyPrint:  true,
	}
}

func (e *TimelineJSONExporter) Export(events []*types.Event, writer io.Writer) error {
	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)

	tl, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build timeline: %w", err)
	}

	visualizer := timeline.NewTimelineVisualizer(tl)
	return visualizer.Export(timeline.FormatTimelineJSON, writer)
}

func (e *TimelineJSONExporter) ContentType() string {
	return "application/json"
}

func (e *TimelineJSONExporter) FileExtension() string {
	return "json"
}

type TimelineHTMLExporter struct{}

func NewTimelineHTMLExporter() *TimelineHTMLExporter {
	return &TimelineHTMLExporter{}
}

func (e *TimelineHTMLExporter) Export(events []*types.Event, writer io.Writer) error {
	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)

	tl, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build timeline: %w", err)
	}

	visualizer := timeline.NewTimelineVisualizer(tl)
	return visualizer.Export(timeline.FormatTimelineHTML, writer)
}

func (e *TimelineHTMLExporter) ContentType() string {
	return "text/html"
}

func (e *TimelineHTMLExporter) FileExtension() string {
	return "html"
}
