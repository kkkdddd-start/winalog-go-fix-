package exporters

import (
	"io"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Exporter interface {
	Export(events []*types.Event, writer io.Writer) error
	ContentType() string
	FileExtension() string
}

type ExporterFactory struct{}

func (f *ExporterFactory) Create(format string) Exporter {
	switch format {
	case "csv":
		return &CsvExporter{delimiter: ','}
	case "excel", "xlsx":
		return &ExcelExporter{}
	case "json":
		return &JsonExporter{prettyPrint: false}
	case "xml", "evtx":
		return NewEVTXExporter()
	case "timeline-csv":
		return NewTimelineExporter()
	case "timeline-json":
		return NewTimelineJSONExporter()
	case "timeline-html":
		return NewTimelineHTMLExporter()
	default:
		return &JsonExporter{prettyPrint: false}
	}
}
