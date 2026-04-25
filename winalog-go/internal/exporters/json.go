package exporters

import (
	"encoding/json"
	"io"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type JsonExporter struct {
	prettyPrint bool
}

func NewJsonExporter(prettyPrint bool) *JsonExporter {
	return &JsonExporter{prettyPrint: prettyPrint}
}

func (e *JsonExporter) Export(events []*types.Event, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	if e.prettyPrint {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(events)
}

func (e *JsonExporter) ContentType() string {
	return "application/json"
}

func (e *JsonExporter) FileExtension() string {
	return "json"
}
