package exporters

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type CsvExporter struct {
	delimiter rune
}

func NewCsvExporter() *CsvExporter {
	return &CsvExporter{delimiter: ','}
}

func (e *CsvExporter) Export(events []*types.Event, writer io.Writer) error {
	w := csv.NewWriter(writer)
	w.Comma = e.delimiter

	headers := []string{
		"ID",
		"Timestamp",
		"EventID",
		"Level",
		"Source",
		"LogName",
		"Computer",
		"User",
		"UserSID",
		"Message",
		"SessionID",
		"IPAddress",
		"ImportTime",
	}
	if err := w.Write(headers); err != nil {
		return err
	}

	for _, event := range events {
		row := []string{
			fmt.Sprintf("%d", event.ID),
			event.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", event.EventID),
			event.Level.String(),
			event.Source,
			event.LogName,
			event.Computer,
			nilToString(event.User),
			nilToString(event.UserSID),
			event.Message,
			nilToString(event.SessionID),
			nilToString(event.IPAddress),
			event.ImportTime.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}

func (e *CsvExporter) ContentType() string {
	return "text/csv"
}

func (e *CsvExporter) FileExtension() string {
	return "csv"
}

func nilToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
