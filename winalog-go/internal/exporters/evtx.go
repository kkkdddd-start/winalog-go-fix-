package exporters

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type EVTXExporter struct{}

func NewEVTXExporter() *EVTXExporter {
	return &EVTXExporter{}
}

func (e *EVTXExporter) Export(events []*types.Event, writer io.Writer) error {
	writer.Write([]byte(strings.Repeat("#", 80) + "\n"))
	writer.Write([]byte("# WinLogAnalyzer EVTX Export\n"))
	writer.Write([]byte(fmt.Sprintf("# Exported at: %s\n", time.Now().Format(time.RFC3339))))
	writer.Write([]byte(fmt.Sprintf("# Total Events: %d\n", len(events))))
	writer.Write([]byte(strings.Repeat("#", 80) + "\n\n"))

	writer.Write([]byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"))
	writer.Write([]byte("<Events>\n"))

	for _, event := range events {
		fmt.Fprintf(writer, "  <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n")
		fmt.Fprintf(writer, "    <System>\n")
		fmt.Fprintf(writer, "      <Provider Name=\"%s\"/>\n", escapeXML(event.Source))
		fmt.Fprintf(writer, "      <EventID>%d</EventID>\n", event.EventID)
		fmt.Fprintf(writer, "      <Level>%s</Level>\n", levelToString(event.Level))
		fmt.Fprintf(writer, "      <Computer>%s</Computer>\n", escapeXML(event.Computer))
		fmt.Fprintf(writer, "      <TimeCreated SystemTime=\"%s\"/>\n", event.Timestamp.Format(time.RFC3339))
		if event.UserSID != nil {
			fmt.Fprintf(writer, "      <Security UserID=\"%s\"/>\n", escapeXML(*event.UserSID))
		}
		fmt.Fprintf(writer, "    </System>\n")
		fmt.Fprintf(writer, "    <EventData>\n")
		fmt.Fprintf(writer, "      <Data Name=\"Message\">%s</Data>\n", escapeXML(event.Message))
		if event.IPAddress != nil {
			fmt.Fprintf(writer, "      <Data Name=\"IpAddress\">%s</Data>\n", escapeXML(*event.IPAddress))
		}
		if event.User != nil {
			fmt.Fprintf(writer, "      <Data Name=\"User\">%s</Data>\n", escapeXML(*event.User))
		}
		fmt.Fprintf(writer, "      <Data Name=\"LogName\">%s</Data>\n", escapeXML(event.LogName))
		if event.SessionID != nil {
			fmt.Fprintf(writer, "      <Data Name=\"SessionID\">%s</Data>\n", escapeXML(*event.SessionID))
		}
		fmt.Fprintf(writer, "    </EventData>\n")
		fmt.Fprintf(writer, "  </Event>\n")
	}

	writer.Write([]byte("</Events>\n"))
	return nil
}

func (e *EVTXExporter) ContentType() string {
	return "application/xml"
}

func (e *EVTXExporter) FileExtension() string {
	return "xml"
}

func (e *EVTXExporter) ExportToCSV(events []*types.Event, writer io.Writer) error {
	writer.Write([]byte("EventID,Timestamp,Level,Source,LogName,Computer,User,Message\n"))

	for _, event := range events {
		user := ""
		if event.User != nil {
			user = *event.User
		}

		timestamp := event.Timestamp.Format("2006-01-02 15:04:05")
		message := strings.ReplaceAll(event.Message, "\"", "\"\"")
		message = strings.ReplaceAll(message, "\n", " ")
		message = strings.ReplaceAll(message, "\r", "")

		fmt.Fprintf(writer, "%d,%s,%s,%s,%s,%s,%s,\"%s\"\n",
			event.EventID,
			timestamp,
			event.Level.String(),
			event.Source,
			event.LogName,
			event.Computer,
			user,
			message)
	}

	return nil
}

func levelToString(level types.EventLevel) string {
	switch level {
	case types.EventLevelCritical:
		return "1"
	case types.EventLevelError:
		return "2"
	case types.EventLevelWarning:
		return "3"
	case types.EventLevelInfo:
		return "4"
	default:
		return "5"
	}
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}
