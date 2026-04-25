package persistence

import (
	"fmt"
	"strings"
)

func EscapeCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

func ExportDetectionsToCSV(detections []*Detection) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString("ID,Time,Technique,Category,Severity,Title,Description,Key,Value,FilePath,RecommendedAction\n")

	for _, det := range detections {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			det.ID,
			det.Time.Format("2006-01-02 15:04:05"),
			det.Technique,
			det.Category,
			det.Severity,
			EscapeCSV(det.Title),
			EscapeCSV(det.Description),
			EscapeCSV(det.Evidence.Key),
			EscapeCSV(det.Evidence.Value),
			EscapeCSV(det.Evidence.FilePath),
			EscapeCSV(det.RecommendedAction),
		))
	}

	return []byte(sb.String()), nil
}

func ExportDetectionsToCSVString(detections []*Detection) string {
	data, err := ExportDetectionsToCSV(detections)
	if err != nil {
		return ""
	}
	return string(data)
}
