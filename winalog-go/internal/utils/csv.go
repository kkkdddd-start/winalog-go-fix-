package utils

import (
	"strings"
)

func EscapeCSV(s string) string {
	s = strings.ReplaceAll(s, "\"", "\"\"")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
