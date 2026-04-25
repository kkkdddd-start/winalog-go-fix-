package api

import (
	"embed"
	"strings"
)

//go:embed _statich
var staticFiles embed.FS

func getStaticFilePath(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "index.html"
	}
	return path
}
