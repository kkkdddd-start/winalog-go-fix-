package main

import (
	"fmt"
	"os"

	"github.com/kkkdddd-start/winalog-go/cmd/winalog/commands"
	"github.com/kkkdddd-start/winalog-go/internal/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "winalog",
	Short: "WinLogAnalyzer - Windows Security Forensics and Log Analysis Tool",
	Long: `WinLogAnalyzer-Go is a Windows security forensics and log analysis tool 
written in Go. It provides high-performance EVTX parsing, alerting, correlation, 
and forensics capabilities in a single binary.

Supported formats:
  - EVTX (Windows Event Log)
  - ETL (Event Trace Log)
  - CSV/LOG (Custom formats)
  - IIS (W3C Extended Log)
  - Sysmon (Event ID 1-22)

Examples:
  winalog import security.evtx
  winalog search --event-id 4624
  winalog collect --output ./evidence.zip`,
	Version: version.Version,
}

func main() {
	commands.RegisterCommands(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
