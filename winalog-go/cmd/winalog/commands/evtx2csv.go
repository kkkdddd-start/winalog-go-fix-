package commands

import (
	"fmt"
	"os"

	"github.com/kkkdddd-start/winalog-go/internal/exporters"
	"github.com/kkkdddd-start/winalog-go/internal/parsers/evtx"
	"github.com/spf13/cobra"
)

var evtx2csvFlags struct {
	limit int
}

var evtx2csvCmd = &cobra.Command{
	Use:   "evtx2csv <input.evtx> [output.csv]",
	Short: "Convert EVTX file to CSV format",
	Long: `Convert Windows Event Log (EVTX) files to CSV format without storing in database.

Examples:
  winalog evtx2csv security.evtx security.csv
  winalog evtx2csv -l 1000 security.evtx > security.csv`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runEvtx2Csv,
}

func init() {
	evtx2csvCmd.Flags().IntVarP(&evtx2csvFlags.limit, "limit", "l", 0, "Limit number of events (0 = no limit)")
}

func runEvtx2Csv(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("cannot access input file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("input path is a directory, not a file")
	}

	var outputPath string
	if len(args) > 1 {
		outputPath = args[1]
	} else {
		outputPath = inputPath + ".csv"
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	fmt.Printf("Parsing EVTX file: %s\n", inputPath)

	parser := evtx.NewEvtxParser()
	events, err := parser.ParseBatch(inputPath)
	if err != nil {
		return fmt.Errorf("failed to parse EVTX file: %w", err)
	}

	if evtx2csvFlags.limit > 0 && len(events) > evtx2csvFlags.limit {
		events = events[:evtx2csvFlags.limit]
	}

	fmt.Printf("Found %d events, converting to CSV...\n", len(events))

	exporter := exporters.NewCsvExporter()
	if err := exporter.Export(events, outputFile); err != nil {
		return fmt.Errorf("failed to export CSV: %w", err)
	}

	fmt.Printf("Successfully converted %d events to %s\n", len(events), outputPath)
	return nil
}
