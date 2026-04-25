package commands

import (
	"context"
	"fmt"

	"github.com/kkkdddd-start/winalog-go/internal/collectors"
	"github.com/spf13/cobra"
)

var collectCmd = &cobra.Command{
	Use:   "collect [flags]",
	Short: "One-click collection of all log sources",
	Long: `Automatically discover and collect all Windows log sources and forensic artifacts.

Collected data includes:
  - Windows Event Logs (Security, System, Application)
  - Registry persistence points (Run keys, Services, IFEO, etc.)
  - Startup folders
  - Scheduled tasks
  - System information
  - Prefetch files
  - ShimCache
  - Amcache
  - UserAssist
  - USN Journal
  - Network connections
  - Drivers
  - Local users
  - Process information

Examples:
  winalog collect
  winalog collect --output ./evidence.zip --compress
  winalog collect --include-prefetch --include-registry --include-startup
  winalog collect --include-amcache --include-userassist --include-usn-journal`,
	RunE: runCollect,
}

var collectFlags struct {
	outputPath        string
	includeLogs       bool
	includePrefetch   bool
	includeShimcache  bool
	includeAmcache    bool
	includeUserassist bool
	includeRegistry   bool
	includeStartup    bool
	includeTasks      bool
	includeSystemInfo bool
	includeNetwork    bool
	includeProcesses  bool
	includeDlls       bool
	includeDrivers    bool
	includeUsers      bool
	includeUSNJournal bool
	compress          bool
	compressLevel     int
	calculateHash     bool
	password          string
	excludePatterns   string
	workers           int
}

func init() {
	collectCmd.Flags().StringVarP(&collectFlags.outputPath, "output", "o", "winalog_collect.zip", "Output file path")
	collectCmd.Flags().BoolVar(&collectFlags.includeLogs, "include-logs", true, "Include Windows Event Logs")
	collectCmd.Flags().BoolVar(&collectFlags.includePrefetch, "include-prefetch", false, "Include Prefetch")
	collectCmd.Flags().BoolVar(&collectFlags.includeShimcache, "include-shimcache", false, "Include ShimCache")
	collectCmd.Flags().BoolVar(&collectFlags.includeAmcache, "include-amcache", false, "Include Amcache")
	collectCmd.Flags().BoolVar(&collectFlags.includeUserassist, "include-userassist", false, "Include UserAssist")
	collectCmd.Flags().BoolVar(&collectFlags.includeRegistry, "include-registry", false, "Include Registry persistence")
	collectCmd.Flags().BoolVar(&collectFlags.includeStartup, "include-startup", false, "Include Startup Folders")
	collectCmd.Flags().BoolVar(&collectFlags.includeTasks, "include-tasks", false, "Include Scheduled Tasks")
	collectCmd.Flags().BoolVar(&collectFlags.includeSystemInfo, "include-system-info", true, "Include System Info")
	collectCmd.Flags().BoolVar(&collectFlags.includeNetwork, "include-network", false, "Include Network Connections")
	collectCmd.Flags().BoolVar(&collectFlags.includeProcesses, "include-processes", false, "Include Process Info")
	collectCmd.Flags().BoolVar(&collectFlags.includeDlls, "include-dlls", false, "Include Process DLLs")
	collectCmd.Flags().BoolVar(&collectFlags.includeDrivers, "include-drivers", false, "Include Drivers")
	collectCmd.Flags().BoolVar(&collectFlags.includeUsers, "include-users", false, "Include Local Users")
	collectCmd.Flags().BoolVar(&collectFlags.includeUSNJournal, "include-usn-journal", false, "Include USN Journal")
	collectCmd.Flags().BoolVar(&collectFlags.compress, "compress", true, "Compress output")
	collectCmd.Flags().IntVar(&collectFlags.compressLevel, "compress-level", 6, "Compression level (0-9)")
	collectCmd.Flags().BoolVar(&collectFlags.calculateHash, "calculate-hash", true, "Calculate SHA256 hash")
	collectCmd.Flags().StringVar(&collectFlags.password, "password", "", "ZIP password (optional)")
	collectCmd.Flags().StringVar(&collectFlags.excludePatterns, "exclude", "", "Exclude patterns")
	collectCmd.Flags().IntVar(&collectFlags.workers, "workers", 4, "Number of parallel workers")
}

func runCollect(cmd *cobra.Command, args []string) error {
	fmt.Println("Starting one-click collection...")
	fmt.Printf("Output: %s\n", collectFlags.outputPath)
	fmt.Printf("Workers: %d\n", collectFlags.workers)
	fmt.Printf("Compress: %v\n", collectFlags.compress)
	fmt.Println()

	ctx := context.Background()

	opts := collectors.CollectOptions{
		Workers:            collectFlags.workers,
		IncludePrefetch:     collectFlags.includePrefetch,
		IncludeRegistry:     collectFlags.includeRegistry,
		IncludeStartup:      collectFlags.includeStartup,
		IncludeSystemInfo:   collectFlags.includeSystemInfo,
		IncludeShimCache:   collectFlags.includeShimcache,
		IncludeAmcache:      collectFlags.includeAmcache,
		IncludeUserassist:   collectFlags.includeUserassist,
		IncludeUSNJournal:   collectFlags.includeUSNJournal,
		IncludeTasks:        collectFlags.includeTasks,
		IncludeLogs:         collectFlags.includeLogs,
		IncludeNetwork:      collectFlags.includeNetwork,
		IncludeProcessSig:   collectFlags.includeProcesses,
		IncludeProcessDLLs:  collectFlags.includeDlls,
		IncludeDrivers:      collectFlags.includeDrivers,
		IncludeUsers:        collectFlags.includeUsers,
		OutputPath:         collectFlags.outputPath,
		Compress:           collectFlags.compress,
		CalculateHash:      collectFlags.calculateHash,
	}

	result, err := collectors.RunOneClickCollection(ctx, opts)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	oneClickResult, ok := result.(*collectors.OneClickResult)
	if !ok {
		return fmt.Errorf("invalid result type")
	}

	if oneClickResult.Success {
		fmt.Printf("\nCollection completed successfully!\n")
		fmt.Printf("Output: %s\n", oneClickResult.OutputPath)
		fmt.Printf("Duration: %v\n", oneClickResult.Duration)
	} else {
		fmt.Printf("\nCollection completed with errors\n")
	}

	return nil
}
