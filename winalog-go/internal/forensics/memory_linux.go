//go:build !windows

package forensics

import "time"

type MemoryDumpResult struct {
	ProcessID   uint32
	ProcessName string
	DumpPath    string
	DumpSize    int64
	DumpTime    time.Time
	Hash        string
	Error       string
}

type MemoryCollector struct {
	outputDir string
}

func NewMemoryCollector(outputDir string) *MemoryCollector {
	return &MemoryCollector{outputDir: outputDir}
}

func (c *MemoryCollector) CollectProcessMemory(pid uint32) (*MemoryDumpResult, error) {
	return nil, &notImplementedError{"CollectProcessMemory requires Windows"}
}

func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error) {
	return nil, &notImplementedError{"CollectSystemMemory requires Windows"}
}

type notImplementedError struct {
	msg string
}

func (e *notImplementedError) Error() string {
	return e.msg
}
