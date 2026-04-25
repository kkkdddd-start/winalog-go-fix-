package forensics

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type EvidenceCollector struct {
	EvidenceID string
	OutputPath string

	CollectRegistry   bool
	CollectPrefetch   bool
	CollectShimcache  bool
	CollectAmcache    bool
	CollectUserAssist bool
	CollectTasks      bool
	CollectLogs       bool

	files []*EvidenceFile
}

func NewEvidenceCollector(evidenceID, outputPath string) *EvidenceCollector {
	return &EvidenceCollector{
		EvidenceID: evidenceID,
		OutputPath: outputPath,
		files:      make([]*EvidenceFile, 0),
	}
}

func (c *EvidenceCollector) Collect() (*EvidenceManifest, error) {
	tempDir, err := os.MkdirTemp("", "winalog_evidence_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	if c.CollectRegistry {
		c.collectRegistry(tempDir)
	}
	if c.CollectPrefetch {
		c.collectPrefetch(tempDir)
	}
	if c.CollectShimcache {
		c.collectShimcache(tempDir)
	}
	if c.CollectLogs {
		c.collectEventLogs(tempDir)
	}

	manifest := GenerateManifest(c.files, "api-collector", getHostname())
	return manifest, nil
}

func (c *EvidenceCollector) collectRegistry(tempDir string) {
	paths := []string{
		`C:\Windows\System32\config\SYSTEM`,
		`C:\Windows\System32\config\SOFTWARE`,
		`C:\Windows\System32\config\SECURITY`,
		`C:\Windows\System32\config\SAM`,
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			if data, err := os.ReadFile(path); err == nil {
				c.files = append(c.files, &EvidenceFile{
					FilePath:    path,
					FileHash:    fmt.Sprintf("%x", data),
					Collector:   "registry",
					CollectedAt: time.Now(),
				})
			}
		}
	}
}

func (c *EvidenceCollector) collectPrefetch(tempDir string) {
	prefetchPath := `C:\Windows\Prefetch`
	if entries, err := os.ReadDir(prefetchPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".pf" {
				fullPath := filepath.Join(prefetchPath, entry.Name())
				info, _ := os.Stat(fullPath)
				var size int64
				if info != nil {
					size = info.Size()
				}
				c.files = append(c.files, &EvidenceFile{
					FilePath:    fullPath,
					FileHash:    "",
					Size:        size,
					Collector:   "prefetch",
					CollectedAt: time.Now(),
				})
			}
		}
	}
}

func (c *EvidenceCollector) collectShimcache(tempDir string) {
	path := `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`
	if _, err := os.Stat(path); err == nil {
		info, _ := os.Stat(path)
		var size int64
		if info != nil {
			size = info.Size()
		}
		c.files = append(c.files, &EvidenceFile{
			FilePath:    path,
			FileHash:    "",
			Size:        size,
			Collector:   "shimcache",
			CollectedAt: time.Now(),
		})
	}
}

func (c *EvidenceCollector) collectEventLogs(tempDir string) {
	logPaths := []string{
		`C:\Windows\System32\winevt\Logs\Security.evtx`,
		`C:\Windows\System32\winevt\Logs\System.evtx`,
		`C:\Windows\System32\winevt\Logs\Application.evtx`,
	}

	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			info, _ := os.Stat(path)
			var size int64
			if info != nil {
				size = info.Size()
			}
			c.files = append(c.files, &EvidenceFile{
				FilePath:    path,
				FileHash:    "",
				Size:        size,
				Collector:   "eventlog",
				CollectedAt: time.Now(),
			})
		}
	}
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}
