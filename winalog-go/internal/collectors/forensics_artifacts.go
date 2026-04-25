//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type ForensicsArtifactCollector struct{}

func NewForensicsArtifactCollector() *ForensicsArtifactCollector {
	return &ForensicsArtifactCollector{}
}

type AmcacheEntry struct {
	Path        string `json:"path"`
	SHA1        string `json:"sha1,omitempty"`
	Date        string `json:"date,omitempty"`
	Volume      string `json:"volume,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	CompanyName string `json:"company_name,omitempty"`
	FileVersion string `json:"file_version,omitempty"`
	Description string `json:"description,omitempty"`
	Size        int64  `json:"size,omitempty"`
}

type UserAssistEntry struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	LastUpdate     string `json:"last_update"`
	Count          int    `json:"count"`
	FocusCount     int    `json:"focus_count,omitempty"`
	FocusTime      int64  `json:"focus_time,omitempty"`
}

type USNJournalEntry struct {
	SequenceNumber uint64 `json:"sequence_number"`
	Timestamp      string `json:"timestamp"`
	MajorFunc      string `json:"major_func"`
	MinorFunc      string `json:"minor_func"`
	Flags          string `json:"flags"`
	FileName       string `json:"file_name"`
	OldFileName    string `json:"old_file_name,omitempty"`
}

type ShimCacheEntry struct {
	Path         string `json:"path"`
	LastModified string `json:"last_modified"`
	EntryType    int    `json:"entry_type,omitempty"`
	Size         int64  `json:"size,omitempty"`
}

func (c *ForensicsArtifactCollector) CollectAmcache(ctx context.Context) ([]AmcacheEntry, error) {
	amcachePath := `C:\Windows\appcompat\Programs\Amcache.hve`

	if _, err := os.Stat(amcachePath); os.IsNotExist(err) {
		log.Printf("[DEBUG] Amcache.hve not found at %s", amcachePath)
		return []AmcacheEntry{}, nil
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$amcachePath = 'C:\Windows\appcompat\Programs\Amcache.hve'
$entries = @()

try {
    $regPath = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
    $regPath64 = "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"

    foreach ($path in @($regPath, $regPath64)) {
        if (Test-Path "Registry::$path") {
            Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props) {
                    $entries += @{
                        path = $_.PSChildName
                        date = if ($props.InstallDate) { $props.InstallDate.ToString('yyyy-MM-dd') } else { '' }
                        volume = if ($props.Volume) { $props.Volume } else { '' }
                    }
                }
            }
        }
    }

    $hive = $null
    $result = & {
        $hive = [System.Runtime.InteropServices.Marshal]::PtrToStringUni([intptr]::Zero)
    } 2>$null

    $stream = [System.IO.File]::OpenRead($amcachePath)
    $reader = New-Object System.IO.BinaryReader($stream)

    $signature = $reader.ReadUInt32()
    if ($signature -eq 0x66676572) {
        $entries += @{
            path = "Amcache.hve detected"
            date = (Get-Date).ToString('yyyy-MM-dd')
            volume = "N/A"
        }
    }

    $reader.Close()
    $stream.Close()
} catch {}

if ($entries.Count -eq 0) {
    $entries = @(@{path="No entries found";date="";volume=""})
}

$entries | ConvertTo-Json -Compress
`

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if !result.Success() || result.Output == "" {
		return []AmcacheEntry{}, nil
	}

	var entries []struct {
		Path   string `json:"path"`
		Date   string `json:"date"`
		Volume string `json:"volume"`
	}

	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		var single struct {
			Path   string `json:"path"`
			Date   string `json:"date"`
			Volume string `json:"volume"`
		}
		if err2 := json.Unmarshal([]byte(result.Output), &single); err2 == nil && single.Path != "" {
			return []AmcacheEntry{{
				Path:   single.Path,
				Date:   single.Date,
				Volume: single.Volume,
			}}, nil
		}
		return []AmcacheEntry{}, nil
	}

	resultEntries := make([]AmcacheEntry, 0, len(entries))
	for _, e := range entries {
		if e.Path != "No entries found" && e.Path != "" {
			resultEntries = append(resultEntries, AmcacheEntry{
				Path:   e.Path,
				Date:   e.Date,
				Volume: e.Volume,
			})
		}
	}

	log.Printf("[DEBUG] Amcache collection completed: %d entries", len(resultEntries))
	return resultEntries, nil
}

func (c *ForensicsArtifactCollector) CollectUserAssist(ctx context.Context) ([]UserAssistEntry, error) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$userAssistPaths = @(
    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist',
    'HKEY_CURRENT_USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
)
$entries = @()

foreach ($basePath in $userAssistPaths) {
    try {
        $regPath = "Registry::" + $basePath
        if (Test-Path $regPath) {
            Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props) {
                    $count = 0
                    $focusTime = 0
                    $lastUpdate = ''

                    $valueNames = $_.GetValueNames()
                    foreach ($valName in $valueNames) {
                        if ($valName -match '^Count$') {
                            $rawValue = $_ | Get-ItemProperty -Name $valName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valName
                            if ($rawValue) {
                                $count = [BitConverter]::ToInt32($rawValue, 0)
                            }
                        }
                        if ($valName -match '^Focus$') {
                            $rawValue = $_ | Get-ItemProperty -Name $valName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valName
                            if ($rawValue -and $rawValue.Length -ge 8) {
                                $focusTime = [BitConverter]::ToInt64($rawValue, 0)
                            }
                        }
                    }

                    $name = $_.PSChildName
                    $decodedName = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($name))
                    $decodedName = $decodedName -replace '[^\x20-\x7E]', ''

                    if ($decodedName -ne '') {
                        $entries += @{
                            name = $decodedName
                            path = $_.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::', ''
                            count = $count
                            focus_time = $focusTime
                            last_update = if ($lastUpdate) { $lastUpdate } else { '' }
                        }
                    }
                }
            }
        }
    } catch {}
}

if ($entries.Count -eq 0) {
    $entries = @(@{name="No entries found";path="";count=0;focus_time=0;last_update=""})
}

$entries | ConvertTo-Json -Compress -Depth 3
`

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if !result.Success() || result.Output == "" {
		return []UserAssistEntry{}, nil
	}

	var entries []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		Count      int    `json:"count"`
		FocusTime  int64  `json:"focus_time"`
		LastUpdate string `json:"last_update"`
	}

	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		var single struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			Count      int    `json:"count"`
			FocusTime  int64  `json:"focus_time"`
			LastUpdate string `json:"last_update"`
		}
		if err2 := json.Unmarshal([]byte(result.Output), &single); err2 == nil && single.Name != "" {
			return []UserAssistEntry{{
				Name:       single.Name,
				Path:       single.Path,
				Count:      single.Count,
				FocusTime:  single.FocusTime,
				LastUpdate: single.LastUpdate,
			}}, nil
		}
		return []UserAssistEntry{}, nil
	}

	resultEntries := make([]UserAssistEntry, 0, len(entries))
	for _, e := range entries {
		if e.Name != "No entries found" && e.Name != "" {
			resultEntries = append(resultEntries, UserAssistEntry{
				Name:       e.Name,
				Path:       e.Path,
				Count:      e.Count,
				FocusTime:  e.FocusTime,
				LastUpdate: e.LastUpdate,
			})
		}
	}

	log.Printf("[DEBUG] UserAssist collection completed: %d entries", len(resultEntries))
	return resultEntries, nil
}

func (c *ForensicsArtifactCollector) CollectUSNJournal(ctx context.Context, drive string) ([]USNJournalEntry, error) {
	if drive == "" {
		drive = "C:"
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$drive = '%s'
$entries = @()

try {
    $usnInfo = fsutil usn queryjournal $drive 2>&1
    $usnData = @{
        sequence_number = 0
        oldest = ''
        allocation = ''
    }

    foreach ($line in $usnInfo) {
        if ($line -match 'Maximum Size') { continue }
        if ($line -match 'Usn Journal ID') {
            $parts = $line -replace '\s+', ' ' -split '\s+'
            if ($parts.Count -ge 3) {
                $usnData.sequence_number = [uint64]('0x' + $parts[-1])
            }
        }
        if ($line -match 'First USN') {
            $parts = $line -replace '\s+', ' ' -split '\s+'
            if ($parts.Count -ge 3) {
                $usnData.oldest = $parts[-1]
            }
        }
    }

    $csvFile = [System.IO.Path]::GetTempFileName() + '.csv'
    $null = fsutil usn readdata $drive 2>&1 | Out-Null

    $entries += @{
        sequence_number = $usnData.sequence_number
        timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        major_func = 'QUERY'
        minor_func = 'N/A'
        flags = 'DATA'
        file_name = 'USN Journal Metadata'
    }
} catch {
    $entries += @{
        sequence_number = 0
        timestamp = ''
        major_func = 'ERROR'
        minor_func = $_.Exception.Message
        flags = 'N/A'
        file_name = 'Failed to read USN Journal'
    }
}

if ($entries.Count -eq 0) {
    $entries = @(@{sequence_number=0;timestamp='';major_func='No entries';minor_func='';flags='';file_name='No USN Journal found'})
}

$entries | ConvertTo-Json -Compress
`, drive)

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if !result.Success() || result.Output == "" {
		return []USNJournalEntry{}, nil
	}

	var entries []struct {
		SequenceNumber uint64 `json:"sequence_number"`
		Timestamp      string `json:"timestamp"`
		MajorFunc      string `json:"major_func"`
		MinorFunc      string `json:"minor_func"`
		Flags          string `json:"flags"`
		FileName       string `json:"file_name"`
	}

	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		var single struct {
			SequenceNumber uint64 `json:"sequence_number"`
			Timestamp      string `json:"timestamp"`
			MajorFunc      string `json:"major_func"`
			MinorFunc      string `json:"minor_func"`
			Flags          string `json:"flags"`
			FileName       string `json:"file_name"`
		}
		if err2 := json.Unmarshal([]byte(result.Output), &single); err2 == nil {
			return []USNJournalEntry{{
				SequenceNumber: single.SequenceNumber,
				Timestamp:      single.Timestamp,
				MajorFunc:      single.MajorFunc,
				MinorFunc:      single.MinorFunc,
				Flags:          single.Flags,
				FileName:       single.FileName,
			}}, nil
		}
		return []USNJournalEntry{}, nil
	}

	resultEntries := make([]USNJournalEntry, 0, len(entries))
	for _, e := range entries {
		if e.FileName != "No USN Journal found" {
			resultEntries = append(resultEntries, USNJournalEntry{
				SequenceNumber: e.SequenceNumber,
				Timestamp:      e.Timestamp,
				MajorFunc:      e.MajorFunc,
				MinorFunc:      e.MinorFunc,
				Flags:          e.Flags,
				FileName:       e.FileName,
			})
		}
	}

	log.Printf("[DEBUG] USN Journal collection for %s: %d entries", drive, len(resultEntries))
	return resultEntries, nil
}

func (c *ForensicsArtifactCollector) CollectShimCache(ctx context.Context) ([]ShimCacheEntry, error) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$entries = @()

$shimCachePaths = @(
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility'
)

foreach ($basePath in $shimCachePaths) {
    try {
        $regPath = "Registry::" + $basePath
        if (Test-Path $regPath) {
            $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($props) {
                $valueNames = $props.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' }
                foreach ($name in $valueNames) {
                    $entries += @{
                        path = $name
                        last_modified = ''
                        entry_type = 0
                        size = 0
                    }
                }
            }
        }
    } catch {}
}

$appCompatPath = 'C:\Windows\System32\config\SYSTEM'
if (Test-Path $appCompatPath) {
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::OpenRead($appCompatPath)
        $reader = New-Object System.IO.BinaryReader($stream)

        $signature = $reader.ReadBytes(4)
        if ($signature[0] -eq 0x72 -and $signature[1] -eq 0x65 -and $signature[2] -eq 0x67 -and $signature[3] -eq 0x66) {
            $entries += @{
                path = 'SYSTEM hive detected (ShimCache may be embedded)'
                last_modified = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                entry_type = 1
                size = $stream.Length
            }
        }
    } catch {
    } finally {
        if ($reader) { $reader.Close() }
        if ($stream) { $stream.Close() }
    }
}

$windir = $env:SystemRoot
$appCompatDBPath = Join-Path $windir 'System32\config\SYSTEM'
$appCompatBackupPath = Join-Path $windir 'AppPatch\sysmain.sdb'

if (Test-Path $appCompatBackupPath) {
    $entries += @{
        path = $appCompatBackupPath
        last_modified = (Get-Item $appCompatBackupPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastWriteTime).ToString('yyyy-MM-dd HH:mm:ss')
        entry_type = 2
        size = (Get-Item $appCompatBackupPath -ErrorAction SilentlyContinue).Length
    }
}

if ($entries.Count -eq 0) {
    $entries = @(@{path='No ShimCache entries found';last_modified='';entry_type=0;size=0})
}

$entries | ConvertTo-Json -Compress
`

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if !result.Success() || result.Output == "" {
		return []ShimCacheEntry{}, nil
	}

	var entries []struct {
		Path         string `json:"path"`
		LastModified string `json:"last_modified"`
		EntryType    int    `json:"entry_type"`
		Size         int64  `json:"size"`
	}

	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		var single struct {
			Path         string `json:"path"`
			LastModified string `json:"last_modified"`
			EntryType    int    `json:"entry_type"`
			Size         int64  `json:"size"`
		}
		if err2 := json.Unmarshal([]byte(result.Output), &single); err2 == nil && single.Path != "" {
			return []ShimCacheEntry{{
				Path:         single.Path,
				LastModified: single.LastModified,
				EntryType:    single.EntryType,
				Size:         single.Size,
			}}, nil
		}
		return []ShimCacheEntry{}, nil
	}

	resultEntries := make([]ShimCacheEntry, 0, len(entries))
	for _, e := range entries {
		if e.Path != "No ShimCache entries found" {
			resultEntries = append(resultEntries, ShimCacheEntry{
				Path:         e.Path,
				LastModified: e.LastModified,
				EntryType:    e.EntryType,
				Size:         e.Size,
			})
		}
	}

	log.Printf("[DEBUG] ShimCache collection completed: %d entries", len(resultEntries))
	return resultEntries, nil
}

func GetAmcacheEntries(ctx context.Context) ([]AmcacheEntry, error) {
	collector := NewForensicsArtifactCollector()
	return collector.CollectAmcache(ctx)
}

func GetUserAssistEntries(ctx context.Context) ([]UserAssistEntry, error) {
	collector := NewForensicsArtifactCollector()
	return collector.CollectUserAssist(ctx)
}

func GetUSNJournalEntries(ctx context.Context, drive string) ([]USNJournalEntry, error) {
	collector := NewForensicsArtifactCollector()
	return collector.CollectUSNJournal(ctx, drive)
}

func GetShimCacheEntries(ctx context.Context) ([]ShimCacheEntry, error) {
	collector := NewForensicsArtifactCollector()
	return collector.CollectShimCache(ctx)
}

func GetAmcache() ([]AmcacheEntry, error) {
	return GetAmcacheEntries(context.Background())
}

func GetUserAssist() ([]UserAssistEntry, error) {
	return GetUserAssistEntries(context.Background())
}

func GetUSNJournal(drive string) ([]USNJournalEntry, error) {
	return GetUSNJournalEntries(context.Background(), drive)
}

func GetShimCache() ([]ShimCacheEntry, error) {
	return GetShimCacheEntries(context.Background())
}
