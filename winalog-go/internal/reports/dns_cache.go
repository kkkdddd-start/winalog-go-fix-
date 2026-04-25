package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type dnsCacheRecord struct {
	Name     string `json:"Name"`
	Type     uint16 `json:"Type"`
	TypeName string `json:"TypeName"`
	Data     string `json:"Data"`
	TTL      uint32 `json:"TTL"`
	Section  string `json:"Section"`
}

func GetSystemDNSCache() ([]storage.DNSCacheEntry, error) {
	entries, err := queryDNSCacheOnce()
	if err != nil {
		return nil, err
	}

	result := make([]storage.DNSCacheEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, storage.DNSCacheEntry{
			Name:        e.Name,
			Type:        fmt.Sprintf("%d", e.Type),
			TypeName:    e.TypeName,
			Data:        e.Data,
			TTL:         e.TTL,
			Section:     e.Section,
			ProcessName: "Unknown",
			CollectedAt: time.Now(),
		})
	}

	return result, nil
}

func queryDNSCacheOnce() ([]dnsCacheRecord, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
		[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
		Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordType, TimeToLive, Data, Section | ConvertTo-Json -Compress
	`)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to query DNS cache: %w", err)
	}

	return parseDNSCacheOutput(out.String())
}

func parseDNSCacheOutput(output string) ([]dnsCacheRecord, error) {
	if output == "" || output == "null" || output == " " {
		return nil, nil
	}

	output = strings.TrimSpace(output)

	var records []dnsCacheRecord

	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &records); err != nil {
			return nil, fmt.Errorf("failed to parse DNS cache JSON: %w", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var record dnsCacheRecord
		if err := json.Unmarshal([]byte(output), &record); err != nil {
			return nil, fmt.Errorf("failed to parse DNS cache JSON object: %w", err)
		}
		records = append(records, record)
	} else {
		return nil, nil
	}

	return records, nil
}
