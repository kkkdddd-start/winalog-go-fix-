//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
	"golang.org/x/sys/windows"
)

type ProcessInfoCollector struct {
	BaseCollector
}

type Process struct {
	PID     int
	PPID    int
	Name    string
	Path    string
	Command string
	User    string
}

func NewProcessInfoCollector() *ProcessInfoCollector {
	return &ProcessInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "process_info",
				Description:   "Collect process information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *ProcessInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	processes, err := c.collectProcessInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(processes))
	for i, p := range processes {
		interfaces[i] = p
	}
	return interfaces, nil
}

func (c *ProcessInfoCollector) collectProcessInfo() ([]*types.ProcessInfo, error) {
	type procInfo struct {
		pid  uint32
		ppid uint32
		name string
	}

	processes := make([]*types.ProcessInfo, 0)

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	var procList []procInfo
	for {
		procList = append(procList, procInfo{
			pid:  entry.ProcessID,
			ppid: entry.ParentProcessID,
			name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	pids := make([]uint32, len(procList))
	for i, p := range procList {
		pids[i] = p.pid
	}
	commandLines := batchGetCommandLines(pids)
	memMap, cpuMap := batchGetProcessMemoryAndCPU(pids)
	pathMap, userMap := batchGetProcessPathAndUser(pids)
	sigMap := batchGetProcessSignatures(pathMap)

	for _, p := range procList {
		exePath := pathMap[p.pid]
		if exePath == "" {
			exePath = getProcessPath(p.pid)
		}
		user := userMap[p.pid]
		if user == "" {
			user = getProcessUser(p.pid)
		}

		proc := &types.ProcessInfo{
			PID:         int32(p.pid),
			PPID:        int32(p.ppid),
			Name:        p.name,
			Path:        exePath,
			CommandLine: commandLines[p.pid],
			User:        user,
			StartTime:   getProcessStartTime(p.pid),
			IsElevated:  isProcessElevated(p.pid),
			MemoryMB:    memMap[p.pid],
			CPUPercent:  cpuMap[p.pid],
		}

		if sigInfo, ok := sigMap[p.pid]; ok && sigInfo != nil {
			proc.IsSigned = sigInfo.Status == "Valid"
			if sigInfo.Status != "Invalid" {
				proc.Signature = &types.SignatureInfo{
					Status:     sigInfo.Status,
					Issuer:     sigInfo.Issuer,
					Subject:    sigInfo.Signer,
					ValidFrom:  sigInfo.ValidFrom,
					ValidTo:    sigInfo.ValidTo,
					Thumbprint: sigInfo.Thumbprint,
				}
			}
		}

		processes = append(processes, proc)
	}

	return processes, nil
}

func batchGetCommandLines(pids []uint32) map[uint32]string {
	result := make(map[uint32]string)

	if len(pids) == 0 {
		return result
	}

	script := `(Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress)`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmdResult := utils.RunPowerShellWithContext(ctx, script)
	if !cmdResult.Success() || cmdResult.Output == "" {
		return result
	}

	var entries []struct {
		ProcessID   uint32 `json:"ProcessId"`
		CommandLine string `json:"CommandLine"`
	}

	if err := json.Unmarshal([]byte(cmdResult.Output), &entries); err != nil {
		var single struct {
			ProcessID   uint32 `json:"ProcessId"`
			CommandLine string `json:"CommandLine"`
		}
		if err2 := json.Unmarshal([]byte(cmdResult.Output), &single); err2 == nil && single.ProcessID != 0 {
			result[single.ProcessID] = single.CommandLine
		}
		return result
	}

	pidSet := make(map[uint32]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	for _, e := range entries {
		if pidSet[e.ProcessID] {
			result[e.ProcessID] = e.CommandLine
		}
	}

	return result
}

func (c *ProcessInfoCollector) CollectProcessInfoWithSignature() ([]*types.ProcessInfo, error) {
	return c.collectProcessInfo()
}

func getProcessPath(pid uint32) string {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(hProcess)

	var pathBuf [windows.MAX_PATH]uint16
	size := uint32(len(pathBuf))
	if err := windows.QueryFullProcessImageName(hProcess, 0, &pathBuf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(pathBuf[:size])
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func getCommandLine(pid uint32) string {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	script := fmt.Sprintf(`(Get-CimInstance Win32_Process -Filter "ProcessId=%d" -ErrorAction SilentlyContinue).CommandLine`, pid)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if result.Success() && result.Output != "" {
		return strings.TrimSpace(result.Output)
	}

	return ""
}

func getProcessUser(pid uint32) string {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "SYSTEM"
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "SYSTEM"
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "SYSTEM"
	}

	user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "SYSTEM"
	}

	return domain + "\\" + user
}

func isProcessElevated(pid uint32) bool {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), 4, nil)
	if err != nil {
		return false
	}

	return elevation != 0
}

func batchGetProcessMemoryAndCPU(pids []uint32) (map[uint32]float64, map[uint32]float64) {
	memMap := make(map[uint32]float64)
	cpuMap := make(map[uint32]float64)

	if len(pids) == 0 {
		return memMap, cpuMap
	}

	memScript := `(Get-CimInstance Win32_Process | Select-Object ProcessId, WorkingSetSize | ConvertTo-Json -Compress)`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	memResult := utils.RunPowerShellWithContext(ctx, memScript)
	if memResult.Success() && memResult.Output != "" {
		var entries []struct {
			ProcessID    uint32 `json:"ProcessId"`
			WorkingSetSize int64 `json:"WorkingSetSize"`
		}
		if err := json.Unmarshal([]byte(memResult.Output), &entries); err == nil {
			pidSet := make(map[uint32]bool)
			for _, pid := range pids {
				pidSet[pid] = true
			}
			for _, e := range entries {
				if pidSet[e.ProcessID] {
					memMap[e.ProcessID] = float64(e.WorkingSetSize) / 1024 / 1024
				}
			}
		}
	}

	cpuScript := `(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Select-Object IDProcess, PercentProcessorTime | ConvertTo-Json -Compress)`
	cpuResult := utils.RunPowerShellWithContext(ctx, cpuScript)
	if cpuResult.Success() && cpuResult.Output != "" {
		var entries []struct {
			IDProcess             uint32 `json:"IDProcess"`
			PercentProcessorTime float64 `json:"PercentProcessorTime"`
		}
		if err := json.Unmarshal([]byte(cpuResult.Output), &entries); err == nil {
			pidSet := make(map[uint32]bool)
			for _, pid := range pids {
				pidSet[pid] = true
			}
			for _, e := range entries {
				if pidSet[e.IDProcess] {
					cpuMap[e.IDProcess] = e.PercentProcessorTime
				}
			}
		}
	}

	return memMap, cpuMap
}

func batchGetProcessPathAndUser(pids []uint32) (map[uint32]string, map[uint32]string) {
	pathMap := make(map[uint32]string)
	userMap := make(map[uint32]string)

	if len(pids) == 0 {
		return pathMap, userMap
	}

	script := `Get-CimInstance Win32_Process | ForEach-Object {
		$owner = $_.GetOwner()
		$user = ''
		if ($owner.Domain -and $owner.User) {
			$user = $owner.Domain + '\' + $owner.User
		}
		[PSCustomObject]@{
			ProcessId = $_.ProcessId
			Path = $_.ExecutablePath
			User = $user
		}
	} | ConvertTo-Json -Compress`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := utils.RunPowerShellWithContext(ctx, script)
	if !result.Success() || result.Output == "" {
		return pathMap, userMap
	}

	var entries []struct {
		ProcessID uint32 `json:"ProcessId"`
		Path      string `json:"Path"`
		User      string `json:"User"`
	}

	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		var single struct {
			ProcessID uint32 `json:"ProcessId"`
			Path      string `json:"Path"`
			User      string `json:"User"`
		}
		if err2 := json.Unmarshal([]byte(result.Output), &single); err2 == nil && single.ProcessID != 0 {
			pathMap[single.ProcessID] = single.Path
			userMap[single.ProcessID] = single.User
		}
		return pathMap, userMap
	}

	pidSet := make(map[uint32]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	for _, e := range entries {
		if pidSet[e.ProcessID] {
			pathMap[e.ProcessID] = e.Path
			userMap[e.ProcessID] = e.User
		}
	}

	return pathMap, userMap
}

type ProcessSignature struct {
	PID           uint32
	Status        string
	Signer        string
	Issuer        string
	Thumbprint    string
	ValidFrom      string
	ValidTo        string
}

func escapePowerShellPath(path string) string {
	escaped := path
	escaped = strings.ReplaceAll(escaped, "%", "%%")
	escaped = strings.ReplaceAll(escaped, "'", "''")
	escaped = strings.ReplaceAll(escaped, "`", "``")
	escaped = strings.ReplaceAll(escaped, "$", "`$")
	return escaped
}

func batchGetProcessSignatures(paths map[uint32]string) map[uint32]*ProcessSignature {
	result := make(map[uint32]*ProcessSignature)

	if len(paths) == 0 {
		log.Printf("[DEBUG] batchGetProcessSignatures: paths map is empty")
		return result
	}

	var pathList []string
	pidByPath := make(map[string]uint32)
	for pid, path := range paths {
		if path != "" && !strings.HasSuffix(strings.ToLower(path), ".tmp") {
			pathList = append(pathList, path)
			pidByPath[path] = pid
		}
	}

	if len(pathList) == 0 {
		log.Printf("[DEBUG] batchGetProcessSignatures: pathList is empty after filtering")
		return result
	}

	log.Printf("[DEBUG] batchGetProcessSignatures: processing %d paths in batches of 100", len(pathList))

	batchSize := 100
	for i := 0; i < len(pathList); i += batchSize {
		end := i + batchSize
		if end > len(pathList) {
			end = len(pathList)
		}
		batch := pathList[i:end]

		for j, p := range batch {
			batch[j] = escapePowerShellPath(p)
		}

		script := `$paths = @('%s')
foreach ($p in $paths) {
	$sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue
	$status = if ($sig.Status -eq 'Valid') { 'Valid' } else { 'Invalid' }
	if ($sig.SignerCertificate) {
		$signer = $sig.SignerCertificate.Subject
		$issuer = $sig.SignerCertificate.Issuer
		$thumbprint = $sig.SignerCertificate.Thumbprint
		$validFrom = $sig.SignerCertificate.NotBefore.ToString('o')
		$validTo = $sig.SignerCertificate.NotAfter.ToString('o')
	} else {
		$signer = $issuer = $thumbprint = $validFrom = $validTo = ''
	}
	$json = '{"p":"' + $p + '","s":"' + $status + '","si":"' + $signer + '","i":"' + $issuer + '","t":"' + $thumbprint + '","vf":"' + $validFrom + '","vt":"' + $validTo + '"}'
	Write-Output $json
}`

		psPaths := strings.Join(batch, "','")
		script = fmt.Sprintf(script, psPaths)

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		cmdResult := utils.RunPowerShellWithContext(ctx, script)
		cancel()
		if cmdResult.Error != nil {
			log.Printf("[WARN] batchGetProcessSignatures: PowerShell error at batch starting at %d: %v", i, cmdResult.Error)
			if i == 0 && len(batch) > 0 {
				log.Printf("[DEBUG] batchGetProcessSignatures: sample paths from first batch: %v", batch[:min(3, len(batch))])
				log.Printf("[DEBUG] batchGetProcessSignatures: generated script (first 500 chars): %s", script[:min(500, len(script))])
			}
			continue
		}
		if cmdResult.Output == "" {
			log.Printf("[WARN] batchGetProcessSignatures: empty output for batch starting at %d", i)
			continue
		}

		lines := strings.Split(strings.TrimSpace(cmdResult.Output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || line == "[" || line == "]" {
				continue
			}
			line = strings.Trim(line, ",")

			var sr struct {
				P  string `json:"p"`
				S  string `json:"s"`
				Si string `json:"si"`
				I  string `json:"i"`
				T  string `json:"t"`
				Vf string `json:"vf"`
				Vt string `json:"vt"`
			}
			if err := json.Unmarshal([]byte(line), &sr); err != nil {
				log.Printf("[WARN] batchGetProcessSignatures: JSON line parse error: %v, line: %s", err, truncateString(line, 200))
				continue
			}

			pid, ok := pidByPath[sr.P]
			if !ok {
				pid, ok = pidByPath[strings.ToLower(sr.P)]
			}
			if !ok {
				pid, ok = pidByPath[strings.ToUpper(sr.P)]
			}
			if ok {
				result[pid] = &ProcessSignature{
					Status:     sr.S,
					Signer:     sr.Si,
					Issuer:     sr.I,
					Thumbprint: sr.T,
					ValidFrom:  sr.Vf,
					ValidTo:    sr.Vt,
				}
			} else {
				log.Printf("[DEBUG] batchGetProcessSignatures: path not found in pidByPath: %s", sr.P)
			}
		}
	}

	return result
}

func getProcessStartTime(pid uint32) time.Time {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if pid == 0 {
		return time.Time{}
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(hProcess)

	if hProcess == 0 {
		return time.Time{}
	}

	var creationTime windows.Filetime
	var exitTime windows.Filetime
	var kernelTime windows.Filetime
	var userTime windows.Filetime
	err = windows.GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)
	if err != nil {
		return time.Time{}
	}

	high := uint64(creationTime.HighDateTime)
	low := uint64(creationTime.LowDateTime)
	if high == 0 && low == 0 {
		return time.Time{}
	}

	ns := (high << 32) | low
	return time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).
		Add(time.Duration(ns) * 100)
}

func ListProcesses() ([]Process, error) {
	var processes []Process

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	var procList []struct {
		pid  uint32
		ppid uint32
		name string
	}
	for {
		procList = append(procList, struct {
			pid  uint32
			ppid uint32
			name string
		}{
			pid:  entry.ProcessID,
			ppid: entry.ParentProcessID,
			name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	pids := make([]uint32, len(procList))
	for i, p := range procList {
		pids[i] = p.pid
	}
	commandLines := batchGetCommandLines(pids)
	pathMap, userMap := batchGetProcessPathAndUser(pids)

	for _, p := range procList {
		exePath := pathMap[p.pid]
		if exePath == "" {
			exePath = getProcessPath(p.pid)
		}
		user := userMap[p.pid]
		if user == "" {
			user = getProcessUser(p.pid)
		}
		processes = append(processes, Process{
			PID:     int(p.pid),
			PPID:    int(p.ppid),
			Name:    p.name,
			Path:    exePath,
			Command: commandLines[p.pid],
			User:    user,
		})
	}

	return processes, nil
}

func GetProcessCmdLine(pid int) string {
	return getCommandLine(uint32(pid))
}

func GetProcessUser(pid int) string {
	return getProcessUser(uint32(pid))
}

func IsProcessRunning(pid int) bool {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(hProcess)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(hProcess, &exitCode); err != nil {
		return false
	}

	return exitCode == 259
}

func GetProcessStartTime(pid int) time.Time {
	return getProcessStartTime(uint32(pid))
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
