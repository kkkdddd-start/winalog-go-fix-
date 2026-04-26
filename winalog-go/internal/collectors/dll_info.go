//go:build windows

package collectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
	"golang.org/x/sys/windows"
)

var (
	dllVersionCache = make(map[string]string)
	dllCacheMu      sync.RWMutex
	dllFetchSem     = make(chan struct{}, 10)
)

type DLLInfoCollector struct {
	BaseCollector
}

type DLLModuleInfo struct {
	ProcessID   int32
	ProcessName string
	Name        string
	Path        string
	Size        uint32
	Version     string
	IsSigned    bool
	Signer      string
}

func NewDLLInfoCollector() *DLLInfoCollector {
	return &DLLInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "dll_info",
				Description:   "Collect DLL information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *DLLInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	dlls, err := c.collectDLLInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(dlls))
	for i, d := range dlls {
		interfaces[i] = d
	}
	return interfaces, nil
}

func (c *DLLInfoCollector) collectDLLInfo() ([]*types.DLLModule, error) {
	dlls := make([]*types.DLLModule, 0)

	dllModules, err := ListLoadedDLLs()
	if err != nil {
		return dlls, err
	}

	if len(dllModules) == 0 {
		return dlls, nil
	}

	uniquePaths := make([]string, 0, len(dllModules))
	pathIndex := make(map[string]int)
	for i, dll := range dllModules {
		if dll.Path != "" && pathIndex[dll.Path] == 0 {
			uniquePaths = append(uniquePaths, dll.Path)
			pathIndex[dll.Path] = i + 1
		}
	}

	versions, _ := GetDLLVersionsBatch(uniquePaths)

	for _, dll := range dllModules {
		module := &types.DLLModule{
			ProcessID:   dll.ProcessID,
			ProcessName: dll.ProcessName,
			Path:        dll.Path,
			Size:        dll.Size,
		}
		if v, ok := versions[dll.Path]; ok {
			module.Version = v
		}
		dlls = append(dlls, module)
	}

	return dlls, nil
}

const TH32CS_SNAPMODULE3264 = 0x00000010

func ListLoadedDLLs() ([]DLLModuleInfo, error) {
	dlls := make([]DLLModuleInfo, 0)

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS|windows.TH32CS_SNAPMODULE|TH32CS_SNAPMODULE3264, 0)
	if err != nil {
		log.Printf("[DEBUG] [DLL] CreateToolhelp32Snapshot failed: %v", err)
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		log.Printf("[DEBUG] [DLL] Process32First failed: %v", err)
		return nil, err
	}

	processCount := 0
	moduleCount := 0
	skipCount := 0
	errorCount := 0

	for {
		pid := int(pe.ProcessID)
		processName := windows.UTF16ToString(pe.ExeFile[:])
		processCount++

		modules, err := enumProcessModules(pid, processName)
		if err != nil {
			errorCount++
			if errorCount <= 3 {
				log.Printf("[DEBUG] [DLL] enumProcessModules(pid=%d, name=%s) error: %v", pid, processName, err)
			}
		} else if len(modules) > 0 {
			for _, mod := range modules {
				mod.ProcessID = int32(pid)
				mod.ProcessName = processName
				dlls = append(dlls, mod)
				moduleCount++
			}
		} else {
			skipCount++
		}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	log.Printf("[INFO] [DLL] ListLoadedDLLs: processes=%d, modules=%d, skipped=%d, errors=%d",
		processCount, moduleCount, skipCount, errorCount)

	if moduleCount == 0 && processCount > 0 {
		log.Printf("[WARN] [DLL] No modules collected - possible permission or architecture issue (32-bit vs 64-bit)")
	}

	if processCount == 0 {
		log.Printf("[WARN] [DLL] No processes found at all - CreateToolhelp32Snapshot may have failed silently")
	}

	if len(dlls) > 0 {
		log.Printf("[INFO] [DLL] Collecting signatures for %d DLLs...", len(dlls))
		sigMap := batchGetDLLSignatures(dlls)
		for i := range dlls {
			dllPath := dlls[i].Path
			if sig, ok := sigMap[dllPath]; ok {
				dlls[i].IsSigned = sig.IsSigned
				dlls[i].Signer = sig.Signer
			} else if sig, ok := sigMap[strings.ToLower(dllPath)]; ok {
				dlls[i].IsSigned = sig.IsSigned
				dlls[i].Signer = sig.Signer
			} else if sig, ok := sigMap[strings.ToUpper(dllPath)]; ok {
				dlls[i].IsSigned = sig.IsSigned
				dlls[i].Signer = sig.Signer
			}
		}
		log.Printf("[INFO] [DLL] Signature collection completed")
	}

	return dlls, nil
}

type DLLSignature struct {
	IsSigned bool
	Signer   string
}

func batchGetDLLSignatures(dlls []DLLModuleInfo) map[string]DLLSignature {
	result := make(map[string]DLLSignature)

	if len(dlls) == 0 {
		return result
	}

	pathSet := make(map[string]struct{})
	var pathList []string
	for _, dll := range dlls {
		if dll.Path != "" {
			if _, exists := pathSet[dll.Path]; !exists {
				pathSet[dll.Path] = struct{}{}
				pathList = append(pathList, dll.Path)
			}
		}
	}

	if len(pathList) == 0 {
		return result
	}

	batchSize := 50
	for i := 0; i < len(pathList); i += batchSize {
		end := i + batchSize
		if end > len(pathList) {
			end = len(pathList)
		}
		batch := pathList[i:end]

		script := `$paths = @('%s')
foreach ($p in $paths) {
	$sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction SilentlyContinue
	$status = 'Unsigned'
	$signer = ''
	if ($sig.Status -eq 'Valid') { $status = 'Signed' }
	if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
	[PSCustomObject]@{
		p = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($p))
		s = $status
		si = $signer
	}
} | ConvertTo-Json -Compress`

		psPaths := strings.Join(batch, "','")
		script = fmt.Sprintf(script, psPaths)

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		cmdResult := utils.RunPowerShellWithContext(ctx, script)
		if !cmdResult.Success() || cmdResult.Output == "" {
			continue
		}

		var sigResults []struct {
			P  string `json:"p"`
			S  string `json:"s"`
			Si string `json:"si"`
		}

		if strings.HasPrefix(cmdResult.Output, "[") {
			if err := json.Unmarshal([]byte(cmdResult.Output), &sigResults); err != nil {
				log.Printf("[WARN] [DLL] batchGetDLLSignatures: JSON parse error: %v", err)
				continue
			}
		} else if strings.HasPrefix(cmdResult.Output, "{") {
			var single struct {
				P  string `json:"p"`
				S  string `json:"s"`
				Si string `json:"si"`
			}
			if err := json.Unmarshal([]byte(cmdResult.Output), &single); err == nil && single.P != "" {
				sigResults = append(sigResults, single)
			}
		}

		for _, sr := range sigResults {
			pathBytes, err := base64.StdEncoding.DecodeString(sr.P)
			if err != nil {
				log.Printf("[WARN] [DLL] batchGetDLLSignatures: base64 decode error: %v, path: %s", err, sr.P)
				continue
			}
			decodedPath := string(pathBytes)
			result[decodedPath] = DLLSignature{
				IsSigned: sr.S == "Signed",
				Signer:   sr.Si,
			}
		}
	}

	return result
}

func enumProcessModules(pid int, processName string) ([]DLLModuleInfo, error) {
	modules := make([]DLLModuleInfo, 0)

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return modules, fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	var moduleCount uint32
	err = windows.EnumProcessModules(hProcess, nil, 0, &moduleCount)
	if err != nil {
		return modules, fmt.Errorf("EnumProcessModules (size) failed: %w", err)
	}

	if moduleCount == 0 {
		return modules, nil
	}

	handleSize := unsafe.Sizeof(windows.Handle(0))
	numModules := int(moduleCount) / int(handleSize)
	if numModules <= 0 {
		numModules = 1
	}

	moduleHandles := make([]windows.Handle, numModules)
	var bytesNeeded uint32
	err = windows.EnumProcessModules(hProcess, &moduleHandles[0], uint32(len(moduleHandles))*uint32(handleSize), &bytesNeeded)
	if err != nil {
		return modules, fmt.Errorf("EnumProcessModules (enum) failed: %w", err)
	}

	actualModuleCount := int(bytesNeeded) / int(handleSize)
	if actualModuleCount > numModules {
		actualModuleCount = numModules
	}

	for i := 0; i < actualModuleCount; i++ {
		hModule := moduleHandles[i]
		if hModule == 0 {
			continue
		}

		var modName [windows.MAX_PATH]uint16
		err = windows.GetModuleBaseName(hProcess, hModule, &modName[0], uint32(len(modName)))
		if err != nil {
			continue
		}

		var pathBuffer [windows.MAX_PATH]uint16
		err = windows.GetModuleFileNameEx(hProcess, hModule, &pathBuffer[0], uint32(len(pathBuffer)))
		if err != nil {
			continue
		}

		dll := DLLModuleInfo{
			Name: windows.UTF16ToString(modName[:]),
			Path: windows.UTF16ToString(pathBuffer[:]),
		}

		modules = append(modules, dll)
	}

	return modules, nil
}

func GetProcessDLLs(pid int) ([]DLLModuleInfo, error) {
	return enumProcessModules(pid, fmt.Sprintf("PID_%d", pid))
}

func GetProcessDLLsWithVersion(pid int) ([]DLLModuleInfo, error) {
	dlls, err := GetProcessDLLs(pid)
	if err != nil || len(dlls) == 0 {
		return dlls, err
	}

	paths := make([]string, len(dlls))
	for i, d := range dlls {
		paths[i] = d.Path
	}

	versions, _ := GetDLLVersionsBatch(paths)

	for i, d := range dlls {
		if v, ok := versions[d.Path]; ok {
			dlls[i].Version = v
		}
	}

	return dlls, nil
}

func GetDLLVersion(dllPath string) string {
	if runtime.GOOS != "windows" {
		return ""
	}

	dllCacheMu.RLock()
	if version, ok := dllVersionCache[dllPath]; ok {
		dllCacheMu.RUnlock()
		return version
	}
	dllCacheMu.RUnlock()

	select {
	case dllFetchSem <- struct{}{}:
		defer func() { <-dllFetchSem }()
	default:
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := fmt.Sprintf(`(Get-Item '%s' -ErrorAction SilentlyContinue).VersionInfo | Select-Object -ExpandProperty FileVersion`, strings.ReplaceAll(dllPath, "'", "''"))
	result := utils.RunPowerShellWithContext(ctx, cmd)
	version := ""
	if result.Success() && result.Output != "" {
		version = strings.TrimSpace(result.Output)
	}

	dllCacheMu.Lock()
	dllVersionCache[dllPath] = version
	dllCacheMu.Unlock()

	return version
}

func IsDLLLoaded(dllName string) bool {
	dlls, err := ListLoadedDLLs()
	if err != nil {
		return false
	}

	for _, dll := range dlls {
		if strings.Contains(strings.ToLower(dll.Name), strings.ToLower(dllName)) {
			return true
		}
	}

	return false
}

func CollectDLLInfo(ctx context.Context) ([]*types.DLLModule, error) {
	collector := NewDLLInfoCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, err
	}

	dlls := make([]*types.DLLModule, 0, len(results))
	for _, r := range results {
		if d, ok := r.(*types.DLLModule); ok {
			dlls = append(dlls, d)
		}
	}
	return dlls, nil
}

func GetDLLVersionsBatch(paths []string) (map[string]string, error) {
	results := make(map[string]string)
	if len(paths) == 0 {
		return results, nil
	}

	batchSize := 200
	for i := 0; i < len(paths); i += batchSize {
		end := i + batchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]

		batchResults, err := fetchDLLVersionsFromFile(batch)
		if err != nil {
			log.Printf("[WARN] GetDLLVersionsBatch: batch fetch failed: %v", err)
			continue
		}
		for k, v := range batchResults {
			results[k] = v
		}
	}

	return results, nil
}

func fetchDLLVersionsFromFile(paths []string) (map[string]string, error) {
	if len(paths) == 0 {
		return make(map[string]string), nil
	}

	tmpFile := filepath.Join(os.TempDir(), "winalog_dll_paths.txt")
	tmpFile = strings.ReplaceAll(tmpFile, "\\", "\\\\")

	content := strings.Join(paths, "\r\n")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	psScript := fmt.Sprintf(`Get-Content '%s' | ForEach-Object { 
		$v = (Get-Item "$_" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
		if (-not $v) { $v = '' }
		[PSCustomObject]@{p="$_";v=$v}
	} | ConvertTo-Json -Compress`, tmpFile)

	result := utils.RunPowerShell(psScript)
	if !result.Success() {
		return nil, fmt.Errorf("PowerShell failed: %v", result.Error)
	}

	return parseDLLVersionResults(result.Output)
}

func parseDLLVersionResults(jsonOutput string) (map[string]string, error) {
	results := make(map[string]string)
	if jsonOutput == "" || jsonOutput == "null" {
		return results, nil
	}

	jsonOutput = strings.TrimSpace(jsonOutput)

	var items []struct {
		P string `json:"p"`
		V string `json:"v"`
	}

	if strings.HasPrefix(jsonOutput, "[") {
		if err := json.Unmarshal([]byte(jsonOutput), &items); err != nil {
			log.Printf("[WARN] parseDLLVersionResults: failed to parse JSON array: %v", err)
			return results, nil
		}
	} else {
		var single struct {
			P string `json:"p"`
			V string `json:"v"`
		}
		if err := json.Unmarshal([]byte(jsonOutput), &single); err != nil {
			log.Printf("[WARN] parseDLLVersionResults: failed to parse single item: %v", err)
			return results, nil
		}
		if single.P != "" {
			items = append(items, single)
		}
	}

	for _, item := range items {
		results[item.P] = item.V
	}

	return results, nil
}

func ClearDLLVersionCache() {
	dllCacheMu.Lock()
	dllVersionCache = make(map[string]string)
	dllCacheMu.Unlock()
}
