//go:build windows
// +build windows

package forensics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/version"
	"golang.org/x/sys/windows"
)

type MemoryDumpResult struct {
	ProcessID   uint32            `json:"process_id"`
	ProcessName string            `json:"process_name"`
	DumpPath    string            `json:"dump_path"`
	DumpSize    int64             `json:"dump_size"`
	DumpTime    time.Time         `json:"dump_time"`
	Hash        string            `json:"hash"`
	Modules     []MemoryModule    `json:"modules,omitempty"`
	Permissions MemoryPermissions `json:"permissions"`
	Error       string            `json:"error,omitempty"`
}

type MemoryModule struct {
	BaseAddress uint64 `json:"base_address"`
	Size        uint64 `json:"size"`
	Name        string `json:"name"`
	Path        string `json:"path"`
}

type MemoryPermissions struct {
	Readable    bool `json:"readable"`
	Writable    bool `json:"writable"`
	Executable  bool `json:"executable"`
	CopyOnWrite bool `json:"copy_on_write"`
}

type MemoryRegion struct {
	BaseAddress    uint64 `json:"base_address"`
	AllocationBase uint64 `json:"allocation_base"`
	RegionSize     uint64 `json:"region_size"`
	State          uint32 `json:"state"`
	Protect        uint32 `json:"protect"`
	Type           uint32 `json:"type"`
}

type MemoryCollector struct {
	outputDir      string
	includeModules bool
	includeStacks  bool
}

func NewMemoryCollector(outputDir string) *MemoryCollector {
	return &MemoryCollector{
		outputDir:      outputDir,
		includeModules: true,
		includeStacks:  false,
	}
}

func (c *MemoryCollector) SetIncludeModules(include bool) {
	c.includeModules = include
}

func (c *MemoryCollector) SetIncludeStacks(include bool) {
	c.includeStacks = include
}

func (c *MemoryCollector) CollectProcessMemory(pid uint32) (*MemoryDumpResult, error) {
	result := &MemoryDumpResult{
		ProcessID:   pid,
		ProcessName: fmt.Sprintf("Process_%d", pid),
		DumpTime:    time.Now(),
	}

	info, err := getProcessInfo(pid)
	if err == nil {
		result.ProcessName = info.Name
	}

	dumpPath := filepath.Join(c.outputDir, fmt.Sprintf("memory_%d_%s.raw", pid, time.Now().Format("20060102_150405")))

	dumpData, err := readProcessMemory(pid)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	file, err := os.Create(dumpPath)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer file.Close()

	written, err := file.Write(dumpData)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.DumpSize = int64(written)
	result.DumpPath = dumpPath
	result.Hash = calculateMemoryHash(dumpData)
	result.Permissions = MemoryPermissions{Readable: true}

	if c.includeModules {
		modules, _ := c.collectModules(pid)
		result.Modules = modules
	}

	return result, nil
}

func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error) {
	result := &MemoryDumpResult{
		ProcessID:   0,
		ProcessName: "System",
		DumpTime:    time.Now(),
	}

	dumpPath := filepath.Join(c.outputDir, fmt.Sprintf("system_memory_%s.raw", time.Now().Format("20060102_150405")))

	dumpData, err := readSystemMemory()
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	file, err := os.Create(dumpPath)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer file.Close()

	written, err := file.Write(dumpData)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.DumpSize = int64(written)
	result.DumpPath = dumpPath
	result.Hash = calculateMemoryHash(dumpData)

	return result, nil
}

func (c *MemoryCollector) collectModules(pid uint32) ([]MemoryModule, error) {
	modules := make([]MemoryModule, 0)

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return modules, err
	}
	defer windows.CloseHandle(hProcess)

	var moduleCount uint32
	err = windows.EnumProcessModules(hProcess, nil, 0, &moduleCount)
	if err != nil {
		return modules, err
	}

	handleSize := unsafe.Sizeof(windows.Handle(0))
	moduleHandles := make([]windows.Handle, moduleCount/uint32(handleSize))
	err = windows.EnumProcessModules(hProcess, &moduleHandles[0], moduleCount, &moduleCount)
	if err != nil {
		return modules, err
	}

	for _, hModule := range moduleHandles {
		var modName [windows.MAX_PATH]uint16
		windows.GetModuleBaseName(hProcess, hModule, &modName[0], uint32(len(modName)))

		var modInfo windows.ModuleInfo
		err := windows.GetModuleInformation(hProcess, hModule, &modInfo, uint32(unsafe.Sizeof(modInfo)))
		if err != nil {
			continue
		}

		modules = append(modules, MemoryModule{
			BaseAddress: uint64(hModule),
			Size:        uint64(modInfo.SizeOfImage),
			Name:        windows.UTF16ToString(modName[:]),
		})
	}

	return modules, nil
}

var (
	ErrProcessMemoryNotImplemented = fmt.Errorf("process memory dump not implemented")
	ErrSystemMemoryNotImplemented  = fmt.Errorf("system memory dump not implemented")
)

type processInfo struct {
	Name string
}

func getProcessInfo(pid uint32) (processInfo, error) {
	if runtime.GOOS != "windows" {
		return processInfo{Name: fmt.Sprintf("Process_%d", pid)}, nil
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return processInfo{Name: fmt.Sprintf("Process_%d", pid)}, err
	}
	defer windows.CloseHandle(hProcess)

	var name [windows.MAX_PATH]uint16
	size := uint32(len(name))
	if err := windows.QueryFullProcessImageName(hProcess, 0, &name[0], &size); err != nil {
		return processInfo{Name: fmt.Sprintf("Process_%d", pid)}, err
	}

	return processInfo{Name: windows.UTF16ToString(name[:])}, nil
}

func readProcessMemory(pid uint32) ([]byte, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	var memInfo windows.MemoryBasicInformation
	var buffer bytes.Buffer

	address := uintptr(0)
	for {
		err := windows.VirtualQueryEx(hProcess, address, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		if memInfo.State == windows.MEM_COMMIT && memInfo.Protect&0x02 != 0 {
			size := uint64(memInfo.RegionSize)

			if size > 100*1024*1024 {
				size = 100 * 1024 * 1024
			}

			data := make([]byte, size)
			var nr uintptr
			err := windows.ReadProcessMemory(
				hProcess,
				memInfo.BaseAddress,
				&data[0],
				uintptr(len(data)),
				&nr,
			)

			if err == nil && nr > 0 {
				buffer.Write(data[:nr])
			}
		}

		address = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
		if address == 0 {
			break
		}
	}

	return buffer.Bytes(), nil
}

func readSystemMemory() ([]byte, error) {
	return readSystemMemoryImpl()
}

func readSystemMemoryImpl() ([]byte, error) {
	privileged, err := hasDebugPrivilege()
	if err != nil {
		return nil, fmt.Errorf("failed to check privileges: %w", err)
	}
	if !privileged {
		return nil, fmt.Errorf("system memory dump requires administrator privileges with SeDebugPrivilege enabled")
	}

	const (
		DevicePhysicalMemory = `\\.\Global\Device\PhysicalMemory`
		SectionBasicInfo     = 0
	)

	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(DevicePhysicalMemory),
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open physical memory device: %w", err)
	}
	defer windows.CloseHandle(handle)

	var sectionBasicInfo struct {
		BaseAddress       uint64
		SectionSize       uint64
		Attributes        uint32
		SessionId         uint32
		Radix             uint32
		MappingOffsetLow  uint32
		MappingOffsetHigh uint32
	}
	var returnedLen uint32

	err = windows.DeviceIoControl(
		handle,
		0x9000003C,
		nil,
		0,
		(*byte)(unsafe.Pointer(&sectionBasicInfo)),
		uint32(unsafe.Sizeof(sectionBasicInfo)),
		&returnedLen,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query physical memory: %w", err)
	}

	var buffer bytes.Buffer
	chunkSize := uint64(1024 * 1024)
	offset := sectionBasicInfo.BaseAddress

	for offset < sectionBasicInfo.BaseAddress+sectionBasicInfo.SectionSize {
		size := chunkSize
		if offset+size > sectionBasicInfo.BaseAddress+sectionBasicInfo.SectionSize {
			size = sectionBasicInfo.BaseAddress + sectionBasicInfo.SectionSize - offset
		}

		var data bytes.Buffer

		readAddr := offset
		for readAddr < offset+size {
			readSize := chunkSize
			if readAddr+readSize > offset+size {
				readSize = offset + size - readAddr
			}

			readBuf := make([]byte, readSize)
			var nr uint32
			ovec := &windows.Overlapped{
				Offset:     uint32(readAddr & 0xFFFFFFFF),
				OffsetHigh: uint32(readAddr >> 32),
			}

			err := windows.ReadFile(
				handle,
				readBuf,
				&nr,
				ovec,
			)
			if err != nil && err != windows.ERROR_IO_PENDING {
				break
			}

			written, _ := data.Write(readBuf[:nr])
			if written == 0 {
				break
			}
			readAddr += uint64(written)
		}

		if data.Len() > 0 {
			buffer.Write(data.Bytes())
		}
		offset += size

		if buffer.Len() > 100*1024*1024 {
			break
		}
	}

	return buffer.Bytes(), nil
}

func hasDebugPrivilege() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return false, fmt.Errorf("failed to lookup SeDebugPrivilege: %w", err)
	}

	enable := uint32(1)
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: enable},
		},
	}

	var retLen uint32
	err = windows.AdjustTokenPrivileges(token, false, &tp, windows.TOKEN_ADJUST_PRIVILEGES, nil, &retLen)
	if err != nil {
		return false, fmt.Errorf("failed to adjust token privileges: %w", err)
	}

	return true, nil
}

func calculateMemoryHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type MemoryAnalysis struct {
	DumpFile           string        `json:"dump_file"`
	Hash               string        `json:"hash"`
	AnalysisTime       time.Time     `json:"analysis_time"`
	ProcessTree        []ProcessNode `json:"process_tree,omitempty"`
	NetworkConnections []NetworkConn `json:"network_connections,omitempty"`
	LoadedDLLs         []DLLInfo     `json:"loaded_dlls,omitempty"`
	SuspiciousAPIs     []APICall     `json:"suspicious_apis,omitempty"`
}

type ProcessNode struct {
	PID      uint32        `json:"pid"`
	Name     string        `json:"name"`
	PPID     uint32        `json:"ppid"`
	Children []ProcessNode `json:"children,omitempty"`
}

type NetworkConn struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	PID        uint32 `json:"pid"`
}

type DLLInfo struct {
	Name        string `json:"name"`
	BaseAddress uint64 `json:"base_address"`
	Size        uint32 `json:"size"`
	Path        string `json:"path"`
}

type APICall struct {
	Address   uint64   `json:"address"`
	APIName   string   `json:"api_name"`
	Module    string   `json:"module"`
	Arguments []string `json:"arguments,omitempty"`
}

func AnalyzeMemoryDump(dumpPath string) (*MemoryAnalysis, error) {
	analysis := &MemoryAnalysis{
		DumpFile:     dumpPath,
		AnalysisTime: time.Now(),
	}

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dump file: %w", err)
	}

	hash := sha256.Sum256(data)
	analysis.Hash = hex.EncodeToString(hash[:])

	return analysis, nil
}

func ExtractProcessTree(dumpData []byte) ([]ProcessNode, error) {
	processes := make([]ProcessNode, 0)

	patterns := []struct {
		name    string
		prefix  []byte
		minSize int
	}{
		{"svchost.exe", []byte("svchost.exe"), 12},
		{"explorer.exe", []byte("explorer.exe"), 14},
		{"cmd.exe", []byte("cmd.exe"), 8},
		{"powershell.exe", []byte("powershell.exe"), 16},
		{"lsass.exe", []byte("lsass.exe"), 10},
		{"services.exe", []byte("services.exe"), 13},
		{"winlogon.exe", []byte("winlogon.exe"), 13},
		{"csrss.exe", []byte("csrss.exe"), 10},
		{"smss.exe", []byte("smss.exe"), 10},
	}

	seen := make(map[string]bool)

	for _, pattern := range patterns {
		for i := 0; i < len(dumpData)-pattern.minSize; i++ {
			if bytes.HasPrefix(dumpData[i:], pattern.prefix) {
				name := pattern.name
				if !seen[name] {
					seen[name] = true
					processes = append(processes, ProcessNode{
						Name: name,
						PID:  0,
						PPID: 0,
					})
				}
				i += pattern.minSize
			}
		}
	}

	return processes, nil
}

func FindNetworkConnections(dumpData []byte) ([]NetworkConn, error) {
	connections := make([]NetworkConn, 0)

	ipPortPattern := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})`)
	hexIPPattern := regexp.MustCompile(`((?:0x[0-9a-fA-F]{8}){4})`)

	matches := ipPortPattern.FindAllSubmatch(dumpData, -1)
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) >= 3 {
			ip := string(match[1])
			port := string(match[2])

			key := ip + ":" + port
			if !seen[key] && !strings.HasPrefix(ip, "0.") && !strings.HasPrefix(ip, "255.") {
				seen[key] = true
				connections = append(connections, NetworkConn{
					Protocol:   "TCP",
					LocalAddr:  ip + ":" + port,
					RemoteAddr: "",
					State:      "",
					PID:        0,
				})
			}
		}
	}

	_ = hexIPPattern

	return connections, nil
}

func FindSuspiciousAPI(dumpData []byte) ([]APICall, error) {
	apiCalls := make([]APICall, 0)

	suspiciousAPIs := []string{
		"VirtualAlloc",
		"VirtualProtect",
		"WriteProcessMemory",
		"CreateRemoteThread",
		"ShellExecute",
		"WinExec",
		"CreateProcess",
		"LoadLibrary",
		"GetProcAddress",
		"WriteFile",
		"InternetOpen",
		"InternetConnect",
		"URLDownloadToFile",
	}

	seen := make(map[string]bool)

	for _, apiName := range suspiciousAPIs {
		searchBytes := []byte(apiName)
		for i := 0; i < len(dumpData)-len(searchBytes); i++ {
			if bytes.Contains(dumpData[i:i+len(searchBytes)], searchBytes) {
				key := apiName
				if !seen[key] {
					seen[key] = true
					apiCalls = append(apiCalls, APICall{
						Address:   uint64(i),
						APIName:   apiName,
						Module:    "unknown",
						Arguments: []string{},
					})
				}
				i += len(searchBytes)
			}
		}
	}

	return apiCalls, nil
}

type MemoryDumpMetadata struct {
	Version      string    `json:"version"`
	Timestamp    time.Time `json:"timestamp"`
	Hostname     string    `json:"hostname"`
	ProcessID    uint32    `json:"process_id,omitempty"`
	ProcessName  string    `json:"process_name,omitempty"`
	DumpType     string    `json:"dump_type"`
	Size         int64     `json:"size"`
	Hash         string    `json:"hash"`
	Algorithm    string    `json:"algorithm"`
	OSVersion    string    `json:"os_version"`
	Architecture string    `json:"architecture"`
}

func (m *MemoryDumpMetadata) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func (m *MemoryDumpMetadata) Save(path string) error {
	data, err := m.ToJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func CreateMemoryDumpMetadata(dumpPath string, dumpType string, hostname string, pid uint32, processName string) (*MemoryDumpMetadata, error) {
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)

	metadata := &MemoryDumpMetadata{
		Version:      version.Version,
		Timestamp:    time.Now(),
		Hostname:     hostname,
		ProcessID:    pid,
		ProcessName:  processName,
		DumpType:     dumpType,
		Size:         int64(len(data)),
		Hash:         hex.EncodeToString(hash[:]),
		Algorithm:    "SHA256",
		OSVersion:    "Windows",
		Architecture: "x64",
	}

	return metadata, nil
}

type MemoryCollectionRequest struct {
	PID            uint32   `json:"pid,omitempty"`
	IncludeModules bool     `json:"include_modules"`
	IncludeStacks  bool     `json:"include_stacks"`
	OutputDir      string   `json:"output_dir"`
	FilterPatterns []string `json:"filter_patterns,omitempty"`
}

type MemoryCollectionResponse struct {
	Success bool                `json:"success"`
	Dumps   []*MemoryDumpResult `json:"dumps"`
	Errors  []string            `json:"errors,omitempty"`
}

func CollectMemoryForProcess(req *MemoryCollectionRequest) (*MemoryCollectionResponse, error) {
	response := &MemoryCollectionResponse{
		Success: true,
		Dumps:   make([]*MemoryDumpResult, 0),
		Errors:  make([]string, 0),
	}

	if req.OutputDir == "" {
		req.OutputDir = os.TempDir()
	}

	collector := NewMemoryCollector(req.OutputDir)
	collector.SetIncludeModules(req.IncludeModules)
	collector.SetIncludeStacks(req.IncludeStacks)

	if req.PID > 0 {
		result, err := collector.CollectProcessMemory(req.PID)
		if err != nil {
			response.Errors = append(response.Errors, err.Error())
			response.Success = false
		} else {
			response.Dumps = append(response.Dumps, result)
		}
	} else {
		result, err := collector.CollectSystemMemory()
		if err != nil {
			response.Errors = append(response.Errors, err.Error())
			response.Success = false
		} else {
			response.Dumps = append(response.Dumps, result)
		}
	}

	return response, nil
}

type MemoryRegions struct {
	Regions []MemoryRegion `json:"regions"`
}

func QueryMemoryRegions(pid uint32) (*MemoryRegions, error) {
	regions := make([]MemoryRegion, 0)

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return &MemoryRegions{Regions: regions}, err
	}
	defer windows.CloseHandle(hProcess)

	var memInfo windows.MemoryBasicInformation
	var address uintptr = 0

	for {
		err := windows.VirtualQueryEx(hProcess, address, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		regions = append(regions, MemoryRegion{
			BaseAddress:    uint64(memInfo.BaseAddress),
			AllocationBase: uint64(memInfo.AllocationBase),
			RegionSize:     uint64(memInfo.RegionSize),
			State:          uint32(memInfo.State),
			Protect:        uint32(memInfo.Protect),
			Type:           uint32(memInfo.Type),
		})

		address = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
		if address == 0 {
			break
		}
	}

	return &MemoryRegions{Regions: regions}, nil
}

func FormatMemoryDumpResult(result *MemoryDumpResult) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Process ID: %d\n", result.ProcessID))
	buf.WriteString(fmt.Sprintf("Process Name: %s\n", result.ProcessName))
	buf.WriteString(fmt.Sprintf("Dump Path: %s\n", result.DumpPath))
	buf.WriteString(fmt.Sprintf("Dump Size: %d bytes\n", result.DumpSize))
	buf.WriteString(fmt.Sprintf("Dump Time: %s\n", result.DumpTime.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Hash: %s\n", result.Hash))
	if result.Error != "" {
		buf.WriteString(fmt.Sprintf("Error: %s\n", result.Error))
	}
	if len(result.Modules) > 0 {
		buf.WriteString(fmt.Sprintf("Modules: %d\n", len(result.Modules)))
	}
	return buf.String()
}
