package types

import (
	"time"
)

type SystemInfo struct {
	Hostname     string        `json:"hostname"`
	Domain       string        `json:"domain"`
	OSName       string        `json:"os_name"`
	OSVersion    string        `json:"os_version"`
	Architecture string        `json:"architecture"`
	Admin        bool          `json:"is_admin"`
	TimeZone     string        `json:"timezone"`
	LocalTime    time.Time     `json:"local_time"`
	Uptime       time.Duration `json:"uptime"`
	CPUCores     int           `json:"cpu_cores"`
	CPUModel     string        `json:"cpu_model"`
	MemoryTotal  uint64        `json:"memory_total"`
	MemoryFree   uint64        `json:"memory_free"`
	BootTime     time.Time     `json:"boot_time"`
}

type SignatureInfo struct {
	Status     string `json:"status"`
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	ValidFrom  string `json:"valid_from"`
	ValidTo    string `json:"valid_to"`
	Thumbprint string `json:"thumbprint"`
	SerialNum  string `json:"serial_number"`
}

type ProcessInfo struct {
	PID         int32          `json:"pid"`
	Name        string         `json:"name"`
	PPID        int32          `json:"ppid"`
	Path        string         `json:"path"`
	CommandLine string         `json:"command_line"`
	User        string         `json:"user"`
	CPUPercent  float64        `json:"cpu_percent"`
	MemoryMB    float64        `json:"memory_mb"`
	StartTime   time.Time      `json:"start_time"`
	Signature   *SignatureInfo `json:"signature,omitempty"`
	IsSigned    bool           `json:"is_signed"`
	HashSHA256  string         `json:"hash_sha256"`
	IsElevated  bool           `json:"is_elevated"`
}

type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
}

type UserAccount struct {
	SID         string        `json:"sid"`
	Name        string        `json:"name"`
	Domain      string        `json:"domain"`
	FullName    string        `json:"full_name"`
	Type        string        `json:"type"`
	Enabled     bool          `json:"enabled"`
	LastLogin   time.Time     `json:"last_login"`
	PasswordAge time.Duration `json:"password_age"`
	PasswordExp bool          `json:"password_expires"`
	HomeDir     string        `json:"home_dir"`
	ProfilePath string        `json:"profile_path"`
}

type RegistryInfo struct {
	Path           string `json:"path"`
	Name           string `json:"name"`
	Value          string `json:"value"`
	Type           string `json:"type"`
	Source         string `json:"source"`
	Enabled        bool   `json:"enabled"`
	Description    string `json:"description,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
	ImagePath      string `json:"image_path,omitempty"`
	Command        string `json:"command,omitempty"`
	ServiceType    string `json:"service_type,omitempty"`
	StartType      string `json:"start_type,omitempty"`
	Debugger       string `json:"debugger,omitempty"`
	DllName        string `json:"dll_name,omitempty"`
	GlobalFlag     string `json:"global_flag,omitempty"`
	VerifierDlls   string `json:"verifier_dlls,omitempty"`
	FilterFullPath string `json:"filter_full_path,omitempty"`
}

type RegistryPersistence struct {
	RunKeys          []*RegistryInfo `json:"run_keys"`
	UserInit         []*RegistryInfo `json:"user_init"`
	TaskScheduler    []*RegistryInfo `json:"task_scheduler"`
	Services         []*RegistryInfo `json:"services"`
	IFEO             []*RegistryInfo `json:"ifeo"`
	AppInitDLLs      []*RegistryInfo `json:"app_init_dlls"`
	KnownDLLs        []*RegistryInfo `json:"known_dlls"`
	BootExecute      []*RegistryInfo `json:"boot_execute"`
	AppCertDlls      []*RegistryInfo `json:"appcert_dlls"`
	LSASSettings     []*RegistryInfo `json:"lsa_settings"`
	ShellExtensions  []*RegistryInfo `json:"shell_extensions"`
	BrowserHelpers   []*RegistryInfo `json:"browser_helpers"`
	StartupFolders   []*RegistryInfo `json:"startup_folders"`
}

type ScheduledTask struct {
	Name        string        `json:"name"`
	Path        string        `json:"path"`
	State       string        `json:"state"`
	LastRun     time.Time     `json:"last_run"`
	NextRun     time.Time     `json:"next_run"`
	LastResult  int           `json:"last_result"`
	Description string        `json:"description"`
	Author      string        `json:"author"`
	Actions     []TaskAction  `json:"actions"`
	Triggers    []TaskTrigger `json:"triggers"`
}

type TaskAction struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Args string `json:"args"`
}

type TaskTrigger struct {
	Type  string    `json:"type"`
	Start time.Time `json:"start"`
}

type DriverInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	Started     bool   `json:"started"`
	FilePath    string `json:"file_path"`
	HashSHA256  string `json:"hash_sha256"`
	Signature   string `json:"signature"`
	Signer      string `json:"signer"`
}

type EnvInfo struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type DLLModule struct {
	ProcessID   int32          `json:"process_id"`
	ProcessName string         `json:"process_name"`
	BaseAddress string         `json:"base_address"`
	Size        uint32         `json:"size"`
	Path        string         `json:"path"`
	HashSHA256  string         `json:"hash_sha256"`
	Version     string         `json:"version"`
	Signature   *SignatureInfo `json:"signature,omitempty"`
	IsSigned    bool           `json:"is_signed"`
}

type WMIProvider struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	CLSID     string `json:"clsid"`
	Enabled   bool   `json:"enabled"`
	Owner     string `json:"owner"`
}

type WMISubscription struct {
	Name         string    `json:"name"`
	Namespace    string    `json:"namespace"`
	Filter       string    `json:"filter"`
	Consumer     string    `json:"consumer"`
	Type         string    `json:"type"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"last_modified"`
}

type PrefetchEntry struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	LastRunTime time.Time `json:"last_run_time"`
	RunCount    int       `json:"run_count"`
	CollectedAt time.Time `json:"collected_at"`
}

type ShimCacheEntry struct {
	Path          string    `json:"path"`
	LastModified  time.Time `json:"last_modified"`
	ExecutionTime time.Time `json:"execution_time"`
	CollectedAt   time.Time `json:"collected_at"`
}

type AmcacheEntry struct {
	Path        string    `json:"path"`
	SHA1        string    `json:"sha1"`
	BinaryType  string    `json:"binary_type"`
	CollectedAt time.Time `json:"collected_at"`
}

type UserAssistEntry struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	FocusCount  int       `json:"focus_count"`
	TimeFocused int64     `json:"time_focused"`
	LastUsed    time.Time `json:"last_used"`
	CollectedAt time.Time `json:"collected_at"`
}

type USNJournalEntry struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	CollectedAt time.Time `json:"collected_at"`
}
