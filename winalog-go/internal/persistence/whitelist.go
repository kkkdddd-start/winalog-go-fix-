//go:build windows

package persistence

import (
	"strings"
	"sync"
)

type WhitelistType int

const (
	WhitelistTypeRunKey WhitelistType = iota
	WhitelistTypeService
	WhitelistTypeBHO
	WhitelistTypePrintMonitor
	WhitelistTypeWinsock
	WhitelistTypeLSA
	WhitelistTypeBootExecute
	WhitelistTypeAppInit
	WhitelistTypeAccessibility
	WhitelistTypeCOM
	WhitelistTypeWMI
	WhitelistTypeScheduledTask
)

type WhitelistEntry struct {
	Key    string
	Type   WhitelistType
	Reason string
	Source string
}

type Whitelist struct {
	entries map[string]*WhitelistEntry
	loaded  bool
	loadMu  sync.Mutex
	once    sync.Once
}

var GlobalWhitelist = &Whitelist{
	entries: make(map[string]*WhitelistEntry),
	loaded:  false,
}

func (w *Whitelist) Add(key string, wtype WhitelistType, reason, source string) {
	w.entries[key] = &WhitelistEntry{
		Key:    key,
		Type:   wtype,
		Reason: reason,
		Source: source,
	}
}

func (w *Whitelist) IsAllowed(key string) bool {
	w.ensureLoaded()
	keyLower := strings.ToLower(key)
	for _, entry := range w.entries {
		if w.keyMatches(keyLower, strings.ToLower(entry.Key)) {
			return true
		}
	}
	return false
}

func (w *Whitelist) IsAllowedByType(key string, wtype WhitelistType) bool {
	w.ensureLoaded()
	keyLower := strings.ToLower(key)
	for _, entry := range w.entries {
		if entry.Type == wtype && w.keyMatches(keyLower, strings.ToLower(entry.Key)) {
			return true
		}
	}
	return false
}

func (w *Whitelist) keyMatches(input, pattern string) bool {
	if strings.Contains(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(input, prefix)
	}
	return input == pattern
}

func (w *Whitelist) ensureLoaded() {
	w.once.Do(w.LoadDefaults)
}

func (w *Whitelist) LoadDefaults() {
	w.loadMu.Lock()
	defer w.loadMu.Unlock()
	if w.loaded {
		return
	}

	w.addRunKeyWhitelist()
	w.addServiceWhitelist()
	w.addBHOWitelist()
	w.addPrintMonitorWhitelist()
	w.addWinsockWhitelist()
	w.addLSAWhitelist()
	w.addBootExecuteWhitelist()
	w.addAccessibilityWhitelist()
	w.addScheduledTaskWhitelist()

	w.loaded = true
}

func (w *Whitelist) addRunKeyWhitelist() {
	microsoftRunKeys := []struct {
		key    string
		reason string
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\DiagTrack`, "Windows Telemetry"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth`, "Windows Security Center"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealthSrm`, "Windows Security Resource Manager"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsDefender`, "Windows Defender"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows Easy Transfer`, "Windows Easy Transfer"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\IME*`, "IME Engine"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemTools`, "System Tools"},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*`, "User Run Key"},
	}

	for _, item := range microsoftRunKeys {
		w.Add(item.key, WhitelistTypeRunKey, item.reason, "microsoft")
	}

	commonSoftwareRunKeys := []struct {
		key    string
		reason string
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AdobeARM`, "Adobe Reader"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Adobe Sync`, "Adobe Creative Cloud"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Apple*`, "Apple Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Google*`, "Google Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Intel*`, "Intel Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\NVIDIA*`, "NVIDIA Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AMD*`, "AMD Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Realtek*`, "Realtek Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Conexant*`, "Conexant Audio"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SynTP*`, "Synaptics Touchpad"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Bluetooth*`, "Bluetooth Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WiFi*`, "WiFi Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Network*`, "Network Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ Dell *`, "Dell Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\HP*`, "HP Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Lenovo*`, "Lenovo Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Asus*`, "Asus Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Acronis*`, "Acronis Software"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TeamViewer`, "TeamViewer"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Steam`, "Steam Gaming"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Spotify`, "Spotify"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDrive`, "Microsoft OneDrive"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Dropbox`, "Dropbox"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Box`, "Box"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Slack`, "Slack"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom`, "Zoom"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Discord`, "Discord"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Teams`, "Microsoft Teams"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Skype`, "Skype"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ZoomUnity*`, "Zoom"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WebEx`, "WebEx"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\GoToMeeting`, "GoToMeeting"},
	}

	for _, item := range commonSoftwareRunKeys {
		w.Add(item.key, WhitelistTypeRunKey, item.reason, "common-software")
	}

	runOnceExKeys := []struct {
		key    string
		reason string
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*`, "RunOnce Key"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\*`, "RunOnceEx Key"},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*`, "User RunOnce Key"},
	}

	for _, item := range runOnceExKeys {
		w.Add(item.key, WhitelistTypeRunKey, item.reason, "microsoft")
	}
}

func (w *Whitelist) addServiceWhitelist() {
	windowsServices := []struct {
		name   string
		reason string
	}{
		{"SecurityHealthService", "Windows Security Center"},
		{"WinDefend", "Windows Defender"},
		{"wscsvc", "Windows Security Center Service"},
		{"mpssvc", "Windows Firewall"},
		{"WdNisSvc", "Windows Defender Network Inspection"},
		{"Sense", "Windows Defender Advanced Threat Protection"},
		{"EventLog", "Windows Event Log"},
		{"RpcSs", "Remote Procedure Call"},
		{"DcomLaunch", "DCOM Server Process Launcher"},
		{"lsass", "Local Security Authority"},
		{"services", "Service Control Manager"},
		{"wininit", "Windows Init"},
		{"winlogon", "Windows Logon"},
		{"csrss", "Client Server Runtime"},
		{"smss", "Session Manager"},
		{"smss.exe", "Session Manager"},
		{"winrm", "Windows Remote Management"},
		{"W32Time", "Windows Time"},
		{"W32tm", "Windows Time"},
		{"Dhcp", "DHCP Client"},
		{"Dnscache", "DNS Client"},
		{"DNS", "DNS Server"},
		{"LanmanServer", "Server"},
		{"LanmanWorkstation", "Workstation"},
		{"BITS", "Background Intelligent Transfer"},
		{"TrustedInstaller", "Windows Module Installer"},
		{"MSiserver", "Windows Installer"},
		{"wuauserv", "Windows Update"},
		{"wusg", "Windows Update"},
		{"BFE", "Base Filtering Engine"},
		{"PolicyAgent", "IPsec Policy Agent"},
		{"IKEEXT", "IKE and AuthIP"},
		{"Netlogon", "Netlogon"},
		{"NTDS", "Active Directory Domain Services"},
		{"kdc", "Kerberos Ticket Granting"},
		{"SamSs", "Security Accounts Manager"},
		{"SSDPSRV", "SSDP Discovery"},
		{"UPNP", "Universal Plug and Play"},
		{"Browser", "Computer Browser"},
		{"CryptSvc", "Cryptographic Services"},
		{"DPS", "Diagnostic Policy Service"},
		{"WdiSystemHost", "Diagnostic System Host"},
		{"WdiServiceHost", "Diagnostic Service Host"},
		{"TrkWks", "Distributed Link Tracking"},
		{"SysMain", "Superfetch"},
		{"Spooler", "Print Spooler"},
		{"PrintNotify", "Printer Extensions"},
		{"Wcmsvc", "Windows Connection Manager"},
		{"wcncsvc", "Windows Connect Now"},
		{"Wdmaud2", "Windows Audio"},
		{"AudioEndpointBuilder", "Audio Endpoint Builder"},
		{"Audiosrv", "Windows Audio"},
		{"stisvc", "Windows Image Acquisition"},
		{"WiaRpc", "Still Image"},
		{"TabletInputService", "Touch Keyboard and Handwriting"},
		{"cbdhsvc", "Clipboard User Service"},
		{"fdPHost", "Function Discovery Provider Host"},
		{"FDResPub", "Function Discovery Resource Publication"},
		{"LicenseManager", "Windows License Manager"},
		{"nhi", "Network Setup Service"},
		{"NetSetupSvc", "Network Setup Service"},
		{"Netman", "Network Connections"},
		{"tmeext", "Telemetry"},
		{"SstpSvc", "SSTP"},
		{"IisAdmin", "IIS Admin"},
		{"W3SVC", "World Wide Web Publishing"},
		{"WAS", "Windows Process Activation"},
		{"MSDTC", "Distributed Transaction Coordinator"},
		{"MicrosoftOfficeSoftwareProtectionPlatform", "Office Licensing"},
		{"SPP", "Software Protection"},
		{"sppsvc", "Software Protection"},
		{"vds", "Virtual Disk"},
		{"VDS", "Virtual Disk Service"},
		{"verifier", "Driver Verifier"},
		{"Vmm", "Hyper-V"},
		{"vmcompute", "Hyper-V Compute"},
		{"vmms", "Hyper-V Virtual Machine Management"},
		{"vmwp", "Hyper-V Virtual Machine Worker"},
		{"HvHost", "Hyper-V Host"},
		{"vmickvpexchange", "Hyper-V"},
		{"vmicguestinterface", "Hyper-V Guest Interface"},
		{"vmicvmsession", "Hyper-V Session"},
		{"vmicvss", "Hyper-V Volume Shadow Copy"},
		{"vmicheartbeat", "Hyper-V Heartbeat"},
		{"vmickvpexchange", "Hyper-V"},
		{"Intmgmt", "Intel Management"},
		{"LManager", "Intel Management"},
		{"LXrun", "Linux Subsystem"},
		{"WslService", "Windows Subsystem for Linux"},
		{"WaaS", "Windows as a Service"},
		{"DoSvc", "Delivery Optimization"},
		{"MapsBroker", "Downloaded Maps"},
		{"DeviceAssociationService", "Device Association"},
		{"AEndpoint", "Azure Endpoint"},
		{"AAD*", "Azure Active Directory"},
		{"cdpusersvc", "CDP User Service"},
		{"AppIDSvc", "Application Identity"},
		{"Appinfo", "Application Information"},
		{"AppMgmt", "Application Management"},
		{"AppReadiness", "App Readiness"},
		{"AppXSvc", "AppX Deployment"},
		{"AudioEndpointBuilder", "Audio Endpoint"},
		{"AxInstSV", "AxInstSV"},
		{"BDESVC", "BitLocker"},
		{"BITS", "Background Intelligent Transfer"},
		{"BrokerInfrastructure", "Background Tasks Infrastructure"},
		{"bthserv", "Bluetooth Support Service"},
		{"CorrespondingSurface*", "Corresponding Surface"},
		{"CoreMessaging", "Core Messaging"},
		{"CoreUIArchitect*", "Core UI"},
		{"CryptSvc", "Cryptographic Services"},
		{"DcomLaunch", "DCOM Launch"},
		{"defragsvc", "Disk Defragmenter"},
		{"DeviceInstall", "Device Install"},
		{"devquerybroker", "Device Query"},
		{"Dhcp", "DHCP Client"},
		{"diagnosticshub.standardcollector.service", "Diagnostics Hub"},
		{"DiagTrack", "Connected User Experience"},
		{"DmEnrollment*", "Device Enrollment"},
		{"dmwappushservice", "Push Messaging"},
		{"Dnscache", "DNS Client"},
		{"DoSvc", "Delivery Optimization"},
		{"DPS", "Diagnostic Policy Service"},
		{"DsmSvc", "Device Setup Manager"},
		{"DsSvc", "Data Sharing Service"},
		{"DusmSvc", "Data Usage"},
		{"EapHost", "Extensible Authentication"},
		{"EntAppSvc", "Enterprise App Management"},
		{"fdPHost", "Function Discovery Provider Host"},
		{"FDResPub", "Function Discovery Resource Publication"},
		{"fhsmithsvc", "Windows Faulkner"},
		{"FontCache", "Font Cache"},
		{"FrameServer", "Frame Server"},
		{"gpsvc", "Group Policy"},
		{"hidserv", "Human Interface Device Service"},
		{"HvHost", "Hyper-V Host"},
		{"icssvc", "Windows Hotspot"},
		{"IKEEXT", "IKE and AuthIP"},
		{"InstallService", "Microsoft Store Install Service"},
		{"iphlpsvc", "IPv6 Tunnel Driver"},
		{"IpxlatCfgSvc", "IP Translation Configuration"},
		{"KeyIso", "Key Storage"},
		{"KtmRm", "KtmRm"},
		{"LanmanServer", "Server"},
		{"LanmanWorkstation", "Workstation"},
		{"lfsvc", "Geolocation Service"},
		{"LicenseManager", "License Manager"},
		{"lltdsvc", "Link Layer Topology Discovery"},
		{"LSM", "Local Session Manager"},
		{"MapsBroker", "Downloaded Maps"},
		{"mpsdrv", "Microsoft Protection Service"},
		{"mpssvc", "Windows Firewall"},
		{"MSDTC", "Distributed Transaction Coordinator"},
		{"MSiSCSI", "Microsoft iSCSI"},
		{"msiserver", "Windows Installer"},
		{"MSOffice*", "Microsoft Office"},
		{"Office*", "Office Software"},
		{"OneDrive*", "OneDrive"},
		{"Outlook*", "Outlook"},
	}

	for _, svc := range windowsServices {
		w.Add(svc.name, WhitelistTypeService, svc.reason, "microsoft")
	}
}

func (w *Whitelist) addBHOWitelist() {
	knownBenignBHOs := []struct {
		key    string
		reason string
	}{
		{"{761497BB-4D99-43CD-88C7-3F01F1D8D6F6}", "Windows Update"},
		{"{D0B07BAD-33DD-47C1-95BF-4F55B9A9C7A2}", "Microsoft"},
		{"{8E5A265F-5AD9-47A8-90E0-5A6B5684B0D4}", "Microsoft Office"},
		{"{1E3A7891-16C1-4D8B-83BF-C5F5A33C3DD6}", "Microsoft"},
		{"{5E5E6BB6-5F9A-4E9B-B5E5-8E9B6D8C1E0F}", "Common BHO"},
	}

	for _, item := range knownBenignBHOs {
		w.Add(item.key, WhitelistTypeBHO, item.reason, "microsoft")
	}
}

func (w *Whitelist) addPrintMonitorWhitelist() {
	knownBenignPrintMonitors := []struct {
		key    string
		reason string
	}{
		{"Local Port", "Standard Local Port"},
		{"Standard TCP/IP Port", "Standard TCP/IP Port"},
		{"WSD Port", "Web Services Print"},
		{"Microsoft XPS Document Writer", "XPS Printer"},
		{"Microsoft Print to PDF", "PDF Printer"},
		{" fax", "Fax Monitor"},
		{"PDF Director Port", "PDF Director"},
		{"Foxit Reader Port", "Foxit Reader"},
	}

	for _, item := range knownBenignPrintMonitors {
		w.Add(item.key, WhitelistTypePrintMonitor, item.reason, "microsoft")
	}
}

func (w *Whitelist) addWinsockWhitelist() {
	knownBenignWinsock := []struct {
		key    string
		reason string
	}{
		{"%SystemRoot%\\system32\\mswsock.dll", "Microsoft Winsock"},
		{"%SystemRoot%\\System32\\wshtcpip.dll", "Microsoft TCP/IP"},
		{"%SystemRoot%\\system32\\wshbth.dll", "Microsoft Bluetooth"},
	}

	for _, item := range knownBenignWinsock {
		w.Add(item.key, WhitelistTypeWinsock, item.reason, "microsoft")
	}
}

func (w *Whitelist) addLSAWhitelist() {
	knownBenignLSA := []struct {
		key    string
		reason string
	}{
		{"msv1_0", "Microsoft Authentication"},
		{"kerberos", "Kerberos Authentication"},
		{"ntlmssp", "NTLM Authentication"},
		{"wdigest", "Digest Authentication"},
		{"schannel", "SSL/TLS Authentication"},
		{"pku2u", "PKU2U Authentication"},
		{"Negotiate", "Negotiate Authentication"},
	}

	for _, item := range knownBenignLSA {
		w.Add(item.key, WhitelistTypeLSA, item.reason, "microsoft")
	}
}

func (w *Whitelist) addBootExecuteWhitelist() {
	knownBenignBoot := []struct {
		key    string
		reason string
	}{
		{"sysmenu", "System Menu"},
		{"userinit", "User Init Process"},
		{"wininit", "Windows Init"},
		{"smss", "Session Manager"},
		{"csrss", "Client Server Runtime"},
		{"winlogon", "Windows Logon"},
		{"services", "Service Control Manager"},
		{"lsass", "Local Security Authority"},
		{"system", "System"},
	}

	for _, item := range knownBenignBoot {
		w.Add(item.key, WhitelistTypeBootExecute, item.reason, "microsoft")
	}
}

func (w *Whitelist) addAccessibilityWhitelist() {
	accessibilityPrograms := []struct {
		key    string
		reason string
	}{
		{"C:\\Windows\\System32\\sethc.exe", "Sticky Keys"},
		{"C:\\Windows\\System32\\utilman.exe", "Utility Manager"},
		{"C:\\Windows\\System32\\osk.exe", "On-Screen Keyboard"},
		{"C:\\Windows\\System32\\magnify.exe", "Magnifier"},
		{"C:\\Windows\\System32\\narrator.exe", "Narrator"},
		{"C:\\Windows\\System32\\displayswitch.exe", "Display Switch"},
		{"C:\\Windows\\System32\\atbroker.exe", "AT Broker"},
		{"C:\\Windows\\System32\\setcraft.exe", "Sticky Keys"},
		{"C:\\Windows\\System32\\SndVolSSO.exe", "Volume Control"},
	}

	for _, item := range accessibilityPrograms {
		w.Add(item.key, WhitelistTypeAccessibility, item.reason, "microsoft")
	}
}

func (w *Whitelist) addScheduledTaskWhitelist() {
	knownSafeTasks := []struct {
		name    string
		author  string
		reason  string
	}{
		{"PcaPatchDbTask", "Microsoft", "Windows Patch Diagnostics"},
		{"StartupAppTask", "Microsoft", "Startup Application Task"},
		{"CleanupTemporaryState", "Microsoft", "Cleanup Temporary State"},
		{"Pre-staged app cleanup", "Microsoft", "App Cleanup"},
		{"Proxy", "Microsoft", "Network Proxy"},
		{"maintenancetasks", "Microsoft", "Maintenance Tasks"},
		{"Microsoft-Windows-DiskDiagnosticDataCollector", "Microsoft", "Disk Diagnostics"},
		{"PCR Prediction Framework Firmware Update Task", "Microsoft", "PCR Prediction"},
		{"MaintenanceTasks", "Microsoft", "Maintenance Tasks"},
		{"WsSwapAssessmentTask", "Microsoft", "Windows Swap Assessment"},
		{"SynchronizeTimeZone", "Microsoft", "Time Zone Sync"},
		{"BfeOnServiceStartTypeChange", "Microsoft", "Base Filtering Engine"},
		{"Automatic-Device-Join", "Microsoft", "Device Join"},
		{"Recovery-Check", "Microsoft", "System Recovery"},
		{"SecurityHealth", "Microsoft", "Windows Security"},
		{"WindowsUpdate", "Microsoft", "Windows Update"},
		{"AuditPolicy", "Microsoft", "Audit Policy"},
		{"DiskCleanup", "Microsoft", "Disk Cleanup"},
		{"Temp", "Microsoft", "Temporary Cleanup"},
		{"UserProfile", "Microsoft", "User Profile"},
		{"Welcome", "Microsoft", "Welcome Experience"},
		{"SMB1", "Microsoft", "SMB1 Protocol"},
	}

	for _, task := range knownSafeTasks {
		w.Add(task.name, WhitelistTypeScheduledTask, task.reason, "microsoft")
	}

	w.Add("*\\Microsoft\\Windows\\*", WhitelistTypeScheduledTask, "Microsoft Official Tasks", "microsoft")
}
