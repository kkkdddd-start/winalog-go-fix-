//go:build windows

package persistence

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type COMHijackDetector struct {
	config               *DetectorConfig
	builtinPaths        []string
	builtinDlls         []string
	builtinClsidsPrefix []string
}

func NewCOMHijackDetector() *COMHijackDetector {
	return &COMHijackDetector{
		config: &DetectorConfig{
			Enabled:  true,
			EventIDs: []int32{4670},
		},
		builtinPaths:        TrustedCOMPaths,
		builtinDlls:         TrustedCOMDLLs,
		builtinClsidsPrefix: TrustedCOMCLSIDPrefixes,
	}
}

func (d *COMHijackDetector) Name() string {
	return "com_hijack_detector"
}

func (d *COMHijackDetector) GetTechnique() Technique {
	return TechniqueT1546015
}

func (d *COMHijackDetector) RequiresAdmin() bool {
	return true
}

func (d *COMHijackDetector) SetConfig(config *DetectorConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	d.config = config
	if config.BuiltinWhitelist != nil {
		d.builtinPaths = expandEnvPaths(config.BuiltinWhitelist)
	}
	if config.BuiltinDllWhitelist != nil {
		d.builtinDlls = config.BuiltinDllWhitelist
	}
	if config.BuiltinClsidsWhitelist != nil {
		d.builtinClsidsPrefix = config.BuiltinClsidsWhitelist
	}
	return nil
}

func (d *COMHijackDetector) GetConfig() *DetectorConfig {
	return d.config
}

var SuspiciousCLSIDPaths = []string{
	`HKCR\CLSID`,
}

var KnownMaliciousCLSID = map[string]string{
	"{00000514-0000-0010-8000-00AA006D2EA4}": "ADO Stream Object (Known COM RAT)",
	"{00000200-0000-0010-8000-00AA006D2EA4}": "ADO RecordSet Object",
	"{00000300-0000-0010-8000-00AA006D2EA4}": "ADO Command Object",
	"{00000304-0000-0010-8000-00AA006D2EA4}": "ADO Parameter Object",
	"{BD1C19A-33C2-11D4-8A26-00C04F5B4896}":  "ASUS Splendid",
	"{C833FD2E-74EE-41DA-AF91-9C378E0043FC}": "ASUS Splendid Registry Key",
	"{E8CC8000-BB2A-4A2F-9F7A-1234567890AB}": "PlugX RAT CLSID",
	"{9E5E8C70-4A2D-4F7A-8F3A-1234567890CD}": "Gh0st RAT CLSID",
	"{1F2E5E3F-3A4B-9C8D-1E2F-1234567890EF}": "PoisonIvy RAT CLSID",
	"{AB890700-12A4-4B5C-9D8E-123456789012}": "DarkComet RAT CLSID",
	"{C8F1E020-D3E5-4B6A-8F9C-123456789034}": "NanoCore RAT CLSID",
	"{1A2B3C4D-5E6F-7A8B-9C0D-1234567890AB}": "AsyncRAT CLSID",
	"{B1C2D3E4-5F6A-7B8C-9D0E-1234567890CD}": "Remcos RAT CLSID",
}

var SuspiciousCOMPaths = []string{
	"%TEMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\",
	"\\\\UNC\\", "\\\\127\\", "\\\\localhost\\",
}

var TrustedCOMPaths = []string{
	"C:\\Windows\\System32",
	"C:\\Windows\\SysWOW64",
	"C:\\Windows",
	"C:\\Program Files",
	"C:\\Program Files (x86)",
	"C:\\ProgramData",
	"%SystemRoot%\\System32",
	"%SystemRoot%\\SysWOW64",
	"%SystemRoot%",
	"%ProgramFiles%",
	"%ProgramFiles(x86)%",
	"%ProgramData%",
	"%CommonProgramFiles%\\Microsoft Shared\\Ink",
	"%CommonProgramFiles%\\System\\Ole DB",
	"%CommonProgramFiles%\\System\\msadc",
	"%CommonProgramFiles%\\System\\wab32.dll",
	"%CommonProgramFiles%\\ado",
	"%ProgramFiles%\\Common Files\\Microsoft Shared\\Ink",
	"%ProgramFiles%\\Common Files\\System\\Ole DB",
	"%ProgramFiles%\\Common Files\\System\\msadc",
	"%ProgramFiles%\\Common Files\\System\\wab32.dll",
	"%ProgramFiles%\\Common Files\\ado",
}

var TrustedCOMDLLs = []string{
	"InkObj.dll",
	"tabskb.dll",
	"rtscom.dll",
	"tipskins.dll",
	"tiptsf.dll",
	"mraut.DLL",
	"micaut.dll",
	"sqloledb.dll",
	"msdaosp.dll",
	"sqlxmlx.dll",
	"msdaps.dll",
	"msxactps.dll",
	"msdarem.dll",
	"msadds.dll",
	"msdasql.dll",
	"SecurityHealthAgent.dll",
	"SecurityHealthSSO.dll",
	"SecurityHealthProxyStub.dll",
	"wab32.dll",
	"wab32res.dll",
	"rdpcredentialprovider.dll",
	"amsi.dll",
	"amsiproxy.dll",
	"btpanui.dll",
	"AppxDeploymentClient.dll",
	"msdbg2.dll",
	"ole32.dll",
	"combase.dll",
	"mscoree.dll",
}

var TrustedCOMCLSIDPrefixes = []string{
	"CAFEEFAC-",
}

func expandEnvPaths(paths []string) []string {
	expanded := make([]string, 0, len(paths))
	for _, p := range paths {
		expanded = append(expanded, os.ExpandEnv(p))
	}
	return expanded
}

func init() {
	TrustedCOMPaths = expandEnvPaths(TrustedCOMPaths)
}

var KnownSafeCOMCLSIDs = map[string]string{
	"{00000300-0000-0000-0000-000000000000}": "COM Structured Storage",
	"{00000303-0000-0000-0000-000000000000}": "Moniker Proxy",
	"{00000304-0000-0000-0000-000000000000}": "OLE1-Presentation",
	"{00000305-0000-0000-0000-000000000000}": "OLE2-Presentation",
	"{00000306-0000-0000-0000-000000000000}": "OLE2-Link",
	"{00000308-0000-0000-0000-000000000000}": "ActiveDoc",
	"{00000309-0000-0000-0000-000000000000}": "Overlays",
	"{0000030B-0000-0000-0000-000000000000}": "COM IIDs",
	"{00000315-0000-0000-0000-000000000000}": "BindCtx",
	"{00000316-0000-0000-0000-000000000000}": "GenericObject",
	"{00000319-0000-0000-0000-000000000000}": "PropertySet",
	"{0000031A-0000-0000-0000-000000000000}": "Layout Luid",
	"{0000031D-0000-0000-0000-000000000000}": "ROT",
	"{00000320-0000-0000-0000-000000000000}": "Memory",
	"{00000327-0000-0000-0000-000000000000}": "ContextMarshaler",
	"{0000032E-0000-0000-0000-000000000000}": "Thumbnail",
	"{0002DF02-0000-0000-0000-000000000000}": "Explorer Browser",
	"{0002E005-0000-0000-0000-000000000000}": "Data Folder",
	"{0002E006-0000-0000-0000-000000000000}": "Channel Manager",
	"{001DC1E0-0F8C-4720-98DB-39D32A661422}": "Enterprise DCS",
	"{006E61DF-1A43-4F2C-B26F-780BAEA3A92D}": "Holographic Speech",
	"{009F3B45-8A6B-4360-B997-B2A009A16402}": "Shell File Operation",
	"{00A77FF7-A514-493e-B721-CDF8CB0F5B59}": "HelpPane",
	"{00B8308C-09F2-4c18-A7B0-4594D6B22EFE}": "wbem Remote",
	"{00BB2763-6A77-11D0-A535-00C04FD7D062}": "MSHTML Zones",
	"{00BB2764-6A77-11D0-A535-00C04FD7D062}": "MSHTML Zones",
	"{00BB2765-6A77-11D0-A535-00C04FD7D062}": "MSHTML Zones",
	"{00C69F81-0524-48C0-A353-4DD9D54F9A6E}": "Intel GPU",
	"{00CA399E-4CC0-43D2-902B-CEA3D36DC9E4}": "Remote Audio Endpoint",
	"{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}": "Photo Viewer",
	"{FFF0A69B-BE97-4023-BBB6-7914DB95E300}": "Wireless Network Manager",
	"{0010890e-8789-413c-adbc-48f5b511b3af}": "Shell Folder",
	"{003e0278-eca8-4bb8-a256-3689ca1c2600}": "Shell Folder",
	"{00722F5F-CB8F-44D3-AC27-CC37F76CFE92}": "Shell UI",
	"{0070746C-9A38-4236-822A-72CC4E5C8087}": "Shell Folder",
	"{A77FF7-A514-493e-B721-CDF8CB0F5B59}": "System Config",
}

func (d *COMHijackDetector) Detect(ctx context.Context) ([]*Detection, error) {
	if d.config != nil && !d.config.Enabled {
		return nil, nil
	}

	detections := make([]*Detection, 0)

	clsidList, err := d.enumerateCLSID()
	if err != nil {
		return detections, nil
	}

	for _, clsid := range clsidList {
		det := d.analyzeCLSID(clsid)
		if det != nil {
			detections = append(detections, det)
		}
	}

	return detections, nil
}

type CLSIDEntry struct {
	CLSID      string
	Name       string
	ServerPath string
	ServerType string
}

func (d *COMHijackDetector) enumerateCLSID() ([]CLSIDEntry, error) {
	entries := make([]CLSIDEntry, 0)

	subkeys, err := utils.ListRegistrySubkeys(`HKCR\CLSID`)
	if err != nil {
		return entries, nil
	}

	for _, clsid := range subkeys {
		if clsid == "" {
			continue
		}

		inprocServer32 := `HKCR\CLSID\` + clsid + `\InprocServer32`
		serverPath, _ := utils.GetRegistryValue(inprocServer32, "")

		if serverPath != "" {
			entries = append(entries, CLSIDEntry{
				CLSID:      clsid,
				ServerPath: serverPath,
				ServerType: "InprocServer32",
			})
		}

		inprocServer6432 := `HKCR\CLSID\` + clsid + `\InprocServer6432`
		serverPath6432, _ := utils.GetRegistryValue(inprocServer6432, "")
		if serverPath6432 != "" {
			entries = append(entries, CLSIDEntry{
				CLSID:      clsid,
				ServerPath: serverPath6432,
				ServerType: "InprocServer6432",
			})
		}

		localServer32 := `HKCR\CLSID\` + clsid + `\LocalServer32`
		localPath, _ := utils.GetRegistryValue(localServer32, "")
		if localPath != "" {
			entries = append(entries, CLSIDEntry{
				CLSID:      clsid,
				ServerPath: localPath,
				ServerType: "LocalServer32",
			})
		}

		treatAs := `HKCR\CLSID\` + clsid + `\TreatAs`
		treatAsPath, _ := utils.GetRegistryValue(treatAs, "")
		if treatAsPath != "" {
			entries = append(entries, CLSIDEntry{
				CLSID:      clsid,
				ServerPath: treatAsPath,
				ServerType: "TreatAs",
			})
		}

		progID := `HKCR\CLSID\` + clsid + `\ProgID`
		progIdPath, _ := utils.GetRegistryValue(progID, "")
		if progIdPath != "" {
			entries = append(entries, CLSIDEntry{
				CLSID:      clsid,
				ServerPath: progIdPath,
				ServerType: "ProgID",
			})
		}

		insertable := `HKCR\CLSID\` + clsid + `\Insertable`
		if utils.RegistryKeyExists(insertable) {
			insertableObj, _ := utils.GetRegistryValue(insertable, "")
			if insertableObj != "" {
				entries = append(entries, CLSIDEntry{
					CLSID:      clsid,
					ServerPath: insertableObj,
					ServerType: "Insertable",
				})
			}
		}
	}

	return entries, nil
}

func (d *COMHijackDetector) analyzeCLSID(clsid CLSIDEntry) *Detection {
	if clsid.CLSID == "" || clsid.ServerPath == "" {
		return nil
	}

	if _, isSafe := KnownSafeCOMCLSIDs[clsid.CLSID]; isSafe {
		return nil
	}

	if malDescription, isKnown := KnownMaliciousCLSID[clsid.CLSID]; isKnown {
		return &Detection{
			Technique:   TechniqueT1546015,
			Category:    "COM",
			Severity:    SeverityCritical,
			Time:        time.Now(),
			Title:       "Known Malicious CLSID Detected",
			Description: "A CLSID associated with known malicious software (" + malDescription + ") was found",
			Evidence: Evidence{
				Type:  EvidenceTypeCOM,
				Key:   `HKCR\CLSID\` + clsid.CLSID,
				Value: clsid.ServerPath,
			},
			MITRERef:          []string{"T1546.015"},
			RecommendedAction: "Immediately investigate this CLSID and associated files",
			FalsePositiveRisk: "Low",
		}
	}

	if d.isTrustedCLSIDPrefix(clsid.CLSID) {
		return nil
	}

	for _, suspiciousPath := range SuspiciousCOMPaths {
		suspiciousPathExpanded := os.ExpandEnv(suspiciousPath)
		if strings.Contains(strings.ToLower(clsid.ServerPath), strings.ToLower(suspiciousPathExpanded)) {
			return &Detection{
				Technique:   TechniqueT1546015,
				Category:    "COM",
				Severity:    SeverityHigh,
				Time:        time.Now(),
				Title:       "Suspicious COM Server Path",
				Description: "A COM server is loading from a suspicious location: " + clsid.ServerPath,
				Evidence: Evidence{
					Type:  EvidenceTypeCOM,
					Key:   `HKCR\CLSID\` + clsid.CLSID,
					Value: clsid.ServerPath,
				},
				MITRERef:          []string{"T1546.015"},
				RecommendedAction: "Investigate the COM server DLL and verify if it is legitimate",
				FalsePositiveRisk: "Medium",
			}
		}
	}

	if !d.isTrustedPath(clsid.ServerPath) && !d.isTrustedDLLName(clsid.ServerPath) && d.isExecutablePath(clsid.ServerPath) {
		return &Detection{
			Technique:   TechniqueT1546015,
			Category:    "COM",
			Severity:    SeverityMedium,
			Time:        time.Now(),
			Title:       "COM Server Outside System Directory",
			Description: "A COM server DLL is loading from outside the standard Windows system directories",
			Evidence: Evidence{
				Type:  EvidenceTypeCOM,
				Key:   `HKCR\CLSID\` + clsid.CLSID,
				Value: clsid.ServerPath,
			},
			MITRERef:          []string{"T1546.015"},
			RecommendedAction: "Verify the COM server is legitimate",
			FalsePositiveRisk: "Medium",
		}
	}

	return nil
}

func (d *COMHijackDetector) isTrustedPath(path string) bool {
	pathExpanded := os.ExpandEnv(path)
	pathLower := strings.ToLower(pathExpanded)
	for _, trusted := range d.builtinPaths {
		trustedLower := strings.ToLower(trusted)
		if strings.HasPrefix(pathLower, trustedLower) {
			return true
		}
	}
	log.Printf("[DEBUG] [COM] isTrustedPath: path=%s, expanded=%s, builtinPaths=%v", path, pathExpanded, d.builtinPaths)
	return false
}

func (d *COMHijackDetector) isTrustedDLLName(path string) bool {
	pathExpanded := os.ExpandEnv(path)
	fileName := strings.ToLower(filepath.Base(pathExpanded))
	for _, trusted := range d.builtinDlls {
		if strings.ToLower(trusted) == fileName {
			return true
		}
	}
	return false
}

func (d *COMHijackDetector) isTrustedCLSIDPrefix(clsid string) bool {
	cleanClsID := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(clsid), "{"), "}")
	for _, prefix := range d.builtinClsidsPrefix {
		if strings.HasPrefix(cleanClsID, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func (d *COMHijackDetector) isExecutablePath(path string) bool {
	pathLower := strings.ToLower(path)
	executableExts := []string{".exe", ".dll", ".ocx", ".sys"}
	for _, ext := range executableExts {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}
	return false
}

func CheckCOMHijacking() []*Detection {
	detections := make([]*Detection, 0)
	detector := NewCOMHijackDetector()

	results, _ := detector.Detect(context.Background())
	detections = append(detections, results...)

	return detections
}
