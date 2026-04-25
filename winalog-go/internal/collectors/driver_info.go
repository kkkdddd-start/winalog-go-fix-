//go:build windows

package collectors

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/kkkdddd-start/winalog-go/internal/forensics"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/internal/utils"
)

type DriverInfoCollector struct {
	BaseCollector
}

type Driver struct {
	Name        string
	DisplayName string
	Description string
	Path        string
	Status      string
}

type DriverWithSignature struct {
	Name        string
	DisplayName string
	Description string
	Path        string
	Status      string
	SigStatus   string
	Signer      string
}

func NewDriverInfoCollector() *DriverInfoCollector {
	return &DriverInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "driver_info",
				Description:   "Collect driver information",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *DriverInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	drivers, err := c.collectDriverInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(drivers))
	for i, d := range drivers {
		interfaces[i] = d
	}
	return interfaces, nil
}

func (c *DriverInfoCollector) collectDriverInfo() ([]*types.DriverInfo, error) {
	drivers := make([]*types.DriverInfo, 0)

	driverList, err := ListDriversWithSignature()
	if err != nil {
		return drivers, err
	}

	for _, driver := range driverList {
		sigStatus := driver.SigStatus
		if sigStatus == "" {
			sigStatus = "Unknown"
		}

		drivers = append(drivers, &types.DriverInfo{
			Name:        driver.Name,
			Description: driver.Description,
			Type:        "Kernel",
			Status:      driver.Status,
			Started:     driver.Status == "Running",
			FilePath:    driver.Path,
			Signature:   sigStatus,
			Signer:      driver.Signer,
		})
	}

	return drivers, nil
}

func ListDrivers() ([]Driver, error) {
	drivers := make([]Driver, 0)

	cmd := `Get-WmiObject -Class Win32_SystemDriver | Select-Object Name,DisplayName,Description,PathName,State,StartMode | ForEach-Object { $_ | ConvertTo-Json -Compress }`

	log.Printf("[INFO] ListDrivers: executing WMI query for drivers")

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		log.Printf("[ERROR] ListDrivers: PowerShell command failed: %v", result.Error)
		return drivers, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" {
		log.Printf("[WARN] ListDrivers: empty result from WMI query")
		return drivers, nil
	}

	log.Printf("[DEBUG] ListDrivers: raw output length: %d", len(output))

	lines := strings.Split(output, "\n")
	parseCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "null" {
			continue
		}

		var driverRaw struct {
			Name        string `json:"Name"`
			DisplayName string `json:"DisplayName"`
			Description string `json:"Description"`
			PathName    string `json:"PathName"`
			State       string `json:"State"`
			StartMode   string `json:"StartMode"`
		}

		if err := json.Unmarshal([]byte(line), &driverRaw); err != nil {
			log.Printf("[WARN] ListDrivers: failed to parse driver JSON: %v", err)
			continue
		}

		drivers = append(drivers, Driver{
			Name:        driverRaw.Name,
			DisplayName: driverRaw.DisplayName,
			Description: driverRaw.Description,
			Path:        driverRaw.PathName,
			Status:      driverRaw.State,
		})
		parseCount++
	}

	log.Printf("[INFO] ListDrivers: parsed %d drivers", parseCount)

	return drivers, nil
}

func ListDriversWithSignature() ([]DriverWithSignature, error) {
	drivers := make([]DriverWithSignature, 0)

	cmd := `Get-WmiObject -Class Win32_SystemDriver | ForEach-Object {
		$sig = $null
		$status = 'Unknown'
		$signer = ''
		if ($_.PathName) {
			try {
				$sig = Get-AuthenticodeSignature $_.PathName -ErrorAction Stop
				if ($sig.Status -eq 'Valid') {
					$status = 'Signed'
				} else {
					$status = 'Unsigned'
				}
				if ($sig.SignerCertificate) {
					$signer = $sig.SignerCertificate.Subject
				}
			} catch {
				$status = 'Unsigned'
			}
		}
		[PSCustomObject]@{
			Name        = $_.Name
			DisplayName = $_.DisplayName
			Description = $_.Description
			Path        = $_.PathName
			Status      = $_.State
			SigStatus   = $status
			Signer      = $signer
		}
	} | ConvertTo-Json -Depth 3 -Compress`

	log.Printf("[INFO] ListDriversWithSignature: executing combined WMI + signature query")

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		log.Printf("[ERROR] ListDriversWithSignature: PowerShell command failed: %v", result.Error)
		return drivers, result.Error
	}

	output := strings.TrimSpace(result.Output)
	if output == "" {
		log.Printf("[WARN] ListDriversWithSignature: empty result")
		return drivers, nil
	}

	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &drivers); err != nil {
			log.Printf("[WARN] ListDriversWithSignature: failed to parse JSON array: %v", err)
			return drivers, err
		}
	} else if strings.HasPrefix(output, "{") {
		var singleDriver DriverWithSignature
		if err := json.Unmarshal([]byte(output), &singleDriver); err != nil {
			log.Printf("[WARN] ListDriversWithSignature: failed to parse single driver: %v", err)
			return drivers, err
		}
		drivers = append(drivers, singleDriver)
	}

	log.Printf("[INFO] ListDriversWithSignature: got %d drivers with signature info", len(drivers))
	return drivers, nil
}

func GetDriverInfo(driverName string) (*Driver, error) {
	cmd := `Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" | Select-Object Name,DisplayName,Description,PathName,State,StartMode | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return nil, result.Error
	}

	var driverRaw struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Description string `json:"Description"`
		PathName    string `json:"PathName"`
		State       string `json:"State"`
		StartMode   string `json:"StartMode"`
	}

	if err := json.Unmarshal([]byte(result.Output), &driverRaw); err != nil {
		return nil, err
	}

	return &Driver{
		Name:        driverRaw.Name,
		DisplayName: driverRaw.DisplayName,
		Description: driverRaw.Description,
		Path:        driverRaw.PathName,
		Status:      driverRaw.State,
	}, nil
}

func IsDriverLoaded(driverName string) bool {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).State -eq 'Running'`

	result := utils.RunPowerShell(cmd)
	return result.Success() && strings.Contains(strings.ToLower(result.Output), "true")
}

func CollectDriverInfo(ctx context.Context) ([]*types.DriverInfo, error) {
	collector := NewDriverInfoCollector()
	results, err := collector.Collect(ctx)
	if err != nil {
		return nil, err
	}

	drivers := make([]*types.DriverInfo, 0, len(results))
	for _, r := range results {
		if d, ok := r.(*types.DriverInfo); ok {
			drivers = append(drivers, d)
		}
	}
	return drivers, nil
}

func GetDriverFileHash(driverPath string) (string, error) {
	result, err := forensics.CalculateFileHash(driverPath)
	if err != nil {
		return "", err
	}
	return result.SHA256, nil
}

func IsDriverSigned(driverPath string) (bool, string, error) {
	cmd := `(Get-AuthenticodeSignature '%s').Status`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return false, "", result.Error
	}

	signatureStatus := strings.TrimSpace(result.Output)
	isSigned := signatureStatus == "Valid"

	var signer string
	cmd2 := `(Get-AuthenticodeSignature '%s').SignerCertificate.Subject`

	result2 := utils.RunPowerShell(cmd2)
	if result2.Success() {
		signer = strings.TrimSpace(result2.Output)
	}

	return isSigned, signer, nil
}

func GetDriverCompanyName(driverPath string) string {
	cmd := `(Get-AuthenticodeSignature '%s').SignerCertificate.Corporation`

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}

	return ""
}

func GetDriverDescription(driverPath string) string {
	cmd := `(Get-Item '%s').VersionInfo.FileDescription`

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}

	return ""
}

func IsDriverLoadedAtBoot(driverName string) bool {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).StartMode -eq 'Boot'`

	result := utils.RunPowerShell(cmd)
	return result.Success() && strings.Contains(strings.ToLower(result.Output), "true")
}

func GetDriverDependancies(driverName string) ([]string, error) {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).DependentServices | ConvertTo-Json -Compress`

	result := utils.RunPowerShell(cmd)
	if !result.Success() {
		return []string{}, nil
	}

	var services []struct {
		Name string `json:"Name"`
	}

	if err := json.Unmarshal([]byte(result.Output), &services); err != nil {
		return []string{}, nil
	}

	dependancies := make([]string, 0, len(services))
	for _, s := range services {
		dependancies = append(dependancies, s.Name)
	}

	return dependancies, nil
}

func GetDriverServiceType(driverName string) string {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).ServiceType`

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}

	return ""
}

func GetDriverStartType(driverName string) string {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).StartMode`

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		return strings.TrimSpace(result.Output)
	}

	return ""
}

func GetDriverProcessID(driverName string) int {
	cmd := `(Get-WmiObject -Class Win32_SystemDriver -Filter "Name='%s'" -ErrorAction SilentlyContinue).ProcessId`

	result := utils.RunPowerShell(cmd)
	if result.Success() {
		if pid, err := parseInt(strings.TrimSpace(result.Output)); err == nil {
			return pid
		}
	}

	return 0
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
