//go:build windows

package forensics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type SignatureResult struct {
	Status       string     `json:"status"`
	Signer       string     `json:"signer,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	Thumbprint   string     `json:"thumbprint,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	Description  string     `json:"description,omitempty"`
	CatalogName  string     `json:"catalog_name,omitempty"`
	IsRootSigned bool       `json:"is_root_signed"`
}

var (
	ErrPlatformNotSupported = fmt.Errorf("signature verification is only supported on Windows")
	ErrPathIsDirectory      = fmt.Errorf("path is a directory")
)

func VerifySignature(path string) (*SignatureResult, error) {
	if runtime.GOOS != "windows" {
		return &SignatureResult{
			Status:      "Unsupported",
			Description: ErrPlatformNotSupported.Error(),
		}, nil
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return &SignatureResult{
			Status:      "Invalid",
			Description: ErrPathIsDirectory.Error(),
		}, nil
	}

	return verifySignatureWindows(path)
}

func verifySignatureWindows(path string) (*SignatureResult, error) {
	result := &SignatureResult{}

	script := fmt.Sprintf(`
$sig = Get-AuthenticodeSignature -FilePath '%s'
$result = @{
    Status = $sig.Status.ToString()
    StatusMessage = $sig.StatusMessage
    SignerCertificate = $null
}
if ($sig.SignerCertificate) {
    $result.SignerCertificate = @{
        Subject = $sig.SignerCertificate.Subject
        Issuer = $sig.SignerCertificate.Issuer
        Thumbprint = $sig.SignerCertificate.Thumbprint
        NotBefore = $sig.SignerCertificate.NotBefore.ToString("o")
        NotAfter = $sig.SignerCertificate.NotAfter.ToString("o")
    }
}
if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=(Microsoft)') {
    $result.IsRootSigned = $true
} else {
    $result.IsRootSigned = $false
}
$result | ConvertTo-Json -Compress
`, strings.ReplaceAll(path, "'", "''"))

	output, err := runPowerShellCommand(script)
	if err != nil {
		return &SignatureResult{
			Status:      "Error",
			Description: err.Error(),
		}, nil
	}

	var sigInfo struct {
		Status            string `json:"Status"`
		StatusMessage     string `json:"StatusMessage"`
		SignerCertificate *struct {
			Subject    string `json:"Subject"`
			Issuer     string `json:"Issuer"`
			Thumbprint string `json:"Thumbprint"`
			NotBefore  string `json:"NotBefore"`
			NotAfter   string `json:"NotAfter"`
		} `json:"SignerCertificate"`
		IsRootSigned bool `json:"IsRootSigned"`
	}

	if err := json.Unmarshal([]byte(output), &sigInfo); err != nil {
		return &SignatureResult{
			Status:      "Error",
			Description: fmt.Sprintf("Failed to parse signature info: %s", err.Error()),
		}, nil
	}

	result.Status = sigInfo.Status
	if sigInfo.SignerCertificate != nil {
		result.Signer = extractCN(sigInfo.SignerCertificate.Subject)
		result.Issuer = extractCN(sigInfo.SignerCertificate.Issuer)
		result.Thumbprint = sigInfo.SignerCertificate.Thumbprint

		if notBefore, err := time.Parse(time.RFC3339, sigInfo.SignerCertificate.NotBefore); err == nil {
			result.NotBefore = &notBefore
		}
		if notAfter, err := time.Parse(time.RFC3339, sigInfo.SignerCertificate.NotAfter); err == nil {
			result.NotAfter = &notAfter
		}
	}
	result.IsRootSigned = sigInfo.IsRootSigned
	result.Description = sigInfo.StatusMessage

	return result, nil
}

func extractCN(distinguishedName string) string {
	parts := strings.Split(distinguishedName, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return distinguishedName
}

func runPowerShellCommand(script string) (string, error) {
	f, err := os.CreateTemp(os.TempDir(), "winalog_ps_*.ps1")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFile := f.Name()

	defer os.Remove(tmpFile)

	if err := os.Chmod(tmpFile, 0600); err != nil {
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	if _, err := f.WriteString(script); err != nil {
		return "", fmt.Errorf("failed to write script: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("failed to close file: %w", err)
	}

	output, err := execPowerShell(tmpFile)
	if err != nil {
		return "", err
	}
	return output, nil
}

func execPowerShell(scriptPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("signature verification timeout")
		}
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%s: %s", err.Error(), stderr.String())
		}
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func IsSigned(path string) (bool, *SignatureResult, error) {
	result, err := VerifySignature(path)
	if err != nil {
		return false, nil, err
	}
	return result.Status == "Valid", result, nil
}

func IsMicrosoftSigned(path string) (bool, error) {
	result, err := VerifySignature(path)
	if err != nil {
		return false, err
	}
	return result.Signer != "" && (strings.Contains(result.Signer, "Microsoft") || result.IsRootSigned), nil
}

func IsSelfSigned(path string) (bool, error) {
	result, err := VerifySignature(path)
	if err != nil {
		return false, err
	}
	if result.Signer == "" || result.Issuer == "" {
		return false, nil
	}
	return result.Signer == result.Issuer, nil
}
