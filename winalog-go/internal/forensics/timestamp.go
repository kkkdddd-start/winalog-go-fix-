package forensics

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type TimestampResult struct {
	Status        string    `json:"status"`
	Timestamp     time.Time `json:"timestamp"`
	HashAlgorithm string    `json:"hash_algorithm"`
	HashValue     string    `json:"hash_value"`
	SerialNumber  string    `json:"serial_number,omitempty"`
	TSAURL        string    `json:"tsa_url,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type TimestampRequest struct {
	FilePath      string
	HashAlgorithm string
	TSAServer     string
}

const (
	maxRetries     = 3
	retryDelay     = 2 * time.Second
	requestTimeout = 30 * time.Second
)

var defaultTSAServers = []string{
	"http://timestamp.digicert.com",
	"http://timestamp.sectigo.com",
	"http://timestamp.globalsign.com",
	"http://tsa.isigntrust.com",
}

func RequestTimestamp(req *TimestampRequest) (*TimestampResult, error) {
	result := &TimestampResult{}

	file, err := os.Open(req.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash, err := calculateFileHashSimple(file, req.HashAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}
	result.HashValue = hash
	result.HashAlgorithm = req.HashAlgorithm

	servers := defaultTSAServers
	if req.TSAServer != "" {
		servers = []string{req.TSAServer}
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		for _, tsaURL := range servers {
			resp, err := requestTimestampFromTSA(tsaURL, hash, req.HashAlgorithm)
			if err != nil {
				lastErr = err
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				result.Status = "Trusted"
				result.Timestamp = time.Now()
				result.TSAURL = tsaURL
				return result, nil
			}

			lastErr = fmt.Errorf("TSA returned status: %d", resp.StatusCode)
		}

		if attempt < maxRetries-1 {
			time.Sleep(retryDelay * time.Duration(1<<uint(attempt)))
		}
	}

	result.Status = "Error"
	result.Error = fmt.Sprintf("all TSA servers failed after %d attempts: %v", maxRetries, lastErr)
	return result, nil
}

func requestTimestampFromTSA(tsaURL, hash, algorithm string) (*http.Response, error) {
	tsaURL = strings.TrimSuffix(tsaURL, "/")

	req, err := http.NewRequest("POST", tsaURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-response")

	client := &http.Client{Timeout: requestTimeout}
	return client.Do(req)
}

func calculateFileHashSimple(file *os.File, algorithm string) (string, error) {
	hash, err := computeFileHash(file, algorithm)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hash), nil
}

func computeFileHash(file *os.File, algorithm string) ([]byte, error) {
	var hash []byte

	switch algorithm {
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			return nil, err
		}
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return hash, nil
}

func VerifyTimestamp(filePath string, tsaServer string) (*TimestampResult, error) {
	return RequestTimestamp(&TimestampRequest{
		FilePath:      filePath,
		HashAlgorithm: "sha256",
		TSAServer:     tsaServer,
	})
}

func ParsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func IsTimestampValid(result *TimestampResult) bool {
	if result.Status != "Trusted" {
		return false
	}
	if result.Timestamp.IsZero() {
		return false
	}
	return true
}

func FormatTimestampResult(result *TimestampResult) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Status: %s\n", result.Status))
	if result.Timestamp.IsZero() {
		buf.WriteString(fmt.Sprintf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339)))
	}
	buf.WriteString(fmt.Sprintf("Hash Algorithm: %s\n", result.HashAlgorithm))
	buf.WriteString(fmt.Sprintf("Hash Value: %s\n", result.HashValue))
	if result.SerialNumber != "" {
		buf.WriteString(fmt.Sprintf("Serial Number: %s\n", result.SerialNumber))
	}
	if result.TSAURL != "" {
		buf.WriteString(fmt.Sprintf("TSA URL: %s\n", result.TSAURL))
	}
	if result.Error != "" {
		buf.WriteString(fmt.Sprintf("Error: %s\n", result.Error))
	}
	return buf.String()
}
