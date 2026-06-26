//go:build !windows

package forensics

import (
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

func VerifySignature(path string) (*SignatureResult, error) {
	return &SignatureResult{
		Status:      "Unsupported",
		Description: "signature verification is only supported on Windows",
	}, nil
}

func IsSigned(path string) (bool, *SignatureResult, error) {
	return false, &SignatureResult{
		Status: "Unsupported",
	}, nil
}
