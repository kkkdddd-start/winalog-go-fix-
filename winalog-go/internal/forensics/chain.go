package forensics

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type EvidenceChain struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Operator     string    `json:"operator"`
	Action       string    `json:"action"`
	InputHash    string    `json:"input_hash"`
	OutputHash   string    `json:"output_hash"`
	PreviousHash string    `json:"previous_hash"`
	FilePath     string    `json:"file_path,omitempty"`
	Description  string    `json:"description,omitempty"`
}

type EvidenceManifest struct {
	ID          string           `json:"id"`
	CreatedAt   time.Time        `json:"created_at"`
	CollectedBy string           `json:"collected_by"`
	MachineID   string           `json:"machine_id"`
	Files       []*EvidenceFile  `json:"files"`
	Chain       []*EvidenceChain `json:"chain"`
	TotalSize   int64            `json:"total_size"`
	Hash        string           `json:"manifest_hash"`
}

type EvidenceFile struct {
	ID          string    `json:"id"`
	FilePath    string    `json:"file_path"`
	FileHash    string    `json:"file_hash"`
	Size        int64     `json:"size"`
	CollectedAt time.Time `json:"collected_at"`
	Collector   string    `json:"collector"`
}

func NewEvidenceChain(operator, action, inputHash string) *EvidenceChain {
	return &EvidenceChain{
		ID:           generateID(),
		Timestamp:    time.Now(),
		Operator:     operator,
		Action:       action,
		InputHash:    inputHash,
		OutputHash:   "",
		PreviousHash: "",
	}
}

func (e *EvidenceChain) CalculateHash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%d",
		e.ID, e.Operator, e.Action, e.InputHash, e.Timestamp.UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (e *EvidenceChain) Link(previousHash string) {
	e.PreviousHash = previousHash
	e.OutputHash = e.CalculateHash()
}

func GenerateManifest(files []*EvidenceFile, collectedBy, machineID string) *EvidenceManifest {
	manifest := &EvidenceManifest{
		ID:          generateID(),
		CreatedAt:   time.Now(),
		CollectedBy: collectedBy,
		MachineID:   machineID,
		Files:       files,
		Chain:       make([]*EvidenceChain, 0),
		TotalSize:   0,
	}

	for _, f := range files {
		manifest.TotalSize += f.Size
	}

	manifest.Hash = manifest.CalculateHash()
	return manifest
}

func (m *EvidenceManifest) AddChainEntry(entry *EvidenceChain) {
	if len(m.Chain) > 0 {
		entry.Link(m.Chain[len(m.Chain)-1].OutputHash)
	} else {
		entry.Link("")
	}
	m.Chain = append(m.Chain, entry)
}

func (m *EvidenceManifest) CalculateHash() string {
	fileCount := len(m.Files)
	data := fmt.Sprintf("%s|%s|%s|%d|%d|%d",
		m.ID, m.CollectedBy, m.MachineID, fileCount, m.TotalSize, m.CreatedAt.UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		timestamp := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
		hash := sha256.Sum256([]byte(timestamp))
		return hex.EncodeToString(hash[:])[:16]
	}
	return hex.EncodeToString(bytes)
}
