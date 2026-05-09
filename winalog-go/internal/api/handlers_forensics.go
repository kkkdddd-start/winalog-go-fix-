package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/forensics"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"go.uber.org/zap"
)

type ForensicsHandler struct {
	db *storage.DB
}

type HashRequest struct {
	Path string `json:"path" binding:"required"`
}

type SignatureRequest struct {
	Path string `json:"path" binding:"required"`
}

type CollectRequest struct {
	Type              string `json:"type" binding:"required"`
	OutputPath        string `json:"output_path"`
	CollectRegistry   bool   `json:"collect_registry"`
	CollectPrefetch   bool   `json:"collect_prefetch"`
	CollectShimcache  bool   `json:"collect_shimcache"`
	CollectAmcache    bool   `json:"collect_amcache"`
	CollectUserAssist bool   `json:"collect_userassist"`
	CollectTasks      bool   `json:"collect_tasks"`
	CollectLogs       bool   `json:"collect_logs"`
}

type MemoryDumpRequest struct {
	PID        uint32 `json:"pid"`
	OutputPath string `json:"output_path"`
}

type HashResponse struct {
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	MD5      string `json:"md5,omitempty"`
	SHA1     string `json:"sha1,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

type SignatureResponse struct {
	Status     string     `json:"status,omitempty"`
	Error      string     `json:"error,omitempty"`
	Signed     bool       `json:"signed"`
	Signer     string     `json:"signer,omitempty"`
	Issuer     string     `json:"issuer,omitempty"`
	Thumbprint string     `json:"thumbprint,omitempty"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
}

type CollectResponse struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	OutputPath  string    `json:"output_path"`
	CollectedAt time.Time `json:"collected_at"`
	Message     string    `json:"message"`
}

func NewForensicsHandler(db *storage.DB) *ForensicsHandler {
	return &ForensicsHandler{db: db}
}

func sanitizePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	return cleaned, nil
}

func (h *ForensicsHandler) CalculateHash(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "forensics is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	var req HashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	safePath, err := sanitizePath(req.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	result, err := forensics.CalculateFileHash(safePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, HashResponse{
		FilePath: result.FilePath,
		SHA256:   result.SHA256,
		MD5:      result.MD5,
		SHA1:     result.SHA1,
		Size:     result.Size,
	})
}

func (h *ForensicsHandler) VerifyHash(c *gin.Context) {
	path := c.Query("path")
	expected := c.Query("expected")

	if path == "" || expected == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "path and expected hash are required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	safePath, err := sanitizePath(path)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	match, result, err := forensics.VerifyFileHash(safePath, expected)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"match":  match,
		"hash":   result.SHA256,
		"path":   path,
		"sha256": result.SHA256,
		"md5":    result.MD5,
		"sha1":   result.SHA1,
		"size":   result.Size,
	})
}

func (h *ForensicsHandler) VerifySignature(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "signature verification is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	path := c.Query("path")

	if path == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "path is required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	safePath, err := sanitizePath(path)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	result, err := forensics.VerifySignature(safePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, SignatureResponse{
		Status:     result.Status,
		Signer:     result.Signer,
		Issuer:     result.Issuer,
		Thumbprint: result.Thumbprint,
		NotBefore:  result.NotBefore,
		NotAfter:   result.NotAfter,
	})
}

func (h *ForensicsHandler) IsSigned(c *gin.Context) {
	path := c.Query("path")

	if path == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "path is required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	safePath, err := sanitizePath(path)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	signed, result, err := forensics.IsSigned(safePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"is_signed": signed,
		"details":   result,
	})
}

func (h *ForensicsHandler) CollectEvidence(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "evidence collection is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	var req CollectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	evidenceID := generateEvidenceID()

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(os.TempDir(), fmt.Sprintf("evidence_%s.zip", evidenceID))
	} else {
		cleaned := filepath.Clean(outputPath)
		if strings.Contains(cleaned, "..") {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "invalid output path: path traversal not allowed",
			})
			return
		}
		outputPath = cleaned
	}

	collector := forensics.NewEvidenceCollector(evidenceID, outputPath)
	collector.CollectRegistry = req.CollectRegistry
	collector.CollectPrefetch = req.CollectPrefetch
	collector.CollectShimcache = req.CollectShimcache
	collector.CollectAmcache = req.CollectAmcache
	collector.CollectUserAssist = req.CollectUserAssist
	collector.CollectTasks = req.CollectTasks
	collector.CollectLogs = req.CollectLogs

	manifest, err := collector.Collect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("collection failed: %v", err),
		})
		return
	}

	if err := h.saveEvidenceManifest(manifest); err != nil {
		observability.Error("failed to save manifest", zap.String("module", "handlers_forensics"), zap.Error(err))
	}

	c.JSON(http.StatusOK, CollectResponse{
		ID:          evidenceID,
		Type:        req.Type,
		Status:      "completed",
		OutputPath:  outputPath,
		CollectedAt: manifest.CreatedAt,
		Message:     fmt.Sprintf("Collected %d files, total %d bytes", len(manifest.Files), manifest.TotalSize),
	})
}

func (h *ForensicsHandler) saveEvidenceManifest(manifest *forensics.EvidenceManifest) error {
	tx, err := h.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO evidence_chain (evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, manifest.ID, manifest.CreatedAt.Format(time.RFC3339),
		manifest.CollectedBy, "manifest_created", "", manifest.Hash, "")
	if err != nil {
		return fmt.Errorf("evidence_chain: %w", err)
	}

	for _, f := range manifest.Files {
		_, err := tx.Exec(`
			INSERT INTO evidence_file (file_path, file_hash, evidence_id, collected_at, collector)
			VALUES (?, ?, ?, ?, ?)
		`, f.FilePath, f.FileHash, manifest.ID, f.CollectedAt.Format(time.RFC3339), f.Collector)
		if err != nil {
			log.Printf("saveEvidenceManifest: failed to insert evidence_file %s: %v", f.FilePath, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (h *ForensicsHandler) ListEvidence(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "evidence listing is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	rows, err := h.db.Query(`
		SELECT 
			ec.evidence_id,
			ec.timestamp,
			ec.operator,
			ec.action,
			COUNT(ef.id) as file_count
		FROM evidence_chain ec
		LEFT JOIN evidence_file ef ON ec.evidence_id = ef.evidence_id
		GROUP BY ec.evidence_id
		ORDER BY ec.timestamp DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query failed: %v", err),
		})
		return
	}
	defer rows.Close()

	evidenceList := make([]map[string]interface{}, 0)
	var scanErrors int
	for rows.Next() {
		var evidenceID, timestamp, operator, action sql.NullString
		var fileCount int

		if err := rows.Scan(&evidenceID, &timestamp, &operator, &action, &fileCount); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("ListEvidence: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}

		item := map[string]interface{}{
			"evidence_id": evidenceID.String,
			"timestamp":   timestamp.String,
			"operator":    operator.String,
			"action":      action.String,
			"file_count":  fileCount,
		}
		evidenceList = append(evidenceList, item)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query iteration failed: %v", err),
		})
		return
	}

	if scanErrors > 5 {
		log.Printf("ListEvidence: total %d rows skipped due to scan errors", scanErrors)
	}

	var total int
	if err := h.db.QueryRow("SELECT COUNT(DISTINCT evidence_id) FROM evidence_chain").Scan(&total); err != nil {
		total = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"evidence": evidenceList,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

func (h *ForensicsHandler) GetEvidence(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "evidence retrieval is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	evidenceID := c.Param("id")
	if evidenceID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "evidence ID is required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	chainRows, err := h.db.Query(`
		SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
		FROM evidence_chain
		WHERE evidence_id = ?
		ORDER BY timestamp ASC
	`, evidenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query failed: %v", err),
		})
		return
	}
	defer chainRows.Close()

	chain := make([]map[string]interface{}, 0)
	var scanErrors int
	for chainRows.Next() {
		var id int64
		var evID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString

		if err := chainRows.Scan(&id, &evID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("GetEvidence chain: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}

		entry := map[string]interface{}{
			"id":          id,
			"evidence_id": evID.String,
			"timestamp":   timestamp.String,
			"operator":    operator.String,
			"action":      action.String,
		}
		if inputHash.Valid {
			entry["input_hash"] = inputHash.String
		}
		if outputHash.Valid {
			entry["output_hash"] = outputHash.String
		}
		if previousHash.Valid {
			entry["previous_hash"] = previousHash.String
		}
		chain = append(chain, entry)
	}

	if err := chainRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("chain query iteration failed: %v", err),
		})
		return
	}

	if len(chain) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"id":      evidenceID,
			"status":  "not_found",
			"message": "Evidence not found",
		})
		return
	}

	fileRows, err := h.db.Query(`
		SELECT id, file_path, file_hash, collected_at, collector
		FROM evidence_file
		WHERE evidence_id = ?
		ORDER BY collected_at ASC
	`, evidenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query failed: %v", err),
		})
		return
	}
	defer fileRows.Close()

	files := make([]map[string]interface{}, 0)
	for fileRows.Next() {
		var id int64
		var filePath, fileHash, collectedAt, collector sql.NullString

		if err := fileRows.Scan(&id, &filePath, &fileHash, &collectedAt, &collector); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("GetEvidence files: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}

		files = append(files, map[string]interface{}{
			"id":           id,
			"file_path":    filePath.String,
			"file_hash":    fileHash.String,
			"collected_at": collectedAt.String,
			"collector":    collector.String,
		})
	}

	if err := fileRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("files query iteration failed: %v", err),
		})
		return
	}

	if scanErrors > 5 {
		log.Printf("GetEvidence: total %d rows skipped due to scan errors", scanErrors)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":     evidenceID,
		"status": "found",
		"chain":  chain,
		"files":  files,
		"summary": map[string]interface{}{
			"chain_length": len(chain),
			"file_count":   len(files),
		},
	})
}

func (h *ForensicsHandler) ExportEvidence(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "evidence export is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	evidenceID := c.Param("id")
	if evidenceID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "evidence ID is required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	format := c.DefaultQuery("format", "json")

	chainRows, err := h.db.Query(`
		SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
		FROM evidence_chain
		WHERE evidence_id = ?
		ORDER BY timestamp ASC
	`, evidenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query failed: %v", err),
		})
		return
	}
	defer chainRows.Close()

	chain := make([]map[string]interface{}, 0)
	for chainRows.Next() {
		var id int64
		var evID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString
		if err := chainRows.Scan(&id, &evID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
			continue
		}
		entry := map[string]interface{}{
			"id":          id,
			"evidence_id": evID.String,
			"timestamp":   timestamp.String,
			"operator":    operator.String,
			"action":      action.String,
		}
		if inputHash.Valid {
			entry["input_hash"] = inputHash.String
		}
		if outputHash.Valid {
			entry["output_hash"] = outputHash.String
		}
		if previousHash.Valid {
			entry["previous_hash"] = previousHash.String
		}
		chain = append(chain, entry)
	}
	if err := chainRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("chain query iteration failed: %v", err),
		})
		return
	}

	fileRows, err := h.db.Query(`
		SELECT id, file_path, file_hash, collected_at, collector
		FROM evidence_file
		WHERE evidence_id = ?
		ORDER BY collected_at ASC
	`, evidenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("query failed: %v", err),
		})
		return
	}
	defer fileRows.Close()

	files := make([]map[string]interface{}, 0)
	for fileRows.Next() {
		var id int64
		var filePath, fileHash, collectedAt, collector sql.NullString
		if err := fileRows.Scan(&id, &filePath, &fileHash, &collectedAt, &collector); err != nil {
			continue
		}
		files = append(files, map[string]interface{}{
			"id":           id,
			"file_path":    filePath.String,
			"file_hash":    fileHash.String,
			"collected_at": collectedAt.String,
			"collector":    collector.String,
		})
	}
	if err := fileRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("files query iteration failed: %v", err),
		})
		return
	}

	response := gin.H{
		"id":      evidenceID,
		"chain":   chain,
		"files":   files,
		"summary": map[string]interface{}{
			"chain_length": len(chain),
			"file_count":   len(files),
		},
		"export_time": time.Now().Format(time.RFC3339),
	}

	if format == "json" {
		data, err := jsonMarshalIndent(response)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
			return
		}
		filename := fmt.Sprintf("evidence_%s.json", evidenceID)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", data)
	} else {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "unsupported format, only json is supported",
		})
	}
}

func (h *ForensicsHandler) GenerateManifest(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Use POST /api/forensics/collect to generate a real evidence manifest",
	})
}

func buildChainEntries(rows *sql.Rows) ([]map[string]interface{}, error) {
	chain := []map[string]interface{}{}
	var scanErrors int
	for rows.Next() {
		var id int64
		var evidenceID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString
		if err := rows.Scan(&id, &evidenceID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
			scanErrors++
			if scanErrors <= 5 {
				log.Printf("buildChainEntries: scan error on row %d: %v", scanErrors, err)
			}
			continue
		}
		entry := map[string]interface{}{
			"id":          id,
			"evidence_id": evidenceID.String,
			"timestamp":   timestamp.String,
			"operator":    operator.String,
			"action":      action.String,
		}
		if inputHash.Valid {
			entry["input_hash"] = inputHash.String
		}
		if outputHash.Valid {
			entry["output_hash"] = outputHash.String
		}
		if previousHash.Valid {
			entry["previous_hash"] = previousHash.String
		}
		chain = append(chain, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if scanErrors > 5 {
		log.Printf("buildChainEntries: total %d rows skipped due to scan errors", scanErrors)
	}
	return chain, nil
}

func (h *ForensicsHandler) ChainOfCustody(c *gin.Context) {
	evidenceID := c.Query("evidence_id")

	var rows *sql.Rows
	var err error

	if evidenceID == "" {
		rows, err = h.db.Query(`
			SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
			FROM evidence_chain
			ORDER BY timestamp DESC
			LIMIT 100
		`)
	} else {
		rows, err = h.db.Query(`
			SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
			FROM evidence_chain
			WHERE evidence_id = ?
			ORDER BY timestamp DESC
		`, evidenceID)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}
	defer rows.Close()

	chain, err := buildChainEntries(rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("chain query iteration failed: %v", err),
		})
		return
	}

	resp := gin.H{
		"chain": chain,
		"total": len(chain),
	}
	if evidenceID != "" {
		resp["evidence_id"] = evidenceID
	}

	c.JSON(http.StatusOK, resp)
}

func (h *ForensicsHandler) MemoryDump(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "memory dump is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	var req MemoryDumpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		if runtime.GOOS == "windows" {
			outputPath = filepath.Join(os.Getenv("TEMP"), "winalog_memory")
		} else {
			outputPath = filepath.Join(os.TempDir(), "winalog_memory")
		}
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create output directory"})
			return
		}
	} else {
		cleaned := filepath.Clean(outputPath)
		if strings.Contains(cleaned, "..") {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "invalid output path: path traversal not allowed",
			})
			return
		}
		outputPath = cleaned
	}

	collector := forensics.NewMemoryCollector(outputPath)

	if req.PID > 0 {
		result, err := collector.CollectProcessMemory(req.PID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": err.Error(),
				"pid":     req.PID,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"result": result,
		})
		return
	}

	result, err := collector.CollectSystemMemory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"result": result,
	})
}

func generateEvidenceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("ev_%s_%s", time.Now().Format("20060102150405"), hex.EncodeToString(b))
}

func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func SetupForensicsRoutes(r *gin.Engine, forensicsHandler *ForensicsHandler) {
	forensicsGroup := r.Group("/api/forensics")
	{
		forensicsGroup.POST("/hash", forensicsHandler.CalculateHash)
		forensicsGroup.GET("/verify-hash", forensicsHandler.VerifyHash)
		forensicsGroup.GET("/signature", forensicsHandler.VerifySignature)
		forensicsGroup.GET("/is-signed", forensicsHandler.IsSigned)
		forensicsGroup.POST("/collect", forensicsHandler.CollectEvidence)
		forensicsGroup.GET("/evidence", forensicsHandler.ListEvidence)
		forensicsGroup.GET("/evidence/:id", forensicsHandler.GetEvidence)
		forensicsGroup.GET("/evidence/:id/export", forensicsHandler.ExportEvidence)
		forensicsGroup.POST("/manifest", forensicsHandler.GenerateManifest)
		forensicsGroup.GET("/chain-of-custody", forensicsHandler.ChainOfCustody)
		forensicsGroup.POST("/memory-dump", forensicsHandler.MemoryDump)
	}
}
