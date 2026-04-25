package api

import (
	"database/sql"
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
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
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

// NewForensicsHandler godoc
// @Summary 创建取证处理器
// @Description 初始化ForensicsHandler
// @Tags forensics
// @Param db query string true "数据库实例"
// @Router /api/forensics [get]
func NewForensicsHandler(db *storage.DB) *ForensicsHandler {
	return &ForensicsHandler{db: db}
}

// CalculateHash godoc
// @Summary 计算文件哈希值
// @Description 计算指定文件的SHA256、MD5、SHA1哈希值
// @Tags forensics
// @Accept json
// @Produce json
// @Param request body HashRequest true "文件路径请求"
// @Success 200 {object} HashResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/hash [post]
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

	result, err := forensics.CalculateFileHash(req.Path)
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

// VerifyHash godoc
// @Summary 验证文件哈希值
// @Description 验证文件哈希与预期值是否匹配
// @Tags forensics
// @Produce json
// @Param path query string true "文件路径"
// @Param expected query string true "预期哈希值"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/verify-hash [get]
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

	match, result, err := forensics.VerifyFileHash(path, expected)
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

// VerifySignature godoc
// @Summary 验证文件签名
// @Description 验证Windows可执行文件的数字签名信息
// @Tags forensics
// @Produce json
// @Param path query string true "文件路径"
// @Success 200 {object} SignatureResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/signature [get]
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

	result, err := forensics.VerifySignature(path)
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

// IsSigned godoc
// @Summary 检查文件是否签名
// @Description 检查文件是否有有效的数字签名
// @Tags forensics
// @Produce json
// @Param path query string true "文件路径"
// @Success 200 {object} map[string]interface{} "is_signed": bool, "details": object
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/is-signed [get]
func (h *ForensicsHandler) IsSigned(c *gin.Context) {
	path := c.Query("path")

	if path == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "path is required",
			Code:  types.ErrCodeInvalidRequest,
		})
		return
	}

	signed, result, err := forensics.IsSigned(path)
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

// CollectEvidence godoc
// @Summary 收集取证证据
// @Description 收集系统取证证据包括注册表、Prefetch、ShimCache等
// @Tags forensics
// @Accept json
// @Produce json
// @Param request body CollectRequest true "取证收集请求"
// @Success 200 {object} CollectResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/collect [post]
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

	evidenceID := fmt.Sprintf("ev_%d", time.Now().UnixNano())

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(os.TempDir(), fmt.Sprintf("evidence_%s.zip", evidenceID))
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
		log.Printf("[ERROR] failed to save manifest: %v", err)
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
	var errs []string

	_, err := h.db.Exec(`
		INSERT OR REPLACE INTO evidence_chain (evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, manifest.ID, manifest.CreatedAt.Format(time.RFC3339),
		manifest.CollectedBy, "manifest_created", "", manifest.Hash, "")
	if err != nil {
		errs = append(errs, fmt.Sprintf("evidence_chain: %v", err))
	}

	for _, f := range manifest.Files {
		_, err := h.db.Exec(`
			INSERT INTO evidence_file (file_path, file_hash, evidence_id, collected_at, collector)
			VALUES (?, ?, ?, ?, ?)
		`, f.FilePath, f.FileHash, manifest.ID, f.CollectedAt.Format(time.RFC3339), f.Collector)
		if err != nil {
			errs = append(errs, fmt.Sprintf("evidence_file %s: %v", f.FilePath, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("save errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ListEvidence godoc
// @Summary 列出证据列表
// @Description 返回所有已收集的证据记录
// @Tags forensics
// @Produce json
// @Param limit query int false "返回记录数量限制" default(50)
// @Param offset query int false "偏移量" default(0)
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/evidence [get]
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
	for rows.Next() {
		var evidenceID, timestamp, operator, action sql.NullString
		var fileCount int

		if err := rows.Scan(&evidenceID, &timestamp, &operator, &action, &fileCount); err != nil {
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

// GetEvidence godoc
// @Summary 获取证据详情
// @Description 根据证据ID返回证据的完整信息
// @Tags forensics
// @Produce json
// @Param id path string true "证据ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/evidence/{id} [get]
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

// GenerateManifest godoc
// @Summary 生成证据清单
// @Description 为证据收集生成哈希清单
// @Tags forensics
// @Produce json
// @Success 200 {object} object
// @Router /api/forensics/manifest [post]
func (h *ForensicsHandler) GenerateManifest(c *gin.Context) {
	manifest := forensics.GenerateManifest(nil, "web-ui", "unknown")
	c.JSON(http.StatusOK, manifest)
}

// ChainOfCustody godoc
// @Summary 获取证据保管链
// @Description 返回证据的完整保管链记录
// @Tags forensics
// @Produce json
// @Param evidence_id query string false "证据ID，默认为所有证据"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/chain-of-custody [get]
func (h *ForensicsHandler) ChainOfCustody(c *gin.Context) {
	evidenceID := c.Query("evidence_id")

	if evidenceID == "" {
		rows, err := h.db.Query(`
			SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
			FROM evidence_chain
			ORDER BY timestamp DESC
			LIMIT 100
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: err.Error(),
			})
			return
		}
		defer rows.Close()

		chain := []map[string]interface{}{}
		for rows.Next() {
			var id int64
			var evidenceID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString
			if err := rows.Scan(&id, &evidenceID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
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

		c.JSON(http.StatusOK, gin.H{
			"chain": chain,
			"total": len(chain),
		})
		return
	}

	rows, err := h.db.Query(`
		SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
		FROM evidence_chain
		WHERE evidence_id = ?
		ORDER BY timestamp DESC
	`, evidenceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: err.Error(),
		})
		return
	}
	defer rows.Close()

	chain := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var evID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString
		if err := rows.Scan(&id, &evID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
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

	c.JSON(http.StatusOK, gin.H{
		"chain":       chain,
		"total":       len(chain),
		"evidence_id": evidenceID,
	})
}

// MemoryDump godoc
// @Summary 内存转储
// @Description 对指定进程或整个系统进行内存转储
// @Tags forensics
// @Produce json
// @Param pid query string false "进程ID，不提供则转储系统内存"
// @Param output query string false "输出目录路径"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/forensics/memory-dump [get]
func (h *ForensicsHandler) MemoryDump(c *gin.Context) {
	if runtime.GOOS != "windows" {
		c.JSON(http.StatusNotImplemented, ErrorResponse{
			Error: "memory dump is only supported on Windows",
			Code:  types.ErrCodeNotSupported,
		})
		return
	}

	pidStr := c.Query("pid")
	outputPath := c.Query("output")

	if outputPath == "" {
		outputPath = filepath.Join(os.TempDir(), "winalog_memory")
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create output directory"})
			return
		}
	}

	collector := forensics.NewMemoryCollector(outputPath)

	if pidStr != "" {
		var pid uint32
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "invalid PID format",
			})
			return
		}

		result, err := collector.CollectProcessMemory(pid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": err.Error(),
				"pid":     pid,
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

// SetupForensicsRoutes godoc
// @Summary 设置取证路由
// @Description 配置取证分析相关的API路由
// @Tags forensics
// @Router /api/forensics/hash [post]
// @Router /api/forensics/verify-hash [get]
// @Router /api/forensics/signature [get]
// @Router /api/forensics/is-signed [get]
// @Router /api/forensics/collect [post]
// @Router /api/forensics/evidence [get]
// @Router /api/forensics/evidence/{id} [get]
// @Router /api/forensics/manifest [post]
// @Router /api/forensics/chain-of-custody [get]
// @Router /api/forensics/memory-dump [get]
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
		forensicsGroup.POST("/manifest", forensicsHandler.GenerateManifest)
		forensicsGroup.GET("/chain-of-custody", forensicsHandler.ChainOfCustody)
		forensicsGroup.GET("/memory-dump", forensicsHandler.MemoryDump)
	}
}
