package api

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type AssetHandler struct {
	db *storage.DB
}

func NewAssetHandler(db *storage.DB) *AssetHandler {
	return &AssetHandler{db: db}
}

// ListAssets godoc
// @Summary 列出所有机器资产
// @Description 获取机器资产清单，支持搜索和过滤
// @Tags assets
// @Produce json
// @Param keyword query string false "搜索关键词"
// @Param role query string false "角色过滤"
// @Param source query string false "来源过滤 (manual, log_discovery)"
// @Success 200 {object} map[string]interface{}
// @Router /api/assets [get]
func (h *AssetHandler) ListAssets(c *gin.Context) {
	keyword := c.Query("keyword")
	role := c.Query("role")
	source := c.Query("source")

	query := `
		SELECT id, hostname, domain, ip_address, role, os_version, importance, source, last_seen, created_at 
		FROM machine_assets 
		WHERE 1=1
	`
	var args []interface{}

	if keyword != "" {
		query += ` AND (hostname LIKE ? OR ip_address LIKE ? OR domain LIKE ?)`
		likeKeyword := "%" + keyword + "%"
		args = append(args, likeKeyword, likeKeyword, likeKeyword)
	}
	if role != "" {
		query += ` AND role = ?`
		args = append(args, role)
	}
	if source != "" {
		query += ` AND source = ?`
		args = append(args, source)
	}

	query += ` ORDER BY last_seen DESC`

	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	var assets []MachineInfo
	for rows.Next() {
		var m MachineInfo
		var importance, source, createdAt string
		var lastSeen, osVersion sqlNullString
		if err := rows.Scan(&m.ID, &m.Name, &m.Domain, &m.IP, &m.Role, &osVersion, &importance, &source, &lastSeen, &createdAt); err != nil {
			continue
		}
		if lastSeen.Valid {
			m.LastSeen = lastSeen.String
		}
		if osVersion.Valid {
			m.OSVersion = osVersion.String
		}
		assets = append(assets, m)
	}

	if assets == nil {
		assets = []MachineInfo{}
	}

	c.JSON(http.StatusOK, gin.H{
		"assets": assets,
		"total":  len(assets),
	})
}

// ImportAssets godoc
// @Summary 导入机器资产
// @Description 通过 CSV 文件批量导入机器资产
// @Tags assets
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "CSV 文件"
// @Success 200 {object} map[string]interface{}
// @Router /api/assets/import [post]
func (h *AssetHandler) ImportAssets(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "missing file parameter"})
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".csv") {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "only CSV files are supported"})
		return
	}

	h.importCSV(c, file)
}

func (h *AssetHandler) importCSV(c *gin.Context, reader io.Reader) {
	csvReader := csv.NewReader(reader)
	// Skip BOM if present
	_, _ = csvReader.Read() // Read header row
	
	// Read all records
	records, err := csvReader.ReadAll()
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid CSV format"})
		return
	}

	successCount := 0
	failedCount := 0
	var errors []string

	tx, rollback, err := h.db.BeginTx()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO machine_assets 
		(id, hostname, domain, ip_address, role, os_version, importance, source, last_seen, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer stmt.Close()

	for i, record := range records {
		if len(record) < 2 {
			failedCount++
			errors = append(errors, fmt.Sprintf("row %d: too few columns", i+1))
			continue
		}

		hostname := strings.TrimSpace(record[0])
		ip := strings.TrimSpace(record[1])
		domain := ""
		role := "workstation"
		osVersion := ""
		importance := "medium"

		if len(record) > 2 {
			domain = strings.TrimSpace(record[2])
		}
		if len(record) > 3 {
			role = strings.ToLower(strings.TrimSpace(record[3]))
			if !isValidRole(role) {
				role = "workstation"
			}
		}
		if len(record) > 4 {
			osVersion = strings.TrimSpace(record[4])
		}
		if len(record) > 5 {
			importance = strings.ToLower(strings.TrimSpace(record[5]))
			if !isValidImportance(importance) {
				importance = "medium"
			}
		}

		id := uuid.New().String()

		_, err := stmt.Exec(id, hostname, domain, ip, role, osVersion, importance, "manual")
		if err != nil {
			failedCount++
			errors = append(errors, fmt.Sprintf("row %d: %v", i+1, err))
		} else {
			successCount++
		}
	}

	if _, err := tx.Exec("COMMIT"); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "import completed",
		"success": successCount,
		"failed":  failedCount,
		"errors":  errors,
	})
}

// DeleteAsset godoc
// @Summary 删除机器资产
// @Description 删除指定的机器资产
// @Tags assets
// @Param id path string true "资产 ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/assets/:id [delete]
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
	id := c.Param("id")
	_, err := h.db.Exec("DELETE FROM machine_assets WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "asset deleted"})
}

// SyncLogDiscovery godoc
// @Summary 同步日志发现的机器
// @Description 将日志中出现但资产列表中不存在的机器添加到资产列表
// @Tags assets
// @Success 200 {object} map[string]interface{}
// @Router /api/assets/sync [post]
func (h *AssetHandler) SyncLogDiscovery(c *gin.Context) {
	// Find all unique computers in events that are not in machine_assets
	rows, err := h.db.Query(`
		SELECT DISTINCT computer FROM events 
		WHERE computer NOT IN (SELECT hostname FROM machine_assets)
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	defer rows.Close()

	count := 0
	stmtStr := `
		INSERT OR IGNORE INTO machine_assets (id, hostname, domain, role, source, last_seen, created_at)
		VALUES (?, ?, '', 'unknown', 'log_discovery', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			continue
		}

		_, err := h.db.Exec(stmtStr, uuid.New().String(), hostname)
		if err == nil {
			count++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "sync completed",
		"discovered": count,
	})
}

func isValidRole(role string) bool {
	switch role {
	case "dc", "server", "workstation", "unknown":
		return true
	default:
		return false
	}
}

func isValidImportance(imp string) bool {
	switch imp {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

func SetupAssetRoutes(r *gin.Engine, h *AssetHandler) {
	assets := r.Group("/api/assets")
	{
		assets.GET("", h.ListAssets)
		assets.POST("/import", h.ImportAssets)
		assets.POST("/sync", h.SyncLogDiscovery)
		assets.DELETE("/:id", h.DeleteAsset)
	}
}

type sqlNullString struct {
	String string
	Valid  bool
}

func (s *sqlNullString) Scan(value interface{}) error {
	if value == nil {
		s.Valid = false
		return nil
	}
	s.String = value.(string)
	s.Valid = true
	return nil
}
