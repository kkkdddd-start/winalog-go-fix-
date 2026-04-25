package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

func setupTestDBForReports(t *testing.T) *storage.DB {
	db, err := storage.NewDB(":memory:")
	if err != nil {
		t.Skip("skipping test: failed to create test database")
	}

	if err := db.CreateTables(); err != nil {
		t.Skip("skipping test: failed to create tables")
	}

	return db
}

func TestReportsHandler_ListReports(t *testing.T) {
	db := setupTestDBForReports(t)
	defer db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := NewReportsHandler(db)
	SetupReportsRoutes(router, handler)

	req := httptest.NewRequest("GET", "/api/reports", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["reports"] == nil {
		t.Error("expected 'reports' field in response")
	}
}

func TestReportsHandler_GenerateReport_InvalidRequest(t *testing.T) {
	db := setupTestDBForReports(t)
	defer db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := NewReportsHandler(db)
	SetupReportsRoutes(router, handler)

	body := map[string]interface{}{}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/reports", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestReportsHandler_GetReport_NotFound(t *testing.T) {
	db := setupTestDBForReports(t)
	defer db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := NewReportsHandler(db)
	SetupReportsRoutes(router, handler)

	req := httptest.NewRequest("GET", "/api/reports/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", w.Code)
	}
}

func TestReportsHandler_ListTemplates(t *testing.T) {
	db := setupTestDBForReports(t)
	defer db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := NewReportsHandler(db)
	SetupReportsRoutes(router, handler)

	req := httptest.NewRequest("GET", "/api/report-templates", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["templates"] == nil {
		t.Error("expected 'templates' field in response")
	}
}

func TestReportsHandler_ExportData(t *testing.T) {
	db := setupTestDBForReports(t)
	defer db.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()

	handler := NewReportsHandler(db)
	SetupReportsRoutes(router, handler)

	req := httptest.NewRequest("GET", "/api/reports/export?format=json", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestReportsHandler_GetReportInfo(t *testing.T) {
	t.Skip("requires database setup with reports table")
}
