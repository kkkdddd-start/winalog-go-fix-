package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHealthCheck(t *testing.T) {
	t.Helper()
	router := gin.New()
	router.GET("/api/health", healthCheck)

	req, _ := http.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthCheck() status = %v, want %v", w.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("healthCheck() status = %v, want ok", response["status"])
	}
	if response["service"] != "winalog-api" {
		t.Errorf("healthCheck() service = %v, want winalog-api", response["service"])
	}
}

func TestQueryHandler_Execute_EmptySQL(t *testing.T) {
	t.Helper()
	router := gin.New()

	handler := &QueryHandler{db: nil}
	router.POST("/api/query/execute", handler.Execute)

	body := bytes.NewBufferString(`{"sql": ""}`)
	req, _ := http.NewRequest("POST", "/api/query/execute", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Execute() status = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func TestQueryHandler_Execute_InvalidJSON(t *testing.T) {
	t.Helper()
	router := gin.New()

	handler := &QueryHandler{db: nil}
	router.POST("/api/query/execute", handler.Execute)

	body := bytes.NewBufferString(`invalid json`)
	req, _ := http.NewRequest("POST", "/api/query/execute", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Execute() status = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func TestSetupCorrelationRoutes(t *testing.T) {
	t.Helper()
	router := gin.New()
	handler := &CorrelationHandler{db: nil}
	SetupCorrelationRoutes(router, handler)

	routes := router.Routes()
	found := false
	for _, r := range routes {
		if r.Method == "POST" && r.Path == "/api/correlation/analyze" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SetupCorrelationRoutes() did not register /api/correlation/analyze")
	}
}

func TestSetupMultiRoutes(t *testing.T) {
	t.Helper()
	router := gin.New()
	handler := &MultiHandler{db: nil}
	SetupMultiRoutes(router, handler)

	routes := router.Routes()
	foundAnalyze := false
	foundLateral := false
	for _, r := range routes {
		if r.Method == "POST" && r.Path == "/api/multi/analyze" {
			foundAnalyze = true
		}
		if r.Method == "GET" && r.Path == "/api/multi/lateral" {
			foundLateral = true
		}
	}
	if !foundAnalyze {
		t.Error("SetupMultiRoutes() did not register POST /api/multi/analyze")
	}
	if !foundLateral {
		t.Error("SetupMultiRoutes() did not register GET /api/multi/lateral")
	}
}

func TestSetupQueryRoutes(t *testing.T) {
	t.Helper()
	router := gin.New()
	handler := &QueryHandler{db: nil}
	SetupQueryRoutes(router, handler)

	routes := router.Routes()
	found := false
	for _, r := range routes {
		if r.Method == "POST" && r.Path == "/api/query/execute" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SetupQueryRoutes() did not register /api/query/execute")
	}
}

func TestSetupSuppressRoutes(t *testing.T) {
	t.Helper()
	router := gin.New()
	handler := &SuppressHandler{db: nil}
	SetupSuppressRoutes(router, handler)

	routes := router.Routes()
	methods := make(map[string]bool)
	for _, r := range routes {
		methods[r.Method+r.Path] = true
	}

	expected := []string{"GET/api/suppress", "POST/api/suppress", "GET/api/suppress/:id", "PUT/api/suppress/:id", "DELETE/api/suppress/:id", "POST/api/suppress/:id/toggle"}
	for _, exp := range expected {
		if !methods[exp] {
			t.Errorf("SetupSuppressRoutes() missing route: %s", exp)
		}
	}
}

func TestSetupUEBARoutes(t *testing.T) {
	t.Helper()
	router := gin.New()
	handler := &UEBAHandler{db: nil}
	SetupUEBARoutes(router, handler)

	routes := router.Routes()
	foundAnalyze := false
	foundProfiles := false
	foundAnomaly := false
	for _, r := range routes {
		if r.Method == "POST" && r.Path == "/api/ueba/analyze" {
			foundAnalyze = true
		}
		if r.Method == "GET" && r.Path == "/api/ueba/profiles" {
			foundProfiles = true
		}
		if r.Method == "GET" && r.Path == "/api/ueba/anomaly/:type" {
			foundAnomaly = true
		}
	}
	if !foundAnalyze {
		t.Error("SetupUEBARoutes() missing POST /api/ueba/analyze")
	}
	if !foundProfiles {
		t.Error("SetupUEBARoutes() missing GET /api/ueba/profiles")
	}
	if !foundAnomaly {
		t.Error("SetupUEBARoutes() missing GET /api/ueba/anomaly/:type")
	}
}

func TestCorrelationRequest_Binding(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid", `{"time_window": "24h", "rules": ["rule1"]}`, false},
		{"empty", `{}`, false},
		{"invalid json", `{invalid}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CorrelationRequest
			err := json.Unmarshal([]byte(tt.json), &req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQueryRequest_Binding(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid", `{"sql": "SELECT * FROM events", "limit": 100}`, false},
		{"empty", `{}`, false},
		{"invalid json", `{invalid}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req QueryRequest
			err := json.Unmarshal([]byte(tt.json), &req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSuppressRuleRequest_Binding(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid", `{"name": "test", "conditions": [], "duration": 60}`, false},
		{"empty", `{}`, false},
		{"invalid json", `{invalid}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req SuppressRuleRequest
			err := json.Unmarshal([]byte(tt.json), &req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUEBARequest_Binding(t *testing.T) {
	t.Helper()
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"valid", `{"hours": 24, "start_time": "2024-01-01T00:00:00Z"}`, false},
		{"empty", `{}`, false},
		{"invalid json", `{invalid}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req UEBARequest
			err := json.Unmarshal([]byte(tt.json), &req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkCorrelationHandler_Analyze(b *testing.B) {
	b.Helper()
	router := gin.New()
	handler := &CorrelationHandler{db: nil}
	router.POST("/api/correlation/analyze", handler.Analyze)

	body := bytes.NewBufferString(`{"time_window": "24h"}`)
	req, _ := http.NewRequest("POST", "/api/correlation/analyze", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.ServeHTTP(w, req)
	}
}

func BenchmarkQueryHandler_Execute(b *testing.B) {
	b.Helper()
	router := gin.New()
	handler := &QueryHandler{db: nil}
	router.POST("/api/query/execute", handler.Execute)

	body := bytes.NewBufferString(`{"sql": "SELECT * FROM events LIMIT 100"}`)
	req, _ := http.NewRequest("POST", "/api/query/execute", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.ServeHTTP(w, req)
	}
}

func TestSuppressHandler_ListSuppressRules_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	router := gin.New()
	handler := NewSuppressHandler(db, nil)
	router.GET("/api/suppress", handler.ListSuppressRules)

	req, _ := http.NewRequest("GET", "/api/suppress", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListSuppressRules() status = %v, want %v", w.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["total"] != float64(0) {
		t.Errorf("ListSuppressRules() total = %v, want 0", response["total"])
	}
}

func TestSuppressHandler_CreateSuppressRule_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	router := gin.New()
	handler := NewSuppressHandler(db, nil)
	router.POST("/api/suppress", handler.CreateSuppressRule)

	body := bytes.NewBufferString(`{"name": "test_rule", "conditions": [], "duration": 60, "scope": "global", "enabled": true}`)
	req, _ := http.NewRequest("POST", "/api/suppress", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Errorf("CreateSuppressRule() status = %v, want %v or %v", w.Code, http.StatusOK, http.StatusCreated)
	}
}

func TestQueryHandler_Execute_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.Exec(`
		INSERT INTO events (timestamp, event_id, level, log_name, computer, message, import_time)
		VALUES (?, 4624, 1, 'Security', 'WORKSTATION1', 'Test event', ?)
	`, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	router := gin.New()
	handler := NewQueryHandler(db)
	router.POST("/api/query/execute", handler.Execute)

	body := bytes.NewBufferString(`{"sql": "SELECT * FROM events"}`)
	req, _ := http.NewRequest("POST", "/api/query/execute", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Execute() status = %v, want %v", w.Code, http.StatusOK)
	}

	var response QueryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Count != 1 {
		t.Errorf("Execute() count = %v, want 1", response.Count)
	}
}

func TestSystemHandler_GetSystemInfo_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewSystemHandler(db)

	router := gin.New()
	router.GET("/api/system/info", handler.GetSystemInfo)

	req, _ := http.NewRequest("GET", "/api/system/info", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetSystemInfo() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestDashboardHandler_GetCollectionStats_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewDashboardHandler(db)

	router := gin.New()
	router.GET("/api/dashboard/collection", handler.GetCollectionStats)

	req, _ := http.NewRequest("GET", "/api/dashboard/collection", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetCollectionStats() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestAlertHandler_GetAlertStats_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := &AlertHandler{db: db, alertEngine: nil}

	router := gin.New()
	router.GET("/api/alerts/stats", handler.GetAlertStats)

	req, _ := http.NewRequest("GET", "/api/alerts/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetAlertStats() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestAlertHandler_GetAlert_NotFound(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := &AlertHandler{db: db, alertEngine: nil}

	router := gin.New()
	router.GET("/api/alerts/:id", handler.GetAlert)

	req, _ := http.NewRequest("GET", "/api/alerts/999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GetAlert() status = %v, want %v", w.Code, http.StatusNotFound)
	}
}

func TestReportsHandler_ListTemplates_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewReportsHandler(db)

	router := gin.New()
	router.GET("/api/reports/templates", handler.ListTemplates)

	req, _ := http.NewRequest("GET", "/api/reports/templates", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListTemplates() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestRulesHandler_ListRules(t *testing.T) {
	t.Helper()
	handler := NewRulesHandler(nil)

	router := gin.New()
	router.GET("/api/rules", handler.ListRules)

	req, _ := http.NewRequest("GET", "/api/rules", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListRules() status = %v, want %v", w.Code, http.StatusOK)
	}

	var response RulesListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.TotalCount < 0 {
		t.Errorf("ListRules() total_count = %v, want >= 0", response.TotalCount)
	}
}

func TestUEBAHandler_GetProfiles_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewUEBAHandler(db)

	router := gin.New()
	router.GET("/api/ueba/profiles", handler.GetProfiles)

	req, _ := http.NewRequest("GET", "/api/ueba/profiles", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetProfiles() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestCorrelationHandler_Analyze_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewCorrelationHandler(db)

	router := gin.New()
	router.POST("/api/correlation/analyze", handler.Analyze)

	body := bytes.NewBufferString(`{"time_window": "1h"}`)
	req, _ := http.NewRequest("POST", "/api/correlation/analyze", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Analyze() status = %v, want %v", w.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["count"] == nil {
		t.Error("Analyze() response missing count")
	}
}

func TestMultiHandler_Analyze_WithDB(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewMultiHandler(db)

	router := gin.New()
	router.POST("/api/multi/analyze", handler.Analyze)

	body := bytes.NewBufferString(`{}`)
	req, _ := http.NewRequest("POST", "/api/multi/analyze", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Analyze() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestCollectHandler_GetCollectStatus(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewCollectHandler(db, nil)

	router := gin.New()
	router.GET("/api/collect/status", handler.GetCollectStatus)

	req, _ := http.NewRequest("GET", "/api/collect/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetCollectStatus() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestForensicsHandler_ListEvidence(t *testing.T) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewForensicsHandler(db)

	router := gin.New()
	router.GET("/api/forensics/evidence", handler.ListEvidence)

	req, _ := http.NewRequest("GET", "/api/forensics/evidence", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if runtime.GOOS != "windows" {
		if w.Code != http.StatusNotImplemented {
			t.Errorf("ListEvidence() status = %v, want %v on non-Windows", w.Code, http.StatusNotImplemented)
		}
	} else {
		if w.Code != http.StatusOK {
			t.Errorf("ListEvidence() status = %v, want %v on Windows", w.Code, http.StatusOK)
		}
	}
}
