package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

func TestIntegration_SuppressHandler_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewSuppressHandler(db, nil)

	router := gin.New()
	router.GET("/api/suppress", handler.ListSuppressRules)
	router.POST("/api/suppress", handler.CreateSuppressRule)
	router.DELETE("/api/suppress/:id", handler.DeleteSuppressRule)

	t.Run("List empty", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/suppress", nil, handler.ListSuppressRules)
		AssertStatus(t, w, http.StatusOK)

		var resp map[string]interface{}
		assertJSONResponse(t, w, &resp)
		if resp["total"] != float64(0) {
			t.Errorf("Expected empty list")
		}
	})

	t.Run("Create rule", func(t *testing.T) {
		body := []byte(`{"name": "test_rule", "conditions": [], "duration": 60}`)
		w, _ := makeRequest(t, "POST", "/api/suppress", body, handler.CreateSuppressRule)
		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			t.Errorf("Create failed with status %d", w.Code)
		}
	})
}

func TestIntegration_QueryHandler_Events(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	now := time.Now().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO events (timestamp, event_id, level, log_name, computer, message, import_time)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, now, 4624, 1, "Security", "WORKSTATION1", "Test login event", now)
	if err != nil {
		t.Fatalf("Failed to insert test event: %v", err)
	}

	handler := NewQueryHandler(db)

	router := gin.New()
	router.POST("/api/query/execute", handler.Execute)

	body := []byte(`{"sql": "SELECT * FROM events"}`)
	w, _ := makeRequest(t, "POST", "/api/query/execute", body, handler.Execute)

	AssertStatus(t, w, http.StatusOK)
	AssertNoError(t, w)

	var resp QueryResponse
	assertJSONResponse(t, w, &resp)
	if resp.Count != 1 {
		t.Errorf("Expected 1 event, got %d", resp.Count)
	}
}

func TestIntegration_UEBAHandler_Profiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewUEBAHandler(db)

	router := gin.New()
	router.GET("/api/ueba/profiles", handler.GetProfiles)
	router.POST("/api/ueba/analyze", handler.Analyze)

	t.Run("GetProfiles empty", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/ueba/profiles", nil, handler.GetProfiles)
		AssertStatus(t, w, http.StatusOK)
	})

	t.Run("Analyze no data", func(t *testing.T) {
		body := []byte(`{"hours": 24}`)
		w, _ := makeRequest(t, "POST", "/api/ueba/analyze", body, handler.Analyze)
		AssertStatus(t, w, http.StatusOK)
	})
}

func TestIntegration_CorrelationHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewCorrelationHandler(db)

	router := gin.New()
	router.POST("/api/correlation/analyze", handler.Analyze)

	body := []byte(`{"time_window": "24h"}`)
	w, _ := makeRequest(t, "POST", "/api/correlation/analyze", body, handler.Analyze)

	AssertStatus(t, w, http.StatusOK)

	var resp map[string]interface{}
	assertJSONResponse(t, w, &resp)
	if resp["count"] == nil {
		t.Errorf("Expected count in response")
	}
}

func TestIntegration_MultiHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewMultiHandler(db)

	router := gin.New()
	router.POST("/api/multi/analyze", handler.Analyze)
	router.GET("/api/multi/lateral", handler.Lateral)

	t.Run("Analyze empty", func(t *testing.T) {
		body := []byte(`{}`)
		w, _ := makeRequest(t, "POST", "/api/multi/analyze", body, handler.Analyze)
		AssertStatus(t, w, http.StatusOK)
	})

	t.Run("Lateral empty", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/multi/lateral", nil, handler.Lateral)
		AssertStatus(t, w, http.StatusOK)
	})
}

func TestIntegration_SystemHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewSystemHandler(db)

	router := gin.New()
	router.GET("/api/system/info", handler.GetSystemInfo)
	router.GET("/api/system/metrics", handler.GetMetrics)

	t.Run("GetSystemInfo", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/system/info", nil, handler.GetSystemInfo)
		AssertStatus(t, w, http.StatusOK)
	})

	t.Run("GetMetrics", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/system/metrics", nil, handler.GetMetrics)
		AssertStatus(t, w, http.StatusOK)
	})
}

func TestIntegration_ForensicsHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewForensicsHandler(db)

	router := gin.New()
	router.GET("/api/forensics/evidence", handler.ListEvidence)
	router.GET("/api/forensics/calculate-hash", handler.CalculateHash)

	expectedStatus := http.StatusOK
	if runtime.GOOS != "windows" {
		expectedStatus = http.StatusNotImplemented
	}

	t.Run("ListEvidence empty", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/forensics/evidence", nil, handler.ListEvidence)
		AssertStatus(t, w, expectedStatus)
	})

	t.Run("CalculateHash", func(t *testing.T) {
		w, _ := makeRequest(t, "GET", "/api/forensics/calculate-hash", nil, handler.CalculateHash)
		AssertStatus(t, w, expectedStatus)
	})
}

func TestAsyncOperation_WithTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping async test in short mode")
	}

	done := make(chan bool)
	var result string

	go func() {
		time.Sleep(50 * time.Millisecond)
		result = "completed"
		done <- true
	}()

	select {
	case <-done:
		if result != "completed" {
			t.Errorf("Expected 'completed', got '%s'", result)
		}
	case <-time.After(1 * time.Second):
		t.Error("Operation timed out")
	}
}

func TestAsyncOperation_Cancel(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping async test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan string, 1)

	go func() {
		time.Sleep(100 * time.Millisecond)
		done <- "should not complete"
	}()

	select {
	case <-ctx.Done():
	case <-done:
		t.Error("Operation should have been cancelled")
	}
}

func BenchmarkQueryHandler_Execute_Full(b *testing.B) {
	db, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	now := time.Now().Format(time.RFC3339)
	for i := 0; i < 100; i++ {
		_, _ = db.Exec(`
			INSERT INTO events (timestamp, event_id, level, log_name, computer, message, import_time)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, now, 4624, 1, "Security", "WORKSTATION1", "Test event", now)
	}

	handler := NewQueryHandler(db)
	router := gin.New()
	router.POST("/api/query/execute", handler.Execute)

	body := bytes.NewBufferString(`{"sql": "SELECT * FROM events"}`)
	req, _ := http.NewRequest("POST", "/api/query/execute", body)
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkSupppressHandler_List(b *testing.B) {
	db, cleanup := setupBenchmarkDB(b)
	defer cleanup()

	now := time.Now().Format(time.RFC3339)
	for i := 0; i < 50; i++ {
		_, _ = db.Exec(`
			INSERT INTO suppress_rules (name, conditions, duration, scope, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, "rule", "[]", 60, "global", 1, now)
	}

	handler := NewSuppressHandler(db, nil)
	router := gin.New()
	router.GET("/api/suppress", handler.ListSuppressRules)

	req, _ := http.NewRequest("GET", "/api/suppress", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func setupBenchmarkDB(b *testing.B) (*storage.DB, func()) {
	tmpDir, err := os.MkdirTemp("", "winalog-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "bench.db")
	db, err := storage.NewDB(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		b.Fatalf("Failed to create benchmark db: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}
