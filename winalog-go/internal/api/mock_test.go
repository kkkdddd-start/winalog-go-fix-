package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type MockDB struct {
	QueryFunc    func(sql string, args ...interface{}) (*MockRows, error)
	ExecFunc     func(sql string, args ...interface{}) (int64, int64, error)
	QueryRowFunc func(sql string, args ...interface{}) *MockRow
}

type MockRows struct {
	Columns []string
	Rows    [][]interface{}
	Index   int
	Closed  bool
}

type MockRow struct {
	ScanFunc func(dest ...interface{}) error
}

func (r *MockRows) Next() bool {
	if r.Index < len(r.Rows) {
		r.Index++
		return true
	}
	return false
}

func (r *MockRows) Scan(dest ...interface{}) error {
	if r.Index <= 0 || r.Index > len(r.Rows) {
		return nil
	}
	row := r.Rows[r.Index-1]
	for i, val := range row {
		if i < len(dest) {
			switch d := dest[i].(type) {
			case *string:
				if v, ok := val.(string); ok {
					*d = v
				}
			case *int:
				if v, ok := val.(int); ok {
					*d = v
				}
			case *int64:
				if v, ok := val.(int64); ok {
					*d = v
				}
			case *bool:
				if v, ok := val.(bool); ok {
					*d = v
				}
			case *float64:
				if v, ok := val.(float64); ok {
					*d = v
				}
			}
		}
	}
	return nil
}

func (r *MockRows) Close() error {
	r.Closed = true
	return nil
}

func (r *MockRow) Scan(dest ...interface{}) error {
	if r.ScanFunc != nil {
		return r.ScanFunc(dest...)
	}
	return nil
}

func NewMockQueryHandler() *QueryHandler {
	return &QueryHandler{}
}

func makeRequest(t *testing.T, method, path string, body []byte, handler gin.HandlerFunc) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, path, handler)

	var req *http.Request
	if body != nil {
		req, _ = http.NewRequest(method, path, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w, req
}

func assertJSONResponse(t *testing.T, w *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
}

func AssertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("Status = %v, want %v", w.Code, want)
	}
}

func AssertJSONField(t *testing.T, w *httptest.ResponseRecorder, field string, want interface{}) {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	got, exists := result[field]
	if !exists {
		t.Errorf("Response missing field: %s", field)
		return
	}

	if got != want {
		t.Errorf("Field %s = %v, want %v", field, got, want)
	}
}

func AssertNoError(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		return
	}
	if errResp.Error != "" {
		t.Errorf("Unexpected error: %s", errResp.Error)
	}
}
