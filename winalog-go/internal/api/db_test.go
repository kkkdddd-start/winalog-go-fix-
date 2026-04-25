package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

func setupTestDB(t *testing.T) (*storage.DB, func()) {
	tmpDir, err := os.MkdirTemp("", "winalog-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := storage.NewDB(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create test db: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}
