package storage

import (
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/persistence"
)

type PersistenceDetectionRepo struct {
	db *DB
}

func NewPersistenceDetectionRepo(db *DB) *PersistenceDetectionRepo {
	return &PersistenceDetectionRepo{db: db}
}

func (r *PersistenceDetectionRepo) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS persistence_detections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		detection_id TEXT NOT NULL UNIQUE,
		technique TEXT NOT NULL,
		category TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		evidence_type TEXT,
		evidence_path TEXT,
		evidence_key TEXT,
		evidence_value TEXT,
		evidence_file_path TEXT,
		evidence_command TEXT,
		mitre_ref TEXT,
		recommended_action TEXT,
		false_positive_risk TEXT,
		detected_at TEXT NOT NULL,
		is_true_positive INTEGER DEFAULT -1,
		notes TEXT,
		created_at TEXT DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_persistence_detections_technique 
		ON persistence_detections(technique);
	CREATE INDEX IF NOT EXISTS idx_persistence_detections_severity 
		ON persistence_detections(severity);
	CREATE INDEX IF NOT EXISTS idx_persistence_detections_detected_at 
		ON persistence_detections(detected_at);
	`
	_, err := r.db.Exec(schema)
	return err
}

func (r *PersistenceDetectionRepo) SaveDetection(det *persistence.Detection) error {
	detectionID := det.ID
	if detectionID == "" {
		detectionID = fmt.Sprintf("det_%d", time.Now().UnixNano())
	}

	mitreRef := ""
	if len(det.MITRERef) > 0 {
		mitreRef = strings.Join(det.MITRERef, ",")
	}

	query := `
	INSERT INTO persistence_detections (
		detection_id, technique, category, severity, title, description,
		evidence_type, evidence_path, evidence_key, evidence_value,
		evidence_file_path, evidence_command, mitre_ref, recommended_action,
		false_positive_risk, detected_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	evidence := det.Evidence

	_, err := r.db.Exec(query,
		detectionID,
		string(det.Technique),
		det.Category,
		string(det.Severity),
		det.Title,
		det.Description,
		string(evidence.Type),
		evidence.Path,
		evidence.Key,
		evidence.Value,
		evidence.FilePath,
		evidence.Command,
		mitreRef,
		det.RecommendedAction,
		det.FalsePositiveRisk,
		det.Time,
	)
	return err
}

func (r *PersistenceDetectionRepo) SaveResult(result *persistence.DetectionResult) error {
	for _, det := range result.Detections {
		if err := r.SaveDetection(det); err != nil {
			return err
		}
	}
	return nil
}

type PersistenceQueryRequest struct {
	Technique      string
	Category       string
	Severity       string
	StartTime      string
	EndTime        string
	IsTruePositive int
	Limit          int
	Offset         int
}

func (r *PersistenceDetectionRepo) Query(req *PersistenceQueryRequest) ([]*persistence.Detection, int64, error) {
	return nil, 0, nil
}

func (r *PersistenceDetectionRepo) MarkTruePositive(detectionID string, isTruePositive bool, notes string) error {
	query := "UPDATE persistence_detections SET is_true_positive = ?, notes = ? WHERE detection_id = ?"
	var tp int
	if isTruePositive {
		tp = 1
	} else {
		tp = 0
	}
	_, err := r.db.Exec(query, tp, notes, detectionID)
	return err
}

func (r *PersistenceDetectionRepo) queryAll() ([]*persistence.Detection, error) {
	query := `SELECT id, detection_id, technique, category, severity, title, description, 
		evidence_type, evidence_path, evidence_key, evidence_value, 
		evidence_file_path, evidence_command, mitre_ref, recommended_action, 
		false_positive_risk, detected_at, is_true_positive, notes, created_at 
		FROM persistence_detections ORDER BY detected_at DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	detections := make([]*persistence.Detection, 0)
	for rows.Next() {
		var detection persistence.Detection
		var evidence persistence.Evidence
		var detectedAt string
		var detectionID, technique, category, severity, title, description string
		var evidenceType, evidencePath, evidenceKey, evidenceValue string
		var evidenceFilePath, evidenceCommand, mitreRef string
		var recommendedAction, falsePositiveRisk string
		var isTruePositive int
		var notes string

		err := rows.Scan(
			&detection.ID,
			&detectionID,
			&technique,
			&category,
			&severity,
			&title,
			&description,
			&evidenceType,
			&evidencePath,
			&evidenceKey,
			&evidenceValue,
			&evidenceFilePath,
			&evidenceCommand,
			&mitreRef,
			&recommendedAction,
			&falsePositiveRisk,
			&detectedAt,
			&isTruePositive,
			&notes,
		)
		if err != nil {
			continue
		}

		detection.ID = detectionID
		detection.Technique = persistence.Technique(technique)
		detection.Category = category
		detection.Severity = persistence.Severity(severity)
		detection.Title = title
		detection.Description = description
		evidence.Type = persistence.EvidenceType(evidenceType)
		evidence.Path = evidencePath
		evidence.Key = evidenceKey
		evidence.Value = evidenceValue
		evidence.FilePath = evidenceFilePath
		evidence.Command = evidenceCommand
		detection.Evidence = evidence
		detection.MITRERef = strings.Split(mitreRef, ",")
		detection.RecommendedAction = recommendedAction
		detection.FalsePositiveRisk = falsePositiveRisk

		if t, err := time.Parse(time.RFC3339, detectedAt); err == nil {
			detection.Time = t
		}

		detections = append(detections, &detection)
	}

	return detections, nil
}
