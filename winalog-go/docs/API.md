# WinLogAnalyzer-Go API Documentation

**Version**: v2.5.0  
**Last Updated**: 2026-04-17

---

## Table of Contents

1. [Overview](#1-overview)
2. [Events API](#2-events-api)
3. [Alerts API](#3-alerts-api)
4. [Timeline API](#4-timeline-api)
5. [Import API](#5-import-api)
6. [Live Events API](#6-live-events-api)
7. [Reports API](#7-reports-api)
8. [Dashboard API](#8-dashboard-api)
9. [Rules API](#9-rules-api)
10. [System API](#10-system-api)
11. [Suppress API](#11-suppress-api)
12. [UEBA API](#12-ueba-api)
13. [Correlation API](#13-correlation-api)
14. [Multi API](#14-multi-api)
15. [Query API](#15-query-api)
16. [Policy API](#16-policy-api)
17. [Monitor API](#17-monitor-api)
18. [Settings API](#18-settings-api)
19. [Persistence API](#19-persistence-api)
20. [Forensics API](#20-forensics-api)
21. [Analyze API](#21-analyze-api)
22. [Collect API](#22-collect-api)
23. [UI API](#23-ui-api)
24. [Health Check](#24-health-check)
25. [Error Codes](#25-error-codes)

---

## 1. Overview

### Base URL
```
http://localhost:8080/api
```

### Authentication
No built-in authentication. Access controlled via CORS middleware.

### Common Response Format

**Success Response (200/201):**
```json
{
  "message": "Success message",
  "data": { ... }
}
```

**Error Response (400/404/500):**
```json
{
  "error": "Error description",
  "code": "ErrorCode"
}
```

### Pagination
Query parameters:
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 100, max: 10000)

---

## 2. Events API

### GET /api/events
List events with pagination.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |

**Response (200):**
```json
{
  "events": [
    {
      "id": 1,
      "timestamp": "2026-01-01T00:00:00Z",
      "event_id": 4624,
      "level": "Info",
      "source": "Microsoft-Windows-Security-Auditing",
      "log_name": "Security",
      "computer": "DESKTOP-XXX",
      "user": "username",
      "message": "An account was successfully logged on",
      "ip_address": "192.168.1.1"
    }
  ],
  "total": 1000,
  "page": 1,
  "page_size": 100,
  "total_pages": 10
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/events?page=1&page_size=50
```

---

### GET /api/events/:id
Get a single event by ID.

**Path Parameters:**
- `id` - Event ID (integer)

**Response (200):**
```json
{
  "id": 1,
  "timestamp": "2026-01-01T00:00:00Z",
  "event_id": 4624,
  "level": "Info",
  "source": "Microsoft-Windows-Security-Auditing",
  "log_name": "Security",
  "computer": "DESKTOP-XXX",
  "user": "username",
  "message": "An account was successfully logged on",
  "ip_address": "192.168.1.1",
  "raw_xml": "<?xml version="1.0"..."
}
```

**Response (404):**
```json
{
  "error": "event not found",
  "code": "ErrCodeEventNotFound"
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/events/12345
```

---

### POST /api/events/search
Search events with filters.

**Request Body:**
```json
{
  "keywords": "login failed",
  "regex": false,
  "event_ids": [4625, 4624],
  "levels": [1, 2, 3],
  "log_names": ["Security", "System"],
  "sources": ["Microsoft-Windows-Security-Auditing"],
  "users": ["Administrator", "SYSTEM"],
  "computers": ["DC01", "FILE01"],
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z",
  "page": 1,
  "page_size": 100,
  "sort_by": "timestamp",
  "sort_order": "desc",
  "highlight": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| keywords | string | No | Search keywords |
| regex | bool | No | Enable regex matching |
| event_ids | []int32 | No | Filter by event IDs |
| levels | []int | No | Filter by levels (1=Critical, 2=Error, 3=Warning, 4=Info) |
| log_names | []string | No | Filter by log names |
| sources | []string | No | Filter by sources |
| users | []string | No | Filter by users |
| computers | []string | No | Filter by computers |
| start_time | string | No | Start time (RFC3339) |
| end_time | string | No | End time (RFC3339) |
| page | int | No | Page number |
| page_size | int | No | Page size (max 10000) |
| sort_by | string | No | Sort field (default: timestamp) |
| sort_order | string | No | Sort order: asc or desc |
| highlight | bool | No | Enable highlight |

**Response (200):**
```json
{
  "events": [...],
  "total": 500,
  "page": 1,
  "page_size": 100,
  "total_pages": 5,
  "query_time": 45
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/events/search   -H "Content-Type: application/json"   -d '{"keywords": "login", "levels": [4], "page_size": 50}'
```

---

### POST /api/events/export
Export events in various formats.

**Request Body:**
```json
{
  "format": "csv",
  "filters": {
    "event_ids": [4624, 4625],
    "levels": [1, 2],
    "log_names": ["Security"],
    "computers": ["DESKTOP-XXX"],
    "users": ["Administrator"],
    "start_time": "2026-04-01T00:00:00Z",
    "end_time": "2026-04-17T23:59:59Z",
    "keywords": "login",
    "limit": 10000
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| format | string | Yes | Export format: json, csv, excel |
| filters | object | No | Filter criteria |
| filters.limit | int | No | Max events to export (default: 10000, max: 100000) |

**Response:**
- For `csv`/`excel`: Returns file download
- For `json`: Returns JSON object

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/events/export   -H "Content-Type: application/json"   -d '{"format": "csv", "filters": {"limit": 1000}}'   -o events_export.csv
```

---

## 3. Alerts API

### GET /api/alerts
List alerts with pagination and filters.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |
| severity | string | "" | Filter by severity (critical, high, medium, low) |
| resolved | bool | null | Filter by resolved status |

**Response (200):**
```json
{
  "alerts": [
    {
      "id": 1,
      "rule_name": "BruteForceDetection",
      "severity": "high",
      "message": "Multiple failed login attempts detected",
      "count": 10,
      "first_seen": "2026-04-17T10:30:00Z",
      "last_seen": "2026-04-17T10:45:00Z",
      "resolved": false,
      "mitre_attack": ["T1110"]
    }
  ],
  "total": 50,
  "page": 1,
  "page_size": 100,
  "total_pages": 1
}
```

**Example Requests:**
```bash
# Get all alerts
curl http://localhost:8080/api/alerts

# Get critical alerts
curl http://localhost:8080/api/alerts?severity=critical

# Get unresolved alerts
curl http://localhost:8080/api/alerts?resolved=false
```

---

### GET /api/alerts/stats
Get alert statistics.

**Response (200):**
```json
{
  "total": 150,
  "by_severity": {
    "critical": 5,
    "high": 20,
    "medium": 45,
    "low": 80
  },
  "by_status": {
    "resolved": 100,
    "unresolved": 50
  },
  "by_rule": {
    "BruteForceDetection": 30,
    "SuspiciousProcessCreation": 25
  },
  "avg_per_day": 7.5
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/alerts/stats
```

---

### GET /api/alerts/trend
Get alert trend over time.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| days | int | 7 | Number of days to analyze (max 90) |

**Response (200):**
```json
{
  "trend": [
    {"date": "2026-04-11", "count": 5},
    {"date": "2026-04-12", "count": 8},
    {"date": "2026-04-13", "count": 3}
  ],
  "total": 50,
  "avg_per_day": 7.1
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/alerts/trend?days=30
```

---

### POST /api/alerts/run-analysis
Run alert analysis on all stored events.

**Response (200):**
```json
{
  "success": true,
  "alerts_created": 15,
  "events_analyzed": 5000,
  "rules_executed": 60,
  "duration": "2.5s",
  "errors": []
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/alerts/run-analysis
```

---

### GET /api/alerts/:id
Get a single alert by ID.

**Response (200):**
```json
{
  "id": 1,
  "rule_name": "BruteForceDetection",
  "severity": "high",
  "message": "Multiple failed login attempts detected",
  "count": 10,
  "first_seen": "2026-04-17T10:30:00Z",
  "last_seen": "2026-04-17T10:45:00Z",
  "resolved": false,
  "resolved_time": null,
  "notes": "",
  "mitre_attack": ["T1110"],
  "event_ids": [1, 2, 3, 4, 5]
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/alerts/12345
```

---

### POST /api/alerts/:id/resolve
Mark an alert as resolved.

**Request Body:**
```json
{
  "notes": "Confirmed as legitimate user behavior"
}
```

**Response (200):**
```json
{
  "message": "Alert resolved"
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/alerts/12345/resolve   -H "Content-Type: application/json"   -d '{"notes": "User confirmed legitimate"}'
```

---

### POST /api/alerts/:id/false-positive
Mark an alert as false positive.

**Request Body:**
```json
{
  "reason": "This is a regular maintenance task"
}
```

**Response (200):**
```json
{
  "message": "Alert marked as false positive"
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/alerts/12345/false-positive   -H "Content-Type: application/json"   -d '{"reason": "Known maintenance window"}'
```

---

### DELETE /api/alerts/:id
Delete an alert.

**Response (200):**
```json
{
  "message": "Alert deleted"
}
```

**Example Request:**
```bash
curl -X DELETE http://localhost:8080/api/alerts/12345
```

---

### POST /api/alerts/batch
Batch operation on multiple alerts.

**Request Body:**
```json
{
  "ids": [1, 2, 3, 4, 5],
  "action": "resolve",
  "notes": "Batch resolved",
  "reason": "Not applicable"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ids | []int64 | Yes | Alert IDs |
| action | string | Yes | Action: resolve, false-positive, delete |
| notes | string | No | Notes for resolve action |
| reason | string | No | Reason for false-positive action |

**Response (200):**
```json
{
  "message": "Batch action completed",
  "data": {
    "affected": 5,
    "failed": 0,
    "errors": []
  }
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/alerts/batch   -H "Content-Type: application/json"   -d '{"ids": [1, 2, 3], "action": "resolve", "notes": "Bulk resolved"}'
```

---

## 4. Timeline API

### GET /api/timeline
Get combined event and alert timeline.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | int | 200 | Max entries (max 1000) |
| offset | int | 0 | Offset for pagination |
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response (200):**
```json
{
  "entries": [
    {
      "id": 1,
      "timestamp": "2026-04-17T10:30:00Z",
      "type": "event",
      "event_id": 4624,
      "level": "Info",
      "source": "Microsoft-Windows-Security-Auditing",
      "message": "Account logon successful"
    },
    {
      "id": 2,
      "timestamp": "2026-04-17T10:31:00Z",
      "type": "alert",
      "alert_id": 1,
      "severity": "high",
      "rule_name": "BruteForceDetection",
      "message": "Multiple failed login attempts"
    }
  ],
  "total_count": 500,
  "event_count": 450,
  "alert_count": 50,
  "has_more": true,
  "next_offset": 200
}
```

**Example Request:**
```bash
curl "http://localhost:8080/api/timeline?limit=100&start_time=2026-04-01T00:00:00Z"
```

---

### GET /api/timeline/stats
Get timeline statistics.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response (200):**
```json
{
  "total_events": 5000,
  "total_alerts": 150,
  "by_level": {
    "Critical": 10,
    "Error": 50,
    "Warning": 200,
    "Info": 4740
  },
  "by_category": {
    "Authentication": 1000,
    "Process": 800,
    "Account": 600
  },
  "by_source": {
    "Microsoft-Windows-Security-Auditing": 3000,
    "Microsoft-Windows-Sysmon": 1500
  },
  "top_event_ids": {
    "4624": 500,
    "4625": 200,
    "4688": 150
  },
  "time_range": "48.5 hours",
  "attack_chains": 3
}
```

**Example Request:**
```bash
curl "http://localhost:8080/api/timeline/stats?start_time=2026-04-01T00:00:00Z"
```

---

### GET /api/timeline/chains
Get detected attack chains.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response (200):**
```json
{
  "chains": [
    {
      "id": "brute-force",
      "name": "Brute Force Attack",
      "technique": "T1110",
      "tactic": "Credential Access",
      "severity": "high",
      "event_count": 25,
      "start_time": "2026-04-17T10:00:00Z",
      "end_time": "2026-04-17T10:30:00Z"
    }
  ],
  "total": 1
}
```

**Example Request:**
```bash
curl "http://localhost:8080/api/timeline/chains"
```

---

### GET /api/timeline/export
Export timeline in various formats.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| format | string | "json" | Export format: json, csv, html |
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response:**
- For `csv`: Returns CSV file download
- For `html`: Returns HTML timeline visualization
- For `json`: Returns JSON object

**Example Request:**
```bash
curl "http://localhost:8080/api/timeline/export?format=html" -o timeline.html
```

---

### DELETE /api/timeline/alerts/:id
Delete an alert from timeline.

**Response (200):**
```json
{
  "message": "Alert deleted"
}
```

**Example Request:**
```bash
curl -X DELETE http://localhost:8080/api/timeline/alerts/12345
```

---

## 5. Import API

### POST /api/import/logs
Import log files.

**Request Body:**
```json
{
  "files": ["/path/to/security.evtx", "/path/to/system.etl"],
  "alert_on_import": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| files | []string | Yes | Array of file paths to import |
| alert_on_import | bool | No | Run alert analysis after import |

**Response (200):**
```json
{
  "success": true,
  "total_files": 2,
  "files_imported": 2,
  "files_failed": 0,
  "events_imported": 5000,
  "alert_on_import": true,
  "duration": "5.2s",
  "errors": []
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/import/logs   -H "Content-Type: application/json"   -d '{"files": ["/var/logs/security.evtx"], "alert_on_import": true}'
```

---

### GET /api/import/status
Get import status for a file.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | Yes | File path |

**Response (200):**
```json
{
  "file_path": "/var/logs/security.evtx",
  "status": "completed",
  "events_imported": 2500,
  "import_time": "2026-04-17T10:30:00Z",
  "import_id": "import_12345"
}
```

**Example Request:**
```bash
curl "http://localhost:8080/api/import/status?path=/var/logs/security.evtx"
```

---

## 6. Live Events API

### GET /api/live/events
Server-Sent Events stream for live event monitoring.

**Response:**
Server-Sent Events stream with event types:
- `connected` - Initial connection confirmation
- `event` - New event data
- `stats` - Current statistics

**Event Data Format:**
```json
{
  "type": "event",
  "data": {
    "id": 1,
    "timestamp": "2026-04-17T10:30:00Z",
    "event_id": 4624,
    "level": "Info",
    "source": "Microsoft-Windows-Security-Auditing",
    "log_name": "Security",
    "computer": "DESKTOP-XXX",
    "user": "username",
    "message": "An account was successfully logged on",
    "ip_address": "192.168.1.1"
  }
}
```

**Stats Format:**
```json
{
  "type": "stats",
  "data": {
    "total_events": 50000,
    "alerts": 150,
    "timestamp": "2026-04-17T10:30:00Z"
  }
}
```

**Example Request:**
```bash
curl -N http://localhost:8080/api/live/events
```

---

### GET /api/live/stats
Get live monitoring statistics.

**Response (200):**
```json
{
  "total_events": 50000,
  "events_per_sec": 2.5,
  "uptime": "6h15m30s",
  "timestamp": "2026-04-17T10:30:00Z"
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/live/stats
```

---

## 7. Reports API

### GET /api/reports
List generated reports.

**Response (200):**
```json
{
  "reports": [
    {
      "id": "report_security_summary_1234567890",
      "type": "security_summary",
      "format": "html",
      "title": "Daily Security Report",
      "description": "",
      "status": "completed",
      "generated_at": "2026-04-17T10:00:00Z",
      "completed_at": "2026-04-17T10:01:30Z",
      "file_path": "/tmp/winalog_reports/report_security_summary_1234567890.html",
      "file_size": 45678
    }
  ],
  "total": 1
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/reports
```

---

### POST /api/reports
Generate a new report.

**Request Body:**
```json
{
  "type": "security_summary",
  "format": "html",
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z",
  "include_raw": false,
  "include_ioc": true,
  "include_mitre": true,
  "title": "Weekly Security Report",
  "description": "Report for week of April 2026"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | Yes | Report type: security_summary, alert_report, event_report, timeline_report |
| format | string | Yes | Output format: html, json, pdf |
| start_time | string | No | Report start time (RFC3339) |
| end_time | string | No | Report end time (RFC3339) |
| include_raw | bool | No | Include raw events |
| include_ioc | bool | No | Include IOC summary |
| include_mitre | bool | No | Include MITRE ATT&CK distribution |
| title | string | No | Report title |
| description | string | No | Report description |

**Response (200):**
```json
{
  "id": "report_security_summary_1234567890",
  "type": "security_summary",
  "format": "html",
  "status": "generating",
  "generated_at": "2026-04-17T10:00:00Z",
  "message": "Report generation started",
  "download_url": "/api/reports/report_security_summary_1234567890/download"
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/reports   -H "Content-Type: application/json"   -d '{"type": "security_summary", "format": "html", "title": "April Report"}'
```

---

### GET /api/reports/:id
Get report details.

**Response (200):**
```json
{
  "id": "report_security_summary_1234567890",
  "type": "security_summary",
  "format": "html",
  "title": "Daily Security Report",
  "description": "",
  "status": "completed",
  "generated_at": "2026-04-17T10:00:00Z",
  "completed_at": "2026-04-17T10:01:30Z",
  "file_path": "/tmp/winalog_reports/report_security_summary_1234567890.html",
  "file_size": 45678
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/reports/report_security_summary_1234567890
```

---

### GET /api/reports/:id/download
Download a generated report file.

**Path Parameters:**
- `id` - Report ID

**Response:**
- Returns the report file download
- Content-Type varies by format (application/pdf, text/html, application/json)

**Response Codes:**
- `200` - Report ready for download
- `400` - Report not ready (still generating)
- `404` - Report not found

**Example Request:**
```bash
curl -O http://localhost:8080/api/reports/report_security_summary_1234567890/download
```

---

### GET /api/reports/export
Export data in various formats.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| format | string | "json" | Export format: json, csv, excel |

**Response:**
- Returns file download

**Example Request:**
```bash
curl "http://localhost:8080/api/reports/export?format=csv" -o export.csv
```

---

## Report Templates API

### GET /api/report-templates
List available report templates.

**Response (200):**
```json
{
  "templates": [
    {
      "name": "security_summary",
      "description": "Comprehensive security summary report"
    },
    {
      "name": "alert_details",
      "description": "Detailed alert analysis report"
    }
  ],
  "total": 2
}
```

---

### GET /api/report-templates/:name
Get template details.

**Response (200):**
```json
{
  "name": "security_summary",
  "content": "",
  "template": "<!DOCTYPE html>...",
  "is_custom": false
}
```

---

### POST /api/report-templates
Create a custom template.

**Request Body:**
```json
{
  "name": "custom_report",
  "content": "<!DOCTYPE html>...",
  "description": "My custom report template"
}
```

---

### PUT /api/report-templates/:name
Update a custom template.

---

### DELETE /api/report-templates/:name
Delete a custom template.

---

## 8. Dashboard API

### GET /api/dashboard/collection-stats
Get collection statistics for dashboard.

**Response (200):**
```json
{
  "total_events": 50000,
  "total_alerts": 150,
  "events_today": 500,
  "alerts_today": 5,
  "top_event_ids": [
    {"event_id": 4624, "count": 5000},
    {"event_id": 4625, "count": 2000}
  ],
  "events_by_level": {
    "Critical": 10,
    "Error": 100,
    "Warning": 500,
    "Info": 44390
  },
  "imports_today": 3
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/dashboard/collection-stats
```

---

## 9. Rules API

### GET /api/rules
List all detection rules.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |
| enabled | bool | null | Filter by enabled status |

**Response (200):**
```json
{
  "rules": [
    {
      "name": "BruteForceDetection",
      "description": "Detects brute force login attempts",
      "event_type": "single",
      "enabled": true,
      "severity": "high",
      "mitre_attack": ["T1110"],
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 60
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/rules
```

---

### GET /api/rules/:name
Get a single rule by name.

**Response (200):**
```json
{
  "name": "BruteForceDetection",
  "description": "Detects brute force login attempts",
  "event_type": "single",
  "enabled": true,
  "severity": "high",
  "mitre_attack": ["T1110"],
  "conditions": [...],
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

### POST /api/rules
Create a new rule.

**Request Body:**
```json
{
  "name": "CustomRule",
  "description": "Custom detection rule",
  "event_type": "single",
  "enabled": true,
  "severity": "medium",
  "mitre_attack": ["T1055"],
  "conditions": [...]
}
```

**Response (201):**
```json
{
  "message": "Rule created successfully"
}
```

---

### PUT /api/rules/:name
Update an existing rule.

**Request Body:**
```json
{
  "description": "Updated description",
  "enabled": false,
  "severity": "low",
  "conditions": [...]
}
```

---

### DELETE /api/rules/:name
Delete a rule.

**Response (200):**
```json
{
  "message": "Rule deleted successfully"
}
```

---

### POST /api/rules/:name/toggle
Enable or disable a rule.

**Response (200):**
```json
{
  "message": "Rule toggled successfully",
  "enabled": false
}
```

---

### POST /api/rules/validate
Validate a rule definition.

**Request Body:**
```json
{
  "name": "TestRule",
  "event_type": "correlation",
  "conditions": [...]
}
```

**Response (200):**
```json
{
  "valid": true,
  "errors": []
}
```

---

### POST /api/rules/import
Import rules from a file.

**Request Body:**
```json
{
  "file_path": "/path/to/rules.json"
}
```

---

### GET /api/rules/export
Export all rules to a file.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| format | string | "json" | Export format: json, yaml |

**Response:**
- Returns file download

---

### GET /api/rules/templates
List available rule templates.

**Response (200):**
```json
{
  "templates": [
    {
      "name": "powershell_detection",
      "description": "Detect PowerShell execution",
      "category": "execution"
    }
  ]
}
```

---

### GET /api/rules/templates/:name
Get a rule template by name.

**Response (200):**
```json
{
  "name": "powershell_detection",
  "description": "Detect PowerShell execution",
  "category": "execution",
  "template": {...}
}
```

---

### POST /api/rules/templates/:name/instantiate
Instantiate a rule from a template.

**Request Body:**
```json
{
  "name": "MyPowerShellRule",
  "parameters": {
    "event_id": 4103
  }
}
```

---

## 10. System API

### GET /api/system/info
Get system information.

**Response (200):**
```json
{
  "hostname": "DESKTOP-XXX",
  "os": "Windows 10 Pro",
  "os_version": "22H2",
  "architecture": "amd64",
  "uptime": "7d15h30m"
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/system/info
```

---

### GET /api/system/metrics
Get system metrics.

**Response (200):**
```json
{
  "cpu_usage": 25.5,
  "memory_usage": 60.2,
  "disk_usage": 45.8,
  "network_io": {
    "bytes_sent": 1024000,
    "bytes_recv": 2048000
  }
}
```

---

### GET /api/system/processes
List running processes.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |

**Response (200):**
```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "explorer.exe",
      "user": "Administrator",
      "cpu_percent": 2.5,
      "memory_mb": 120
    }
  ],
  "total": 150
}
```

---

### GET /api/system/network
Get network connections.

**Response (200):**
```json
{
  "connections": [
    {
      "protocol": "TCP",
      "local_addr": "192.168.1.100:8080",
      "remote_addr": "192.168.1.200:443",
      "state": "ESTABLISHED"
    }
  ]
}
```

---

### GET /api/system/env
Get environment variables.

**Response (200):**
```json
{
  "variables": [
    {"name": "PATH", "value": "C:\\Windows\\..."},
    {"name": "TEMP", "value": "C:\\Users\\...\\AppData\\Local\\Temp"}
  ]
}
```

---

### GET /api/system/dlls
Get loaded DLLs.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| process_id | int | null | Filter by process ID |

**Response (200):**
```json
{
  "dlls": [
    {
      "name": "ntdll.dll",
      "path": "C:\\Windows\\System32\\ntdll.dll",
      "size": 1929472
    }
  ]
}
```

---

### GET /api/system/drivers
Get loaded kernel drivers.

**Response (200):**
```json
{
  "drivers": [
    {
      "name": "ntfs.sys",
      "path": "C:\\Windows\\System32\\drivers\\ntfs.sys",
      "size": 1824768
    }
  ]
}
```

---

### GET /api/system/users
Get local users.

**Response (200):**
```json
{
  "users": [
    {
      "username": "Administrator",
      "enabled": true,
      "last_logon": "2026-04-17T10:00:00Z"
    }
  ]
}
```

---

### GET /api/system/registry
Get registry statistics.

**Response (200):**
```json
{
  "hives": [
    {"name": "HKEY_LOCAL_MACHINE", "keys": 15230},
    {"name": "HKEY_CURRENT_USER", "keys": 3420}
  ]
}
```

---

### GET /api/system/tasks
Get scheduled tasks.

**Response (200):**
```json
{
  "tasks": [
    {
      "name": "\\Microsoft\\Windows\\Something",
      "state": "Ready",
      "last_run": "2026-04-16T08:00:00Z",
      "next_run": "2026-04-18T08:00:00Z"
    }
  ]
}
```

---

### GET /api/system/process/:pid/dlls
Get DLLs for a specific process.

**Path Parameters:**
- `pid` - Process ID

**Response (200):**
```json
{
  "process_id": 1234,
  "process_name": "explorer.exe",
  "dlls": [
    {
      "name": "user32.dll",
      "path": "C:\\Windows\\System32\\user32.dll",
      "size": 834560
    }
  ]
}
```

---

## 11. Suppress API

### GET /api/suppress
List all suppression rules.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |

**Response (200):**
```json
{
  "suppressions": [
    {
      "id": 1,
      "name": "SuppressKnownGood",
      "description": "Suppress known good behavior",
      "enabled": true,
      "filter": {"event_ids": [4624]},
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 5
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/suppress
```

---

### POST /api/suppress
Create a new suppression rule.

**Request Body:**
```json
{
  "name": "SuppressKnownGood",
  "description": "Suppress known good behavior",
  "enabled": true,
  "filter": {
    "event_ids": [4624],
    "users": ["KnownUser"]
  }
}
```

**Response (201):**
```json
{
  "message": "Suppression rule created",
  "id": 1
}
```

---

### GET /api/suppress/:id
Get a suppression rule by ID.

**Response (200):**
```json
{
  "id": 1,
  "name": "SuppressKnownGood",
  "description": "Suppress known good behavior",
  "enabled": true,
  "filter": {"event_ids": [4624]},
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

### PUT /api/suppress/:id
Update a suppression rule.

**Request Body:**
```json
{
  "name": "UpdatedSuppression",
  "enabled": false,
  "filter": {"event_ids": [4624, 4625]}
}
```

---

### DELETE /api/suppress/:id
Delete a suppression rule.

**Response (200):**
```json
{
  "message": "Suppression rule deleted"
}
```

---

### POST /api/suppress/:id/toggle
Enable or disable a suppression rule.

**Response (200):**
```json
{
  "message": "Suppression rule toggled",
  "enabled": false
}
```

---

## 12. UEBA API

### POST /api/ueba/analyze
Analyze user behavior.

**Request Body:**
```json
{
  "username": "Administrator",
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z"
}
```

**Response (200):**
```json
{
  "username": "Administrator",
  "baseline": {
    "typical_hours": ["9:00-18:00"],
    "typical_locations": ["192.168.1.0/24"],
    "typical_commands": ["explorer.exe", "cmd.exe"]
  },
  "anomalies": [
    {
      "type": "unusual_time",
      "severity": "medium",
      "description": "Activity outside typical hours"
    }
  ],
  "risk_score": 45
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/ueba/analyze \
  -H "Content-Type: application/json" \
  -d '{"username": "Administrator"}'
```

---

### GET /api/ueba/profiles
Get all user behavior profiles.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |

**Response (200):**
```json
{
  "profiles": [
    {
      "username": "Administrator",
      "risk_score": 45,
      "baseline_established": true,
      "last_analyzed": "2026-04-17T10:00:00Z"
    }
  ],
  "total": 10
}
```

---

### GET /api/ueba/anomaly/:type
Get anomalies of a specific type.

**Path Parameters:**
- `type` - Anomaly type (unusual_time, unusual_location, unusual_command, unusual_process)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |
| severity | string | "" | Filter by severity |

**Response (200):**
```json
{
  "anomalies": [
    {
      "id": 1,
      "username": "Administrator",
      "type": "unusual_time",
      "severity": "medium",
      "timestamp": "2026-04-17T02:00:00Z",
      "description": "Activity at 2:00 AM"
    }
  ]
}
```

---

## 13. Correlation API

### POST /api/correlation/analyze
Run correlation analysis.

**Request Body:**
```json
{
  "rules": ["BruteForceDetection", "SuspiciousProcessCreation"],
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z",
  "window": "5m"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| rules | []string | No | Specific rules to analyze |
| start_time | string | No | Start time (RFC3339) |
| end_time | string | No | End time (RFC3339) |
| window | string | No | Correlation window (default: 5m) |

**Response (200):**
```json
{
  "success": true,
  "correlations_found": 3,
  "chains": [
    {
      "id": "chain_1",
      "name": "Credential Access Chain",
      "events": [4624, 4625, 4672],
      "severity": "high"
    }
  ],
  "duration": "1.2s"
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/correlation/analyze \
  -H "Content-Type: application/json" \
  -d '{"window": "10m"}'
```

---

## 14. Multi API

### POST /api/multi/analyze
Analyze multiple event sources simultaneously.

**Request Body:**
```json
{
  "sources": ["security", "system", "sysmon"],
  "query": "event_id:4624 OR event_id:4625",
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z"
}
```

**Response (200):**
```json
{
  "results": {
    "security": {"count": 100, "events": [...]},
    "system": {"count": 50, "events": [...]},
    "sysmon": {"count": 25, "events": [...]}
  },
  "total": 175
}
```

---

### GET /api/multi/lateral
Detect lateral movement across multiple sources.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response (200):**
```json
{
  "movements": [
    {
      "source_host": "WORKSTATION1",
      "dest_host": "DC01",
      "username": "Administrator",
      "timestamp": "2026-04-17T10:30:00Z",
      "method": "WMI"
    }
  ]
}
```

---

## 15. Query API

### POST /api/query/execute
Execute a raw query.

**Request Body:**
```json
{
  "sql": "SELECT * FROM events WHERE event_id = 4624 LIMIT 100",
  "limit": 100,
  "offset": 0
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| sql | string | Yes | SQL query (SELECT, PRAGMA, EXPLAIN, WITH only) |
| limit | int | No | Max rows to return (default: 100, max: 1000) |
| offset | int | No | Offset for pagination |

**Response (200):**
```json
{
  "columns": ["id", "timestamp", "event_id", "level", "message"],
  "rows": [
    [1, "2026-04-17T10:00:00Z", 4624, "Info", "An account was successfully logged on"]
  ],
  "count": 1,
  "total": 1
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/query/execute \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT COUNT(*) FROM events"}'
```

---

## 16. Monitor API

Real-time system monitoring API for process, network, and DNS monitoring.

### GET /api/monitor/stats
Get monitoring statistics.

**Response (200):**
```json
{
  "stats": {
    "running": true,
    "process_count": 150,
    "network_connections": 45,
    "dns_queries": 12,
    "start_time": "2026-04-17T10:00:00Z"
  }
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/monitor/stats
```

---

### GET /api/monitor/events
List monitoring events with filters.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| type | string | "" | Event type (process, network, dns) |
| severity | string | "" | Severity (info, low, medium, high, critical) |
| limit | int | 50 | Max events to return |
| offset | int | 0 | Offset for pagination |
| start_time | string | "" | Start time (RFC3339) |
| end_time | string | "" | End time (RFC3339) |

**Response (200):**
```json
{
  "events": [
    {
      "id": "process-1234-1609456000000000000",
      "type": "process",
      "timestamp": "2026-04-17T10:00:00Z",
      "severity": "info",
      "data": {
        "pid": 1234,
        "process_name": "notepad.exe",
        "action": "created"
      }
    }
  ],
  "total": 100,
  "limit": 50,
  "offset": 0
}
```

**Example Request:**
```bash
curl "http://localhost:8080/api/monitor/events?type=process&limit=50"
```

---

### POST /api/monitor/config
Update monitoring configuration.

**Request Body:**
```json
{
  "process_monitoring": {
    "enabled": true,
    "interval_ms": 5000
  },
  "network_monitoring": {
    "enabled": true,
    "interval_ms": 10000
  },
  "dns_monitoring": {
    "enabled": false,
    "interval_ms": 30000
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| process_monitoring.enabled | bool | No | Enable process monitoring |
| process_monitoring.interval_ms | int | No | Polling interval in milliseconds |
| network_monitoring.enabled | bool | No | Enable network monitoring |
| network_monitoring.interval_ms | int | No | Polling interval in milliseconds |
| dns_monitoring.enabled | bool | No | Enable DNS monitoring |
| dns_monitoring.interval_ms | int | No | Polling interval in milliseconds |

**Response (200):**
```json
{
  "message": "Configuration updated successfully",
  "stats": {
    "running": true,
    "process_count": 150,
    "network_connections": 45,
    "dns_queries": 12
  }
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/monitor/config \
  -H "Content-Type: application/json" \
  -d '{"process_monitoring": {"enabled": true, "interval_ms": 5000}}'
```

---

### POST /api/monitor/action
Start or stop monitoring.

**Request Body:**
```json
{
  "action": "start"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | Action: "start" or "stop" |

**Response (200):**
```json
{
  "message": "Monitor start successfully",
  "stats": {
    "running": true,
    "process_count": 150,
    "network_connections": 45
  }
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/monitor/action \
  -H "Content-Type: application/json" \
  -d '{"action": "start"}'
```

---

### GET /api/monitor/events/stream
Server-Sent Events stream for real-time monitoring events.

**Response:**
Server-Sent Events stream with monitoring events.

**Event Format:**
```json
{
  "id": "process-1234-1609456000000000000",
  "type": "process",
  "timestamp": "2026-04-17T10:00:00Z",
  "severity": "info",
  "data": {
    "pid": 1234,
    "process_name": "notepad.exe",
    "action": "created"
  }
}
```

**Example Request:**
```bash
curl -N http://localhost:8080/api/monitor/events/stream
```

---

## 17. Policy API

### GET /api/policy-templates
List available policy templates.

**Response (200):**
```json
{
  "templates": [
    {
      "name": "baseline_policy",
      "description": "Baseline security policy",
      "rules": ["rule1", "rule2"]
    }
  ]
}
```

---

### GET /api/policy-templates/:name
Get a policy template by name.

**Response (200):**
```json
{
  "name": "baseline_policy",
  "description": "Baseline security policy",
  "rules": ["rule1", "rule2"],
  "settings": {...}
}
```

---

### POST /api/policy-templates
Create a policy template.

**Request Body:**
```json
{
  "name": "custom_policy",
  "description": "Custom security policy",
  "rules": ["rule1", "rule2"],
  "settings": {...}
}
```

**Response (201):**
```json
{
  "message": "Policy template created"
}
```

---

### POST /api/policy-templates/apply
Apply a policy template to current configuration.

**Request Body:**
```json
{
  "template_name": "baseline_policy",
  "targets": ["host1", "host2"]
}
```

**Response (200):**
```json
{
  "success": true,
  "applied_to": 2,
  "results": [...]
}
```

---

### DELETE /api/policy-templates/:name
Delete a policy template.

**Response (200):**
```json
{
  "message": "Policy template deleted"
}
```

---

### GET /api/policy-instances
List applied policy instances.

**Response (200):**
```json
{
  "instances": [
    {
      "key": "host1_baseline",
      "template": "baseline_policy",
      "target": "host1",
      "applied_at": "2026-04-01T00:00:00Z",
      "status": "active"
    }
  ]
}
```

---

### DELETE /api/policy-instances/:key
Remove a policy instance.

**Path Parameters:**
- `key` - Instance key (format: target_template)

**Response (200):**
```json
{
  "message": "Policy instance removed"
}
```

---

### POST /api/policies
Create or update a policy.

**Request Body:**
```json
{
  "name": "my_policy",
  "rules": [...],
  "settings": {...}
}
```

---

### DELETE /api/policies/:name
Delete a policy.

**Response (200):**
```json
{
  "message": "Policy deleted"
}
```

---

## 18. Settings API

### GET /api/settings
Get current application settings.

**Response (200):**
```json
{
  "settings": {
    "alert_retention_days": 90,
    "event_retention_days": 365,
    "log_level": "info",
    "enable_telemetry": false
  }
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/settings
```

---

### POST /api/settings
Update application settings.

**Request Body:**
```json
{
  "alert_retention_days": 60,
  "log_level": "debug"
}
```

**Response (200):**
```json
{
  "message": "Settings updated successfully"
}
```

---

### POST /api/settings/reset
Reset settings to defaults.

**Response (200):**
```json
{
  "message": "Settings reset to defaults"
}
```

---

## 19. Persistence API

### GET /api/persistence/detect
Detect persistence mechanisms on the system.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| category | string | "" | Filter by category (runkey, service, scheduled_task, etc.) |

**Response (200):**
```json
{
  "persistence_mechanisms": [
    {
      "id": 1,
      "type": "runkey",
      "name": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "data": "C:\\malware.exe",
      "detected_at": "2026-04-17T10:00:00Z"
    }
  ],
  "total": 5
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/persistence/detect
```

---

### GET /api/persistence/detect/stream
Stream persistence detection results (SSE).

**Response:**
Server-Sent Events stream with persistence detection results.

---

### GET /api/persistence/categories
Get all persistence categories.

**Response (200):**
```json
{
  "categories": [
    "runkey",
    "service",
    "scheduled_task",
    "wmi",
    "registry",
    "dll_hijacking"
  ]
}
```

---

### GET /api/persistence/techniques
Get MITRE ATT&CK persistence techniques.

**Response (200):**
```json
{
  "techniques": [
    {
      "id": "T1547",
      "name": "Boot or Logon Autostart Execution",
      "subtechniques": ["T1547.001", "T1547.002"]
    }
  ]
}
```

---

## 20. Forensics API

### POST /api/forensics/hash
Calculate file hashes.

**Request Body:**
```json
{
  "paths": ["C:\\Windows\\System32\\calc.exe"],
  "algorithms": ["md5", "sha256"]
}
```

**Response (200):**
```json
{
  "results": [
    {
      "path": "C:\\Windows\\System32\\calc.exe",
      "md5": "a1b2c3d4e5f6...",
      "sha256": "1234567890abcdef..."
    }
  ]
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8080/api/forensics/hash \
  -H "Content-Type: application/json" \
  -d '{"paths": ["/path/to/file.exe"]}'
```

---

### GET /api/forensics/verify-hash
Verify a file against known malicious hashes.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| hash | string | Yes | File hash to verify |
| algorithm | string | No | Hash algorithm (default: sha256) |

**Response (200):**
```json
{
  "hash": "a1b2c3d4e5f6...",
  "known_malicious": false,
  "sources": ["VirusTotal: 0/60", "HybridAnalysis: clean"]
}
```

---

### GET /api/forensics/signature
Get digital signature information for a file.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | Yes | File path |

**Response (200):**
```json
{
  "path": "C:\\Windows\\System32\\calc.exe",
  "signed": true,
  "signature": {
    "subject": "Microsoft Windows",
    "issuer": "Microsoft Windows Production PCA",
    "thumbprint": "a1b2c3d4e5f6..."
  }
}
```

---

### GET /api/forensics/is-signed
Check if a file is digitally signed.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | Yes | File path |

**Response (200):**
```json
{
  "path": "C:\\Windows\\System32\\calc.exe",
  "signed": true,
  "valid": true
}
```

---

### POST /api/forensics/collect
Collect forensic data.

**Request Body:**
```json
{
  "targets": ["processes", "registry", "network"],
  "options": {
    "include_hidden": true,
    "deep_scan": false
  }
}
```

**Response (200):**
```json
{
  "collection_id": "coll_12345",
  "status": "completed",
  "data_size": 1024000,
  "collected_at": "2026-04-17T10:00:00Z"
}
```

---

### GET /api/forensics/evidence
List collected evidence.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 100 | Items per page |

**Response (200):**
```json
{
  "evidence": [
    {
      "id": "coll_12345",
      "type": "process_dump",
      "size": 1024000,
      "collected_at": "2026-04-17T10:00:00Z",
      "hash": "a1b2c3d4..."
    }
  ],
  "total": 5
}
```

---

### GET /api/forensics/evidence/:id
Get evidence details.

**Response (200):**
```json
{
  "id": "coll_12345",
  "type": "process_dump",
  "size": 1024000,
  "collected_at": "2026-04-17T10:00:00Z",
  "hash": "a1b2c3d4...",
  "metadata": {...}
}
```

---

### POST /api/forensics/manifest
Generate a forensic manifest.

**Request Body:**
```json
{
  "paths": ["C:\\Windows\\System32"],
  "include_hashes": true
}
```

**Response (200):**
```json
{
  "manifest_id": "manifest_12345",
  "files": [
    {
      "path": "C:\\Windows\\System32\\calc.exe",
      "size": 18500,
      "sha256": "a1b2c3d4..."
    }
  ],
  "generated_at": "2026-04-17T10:00:00Z"
}
```

---

### GET /api/forensics/chain-of-custody
Get chain of custody records.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| evidence_id | string | "" | Filter by evidence ID |

**Response (200):**
```json
{
  "records": [
    {
      "id": 1,
      "evidence_id": "coll_12345",
      "action": "collected",
      "user": "admin",
      "timestamp": "2026-04-17T10:00:00Z",
      "details": "Initial collection"
    }
  ]
}
```

---

### GET /api/forensics/memory-dump
Get memory dump information.

**Response (200):**
```json
{
  "dumps": [
    {
      "id": "mem_12345",
      "pid": 1234,
      "process_name": "explorer.exe",
      "size": 524288000,
      "created_at": "2026-04-17T10:00:00Z"
    }
  ]
}
```

---

## 21. Analyze API

### POST /api/analyze/:type
Run specific analysis by type.

**Path Parameters:**
- `type` - Analysis type (hash, memory, network, file, registry)

**Request Body:**
```json
{
  "target": "C:\\Windows\\System32\\calc.exe",
  "options": {
    "deep_scan": true
  }
}
```

**Response (200):**
```json
{
  "type": "hash",
  "target": "C:\\Windows\\System32\\calc.exe",
  "results": {
    "sha256": "a1b2c3d4...",
    "malicious": false
  },
  "duration": "1.5s"
}
```

---

### GET /api/analyzers
List available analyzers.

**Response (200):**
```json
{
  "analyzers": [
    {
      "type": "hash",
      "name": "Hash Analyzer",
      "description": "Analyze file hashes",
      "enabled": true
    },
    {
      "type": "memory",
      "name": "Memory Analyzer",
      "description": "Analyze memory dumps",
      "enabled": true
    }
  ]
}
```

---

### GET /api/analyzers/:type
Get analyzer details.

**Response (200):**
```json
{
  "type": "hash",
  "name": "Hash Analyzer",
  "description": "Analyze file hashes",
  "enabled": true,
  "capabilities": ["md5", "sha1", "sha256", "imphash"]
}
```

---

## 22. Collect API

### POST /api/collect
Start a new collection task.

**Request Body:**
```json
{
  "sources": ["security", "system", "sysmon"],
  "start_time": "2026-04-01T00:00:00Z",
  "end_time": "2026-04-17T23:59:59Z",
  "filters": {
    "event_ids": [4624, 4625]
  }
}
```

**Response (201):**
```json
{
  "task_id": "coll_task_12345",
  "status": "started",
  "estimated_events": 5000
}
```

---

### POST /api/collect/import
Import collected data.

**Request Body:**
```json
{
  "file_path": "/path/to/collection.zip",
  "source_type": "evtx"
}
```

**Response (200):**
```json
{
  "success": true,
  "events_imported": 5000,
  "task_id": "import_12345"
}
```

---

### GET /api/collect/status
Get collection task status.

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| task_id | string | Yes | Collection task ID |

**Response (200):**
```json
{
  "task_id": "coll_task_12345",
  "status": "running",
  "progress": 45,
  "events_collected": 2250,
  "start_time": "2026-04-17T10:00:00Z"
}
```

---

## 23. UI API

### GET /api/ui/dashboard
Get dashboard data for UI.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| refresh | int | 30 | Auto-refresh interval (seconds) |

**Response (200):**
```json
{
  "stats": {
    "total_events": 50000,
    "total_alerts": 150,
    "critical_alerts": 5
  },
  "recent_alerts": [...],
  "top_events": [...],
  "timeline": {...}
}
```

---

### GET /api/ui/alerts/groups
Get grouped alerts for UI.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| group_by | string | "rule" | Grouping field (rule, severity, time) |
| page | int | 1 | Page number |
| page_size | int | 50 | Items per page |

**Response (200):**
```json
{
  "groups": [
    {
      "key": "BruteForceDetection",
      "count": 25,
      "alerts": [...]
    }
  ]
}
```

---

### GET /api/ui/metrics
Get metrics for UI.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| period | string | "24h" | Time period (1h, 24h, 7d, 30d) |

**Response (200):**
```json
{
  "events_over_time": [
    {"timestamp": "2026-04-17T10:00:00Z", "count": 500}
  ],
  "alerts_over_time": [
    {"timestamp": "2026-04-17T10:00:00Z", "count": 5}
  ],
  "top_event_ids": [
    {"event_id": 4624, "count": 5000}
  ]
}
```

---

### GET /api/ui/events/distribution
Get event distribution for UI.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| field | string | "level" | Distribution field (level, source, log_name) |
| limit | int | 10 | Max results |

**Response (200):**
```json
{
  "distribution": [
    {"value": "Info", "count": 40000},
    {"value": "Warning", "count": 5000},
    {"value": "Error", "count": 1000}
  ]
}
```

---

## 24. Health Check

### GET /api/health
Health check endpoint.

**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": "2026-04-17T10:00:00Z",
  "components": {
    "database": "healthy",
    "storage": "healthy",
    "collectors": "healthy"
  }
}
```

**Example Request:**
```bash
curl http://localhost:8080/api/health
```

---

## 25. Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| ErrCodeInvalidRequest | 400 | Invalid request parameters |
| ErrCodeInternalError | 500 | Internal server error |
| ErrCodeEventNotFound | 404 | Event not found |
| ErrCodeAlertNotFound | 404 | Alert not found |
| ErrCodeInvalidQuery | 400 | Invalid SQL query |
| ErrCodeAlertAlreadyResolved | 400 | Alert already resolved |

---

## Appendix A: Event Levels

| Level | Value | Description |
|-------|-------|-------------|
| Critical | 1 | Critical event |
| Error | 2 | Error event |
| Warning | 3 | Warning event |
| Info | 4 | Information event |
| Verbose | 5 | Verbose event |

---

## Appendix B: Report Types

| Type | Aliases | Description |
|------|---------|-------------|
| security_summary | security | Comprehensive security summary with executive overview, threat landscape, and recommendations |
| alert_report | alert | Alert details report with MITRE ATT&CK mapping |
| event_report | event | Raw events report with filtering and statistics |
| timeline_report | timeline | Timeline visualization of security events and alerts |

**Report Response Structure:**

Each report type returns a JSON structure with the following components:

```json
{
  "generated_at": "2026-04-17T10:00:00Z",
  "title": "Report Title",
  "time_range": {
    "start": "2026-04-01T00:00:00Z",
    "end": "2026-04-17T23:59:59Z"
  },
  "summary": {
    "total_events": 5000,
    "total_alerts": 150,
    "critical_events": 10,
    "high_alerts": 45
  },
  "stats": { ... },
  "top_alerts": [ ... ],
  "top_events": [ ... ],
  "event_distribution": { ... },
  "login_stats": { ... },
  "iocs": { ... },
  "mitre_distribution": { ... },
  "executive_summary": { ... },
  "timeline_analysis": { ... },
  "threat_landscape": { ... },
  "recommendations": [ ... ],
  "attack_patterns": [ ... ],
  "compliance_status": { ... },
  "timeline": [ ... ]
}
```

**Note:** Not all fields are present in every report type. Each report type includes different subsets:
- `security_summary`: All fields
- `alert_report`: summary, top_alerts, mitre_distribution
- `event_report`: summary, stats, top_events
- `timeline_report`: summary, stats, timeline, timeline_analysis

---

## Appendix C: Example Use Cases

### Use Case 1: Search for Failed Logins

```bash
# Find all failed login events (EventID 4625)
curl -X POST http://localhost:8080/api/events/search \
  -H "Content-Type: application/json" \
  -d '{
    "event_ids": [4625],
    "levels": [2],
    "start_time": "2026-04-01T00:00:00Z",
    "page_size": 100
  }'
```

### Use Case 2: Monitor Real-time Events

```bash
# Stream live events
curl -N http://localhost:8080/api/live/events

# Get live stats
curl http://localhost:8080/api/live/stats
```

### Use Case 3: Generate and Download Report

```bash
# 1. Generate report
REPORT_ID=$(curl -s -X POST http://localhost:8080/api/reports \
  -H "Content-Type: application/json" \
  -d '{"type": "security_summary", "format": "html"}' | jq -r '.id')

# 2. Wait for completion
sleep 5

# 3. Get report details
curl http://localhost:8080/api/reports/$REPORT_ID
```

### Use Case 4: Batch Resolve Alerts

```bash
# Resolve multiple alerts
curl -X POST http://localhost:8080/api/alerts/batch \
  -H "Content-Type: application/json" \
  -d '{
    "ids": [1, 2, 3, 4, 5],
    "action": "resolve",
    "notes": "Resolved after investigation"
  }'
```

---

**Document Version**: v2.5.0  
**Last Updated**: 2026-04-17
