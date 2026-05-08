# Winalog Analysis Modules Enhancement Specification

**Date:** 2026-05-08
**Status:** Proposed
**Modules:** Correlation Analysis, Multi-Machine Analysis, UEBA Analysis

## 1. Overview

This specification details the roadmap for upgrading the three core analysis modules from "Demo-level" prototypes to "Production-ready" features. The primary goals are:
1. **Reliability:** Eliminate state loss (UEBA baselines) upon restart.
2. **Completeness:** Enrich machine data using a hybrid asset management approach.
3. **Usability:** Fix broken visualizations (Topology Graph) and enable deep-dive investigations (Correlation Chains).

---

## 2. Architecture: Hybrid Asset Management (Multi-Machine Core)

The Multi-Machine Analysis module relies on accurate machine context. We will implement a **Hybrid Approach** combining **Manual Configuration** (Primary) and **Log Discovery** (Auxiliary).

### 2.1. Asset Management Logic

1.  **Master Data (Manual Import):**
    *   Users import a CSV/Excel "Asset List" containing `Hostname`, `IP`, `Role` (DC/Server/Workstation), `OS`.
    *   This data is the "Source of Truth" for analysis.
2.  **Auto-Discovery (Log Parsing):**
    *   When logs are imported, if a machine name exists in logs but NOT in the asset list, the system auto-creates a record.
    *   These records are marked with `source: "log_discovery"` and `role: "unknown"`.
    *   Users can later review and update these "Unknown" entries.
3.  **Enrichment Strategy:**
    *   During analysis, the engine queries `machine_assets`.
    *   If logs contain IP info (e.g., Event 4624), update the `last_seen` and potentially fill empty IP fields in the asset record.

---

## 3. Database Schema Changes

### 3.1. New Table: `ueba_baselines` (P0 - Critical)
Solves the issue where UEBA loses learned behavior on restart.

```sql
CREATE TABLE IF NOT EXISTS ueba_baselines (
    user TEXT PRIMARY KEY,
    baseline_json TEXT NOT NULL, -- JSON serialized UserBaseline
    learned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    events_count INTEGER DEFAULT 0
);
```

### 3.2. New Table: `machine_assets` (P0 - Critical)
Stores the asset inventory for Multi-Machine Analysis.

```sql
CREATE TABLE IF NOT EXISTS machine_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    domain TEXT,
    role TEXT DEFAULT 'workstation', -- dc, server, workstation, unknown
    os_version TEXT,
    importance TEXT DEFAULT 'medium', -- high, medium, low
    source TEXT DEFAULT 'manual',     -- manual, log_discovery
    last_seen DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. Module Implementation Plans

### 4.1. UEBA Analysis (User & Entity Behavior Analytics)

#### Problem
Baselines are stored in memory (`map[string]*ueba.UserBaseline`). Service restart resets the "Normal" behavior model, causing false positives immediately after reboot.

#### Implementation Plan
1.  **Engine Initialization (`NewEngine`):**
    *   Query `ueba_baselines` table.
    *   Deserialize JSON into `UserBaseline` structs.
    *   Pre-populate the in-memory map.
2.  **Persistence Strategy:**
    *   **Auto-Save:** Implement a background ticker (every 5 mins) that flushes dirty baselines to DB.
    *   **Learn Endpoint:** Modify `/api/ueba/baseline/learn` to immediately persist to DB upon completion.
    *   **Upsert Logic:** `INSERT ... ON CONFLICT(user) DO UPDATE SET baseline_json=excluded.baseline_json`.
3.  **False Positive Suppression (P2):**
    *   Add a UI button "Mark as Normal".
    *   Store in a new `ueba_suppressions` table.
    *   Filter out matches during detection.

### 4.2. Multi-Machine Analysis

#### Problem 1: Missing Context
Machines only show Hostname. IP, Role, OS are empty because log parsing is unreliable and incomplete.

#### Implementation Plan (Hybrid Approach)
1.  **Asset Import API:**
    *   `POST /api/multi/assets/import`: Accepts CSV/JSON.
    *   Parses and performs Bulk Upsert into `machine_assets`.
2.  **Log Import Hook:**
    *   Modify `storage/events.go` (`updateMachineContexts`).
    *   Check if `computer` exists in `machine_assets`.
    *   If No: `INSERT INTO machine_assets (hostname, source) VALUES (computer, 'log_discovery')`.
3.  **Analysis Enrichment:**
    *   Modify `detectLateralMovement`: Instead of just returning raw strings, join with `machine_assets` to return full `MachineInfo` objects (IP, Role).

#### Problem 2: Broken Topology Graph
Frontend receives nodes and edges but only renders nodes.

#### Implementation Plan
1.  **Data Structure Update:**
    *   Ensure API `/api/multi/analyze` returns a clean `edges` array: `[{source: "HostA", target: "HostB", count: 5, severity: "high"}]`.
2.  **Frontend Rendering:**
    *   Use **SVG Overlay** or **Canvas** on top of the node container.
    *   Calculate center points of rendered nodes.
    *   Draw Bezier curves connecting Source to Target.
    *   Color code lines by severity (Red for High Risk).

### 4.3. Correlation Analysis

#### Problem 1: Shallow Export
Exports only contain rule summaries, missing the actual evidence (Event Logs).

#### Implementation Plan
1.  **Deep Export (JSON/CSV):**
    *   Modify `/api/correlation/export`.
    *   Include `evidence` array in JSON output.
    *   In CSV, append evidence rows immediately following the summary row (indented or grouped).

#### Problem 2: Missing Attack Chain Visualization
Frontend shows "5 Events Detected" but not *which* events or their sequence.

#### Implementation Plan
1.  **API Response Update:**
    *   Add `chain: []ChainEvent` to the response payload.
    *   `ChainEvent` includes `event_id`, `timestamp`, `message_preview`, `tactic`.
2.  **Frontend UI (Timeline View):**
    *   **Accordion Card:** When a result card is clicked, expand to show a vertical timeline.
    *   **Step Indicators:** Visualize the MITRE ATT&CK flow (e.g., 🎯 Initial Access ➔ 🔑 Credential Access ➔ 🔄 Lateral Movement).
    *   **Drill-Down Button:** "View Logs" button that redirects to `/events` with pre-filled filters (e.g., `EventID in [...]`).

---

## 5. Phased Execution Roadmap

| Phase | Scope | Tasks | Estimate |
| :--- | :--- | :--- | :--- |
| **P0: Foundation** | DB & Persistence | 1. Create `ueba_baselines` & `machine_assets` tables.<br>2. Implement UEBA Load/Save logic.<br>3. Implement Asset Import API. | 3 Days |
| **P1: Logic & API** | Enrichment & Export | 1. Hook log import to auto-discover machines.<br>2. Update Multi-Machine analysis to use Asset DB.<br>3. Implement Deep Export for Correlation. | 3 Days |
| **P2: UI/UX** | Visual Fixes | 1. Fix Topology Graph edges (SVG/Canvas).<br>2. Implement Correlation Attack Chain Timeline.<br>3. Add Asset Management UI Page. | 4 Days |

---

## 6. Risk Management

*   **Risk:** SQLite Locking during Bulk Import.
    *   **Mitigation:** Use `BEGIN IMMEDIATE TRANSACTION` for asset imports and baseline flushes.
*   **Risk:** Memory OOM on Large UEBA Baselines.
    *   **Mitigation:** Implement a TTL or pruning strategy (e.g., discard behaviors older than 90 days).
*   **Risk:** Topology Graph Performance.
    *   **Mitigation:** Limit graph rendering to top 50 most active machines to prevent browser lag.
