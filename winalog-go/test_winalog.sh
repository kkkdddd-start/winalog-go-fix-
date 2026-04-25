#!/bin/bash

# WinLogAnalyzer-Go Test Script (Linux)
# Tests all API endpoints and CLI commands

set -e

BASE_URL="http://localhost:8080"
WINALOG_PATH="./winalog_linux"
OUTPUT_DIR="./test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

mkdir -p "$OUTPUT_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# ============================================================================
# CLI COMMANDS TESTS (27 commands)
# ============================================================================
log "========================================"
log "SECTION 1: CLI COMMANDS TESTS"
log "========================================"

CLI_COMMANDS=(
    "import --help"
    "search --help"
    "collect --help"
    "alert --help"
    "correlate --help"
    "analyze --help"
    "report --help"
    "export --help"
    "timeline --help"
    "multi --help"
    "live --help"
    "status --help"
    "info --help"
    "verify --help"
    "rules --help"
    "db --help"
    "config --help"
    "metrics --help"
    "query --help"
    "tui --help"
    "serve --help"
    "forensics --help"
    "dashboard --help"
    "whitelist --help"
    "ueba --help"
    "persistence --help"
    "evtx2csv --help"
)

CLI_SUCCESS=0
CLI_FAILED=0

for i in "${!CLI_COMMANDS[@]}"; do
    CMD="${CLI_COMMANDS[$i]}"
    NAME="CLI_$(printf '%02d' $((i+1)))_${CMD%% *}"
    log "Testing CLI: $NAME - $CMD"
    
    JSON_FILE="$OUTPUT_DIR/${NAME}.json"
    
    if $WINALOG_PATH $CMD > "$OUTPUT_DIR/${NAME}_stdout.txt" 2> "$OUTPUT_DIR/${NAME}_stderr.txt"; then
        EXIT_CODE=0
        STATUS="SUCCESS"
        ((CLI_SUCCESS++))
    else
        EXIT_CODE=$?
        STATUS="FAILED"
        ((CLI_FAILED++))
    fi
    
    echo '{"name":"'"$NAME"'","command":"'"$WINALOG_PATH $CMD"'","exit_code":'"$EXIT_CODE"'}' | jq -s '.' > "$JSON_FILE"
    log "  -> $STATUS (Exit: $EXIT_CODE)"
done

# ============================================================================
# API TESTS
# ============================================================================
log ""
log "========================================"
log "SECTION 2: API TESTS"
log "========================================"

test_api() {
    local NAME=$1
    local METHOD=$2
    local ENDPOINT=$3
    local BODY=$4
    
    log "Testing API: $NAME $METHOD $ENDPOINT"
    
    JSON_FILE="$OUTPUT_DIR/${NAME}.json"
    RESPONSE_FILE="$OUTPUT_DIR/${NAME}_response.txt"
    
    if [ "$METHOD" = "GET" ]; then
        HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' -X GET "$BASE_URL$ENDPOINT" --max-time 30 2>/dev/null || echo "000")
    elif [ "$METHOD" = "POST" ]; then
        if [ -n "$BODY" ]; then
            HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' -X POST "$BASE_URL$ENDPOINT" -H "Content-Type: application/json" -d "$BODY" --max-time 30 2>/dev/null || echo "000")
        else
            HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' -X POST "$BASE_URL$ENDPOINT" --max-time 30 2>/dev/null || echo "000")
        fi
    elif [ "$METHOD" = "PUT" ]; then
        HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' -X PUT "$BASE_URL$ENDPOINT" -H "Content-Type: application/json" -d "$BODY" --max-time 30 2>/dev/null || echo "000")
    elif [ "$METHOD" = "DELETE" ]; then
        HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' -X DELETE "$BASE_URL$ENDPOINT" --max-time 30 2>/dev/null || echo "000")
    fi
    
    local DURATION=$(curl -s -o /dev/null -w '%{time_total}' "$BASE_URL$ENDPOINT" --max-time 30 2>/dev/null || echo "0")
    
    echo '{"name":"'"$NAME"'","method":"'"$METHOD"'","endpoint":"'"$ENDPOINT"'","status_code":'"$HTTP_CODE"'","duration":'"$DURATION"'}' > "$JSON_FILE"
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        log "  -> SUCCESS (HTTP $HTTP_CODE, Duration: ${DURATION}s)"
    else
        log "  -> FAILED (HTTP $HTTP_CODE, Duration: ${DURATION}s)"
    fi
}

# Events API
log ""
log "--- Events API ---"
test_api "API_Events_01_List" "GET" "/api/events"
test_api "API_Events_02_Search" "POST" "/api/events/search" '{"page":1,"page_size":10}'
test_api "API_Events_03_Export" "POST" "/api/events/export" '{"format":"json","filters":{"limit":10}}'

# Alerts API
log ""
log "--- Alerts API ---"
test_api "API_Alerts_01_List" "GET" "/api/alerts"
test_api "API_Alerts_02_Stats" "GET" "/api/alerts/stats"
test_api "API_Alerts_03_Trend" "GET" "/api/alerts/trend"
test_api "API_Alerts_04_RunAnalysis" "POST" "/api/alerts/run-analysis"
test_api "API_Alerts_05_Batch" "POST" "/api/alerts/batch" '{"ids":[1],"action":"resolve"}'

# Timeline API
log ""
log "--- Timeline API ---"
test_api "API_Timeline_01_List" "GET" "/api/timeline?limit=10"
test_api "API_Timeline_02_Stats" "GET" "/api/timeline/stats"
test_api "API_Timeline_03_Chains" "GET" "/api/timeline/chains"
test_api "API_Timeline_04_Export" "GET" "/api/timeline/export?format=json"

# Import API
log ""
log "--- Import API ---"
test_api "API_Import_01_Status" "GET" "/api/import/status?path=test.evtx"

# Live Events API
log ""
log "--- Live Events API ---"
test_api "API_Live_01_Stats" "GET" "/api/live/stats"

# Reports API
log ""
log "--- Reports API ---"
test_api "API_Reports_01_List" "GET" "/api/reports"
test_api "API_Reports_02_Templates" "GET" "/api/report-templates"
test_api "API_Reports_03_Export" "GET" "/api/reports/export?format=json"
test_api "API_Reports_04_Create" "POST" "/api/reports" '{"type":"security_summary","format":"html"}'

# Dashboard API
log ""
log "--- Dashboard API ---"
test_api "API_Dashboard_01_Stats" "GET" "/api/dashboard/collection-stats"

# Rules API
log ""
log "--- Rules API ---"
test_api "API_Rules_01_List" "GET" "/api/rules"
test_api "API_Rules_02_Templates" "GET" "/api/rules/templates"
test_api "API_Rules_03_Export" "GET" "/api/rules/export"
test_api "API_Rules_04_Validate" "POST" "/api/rules/validate" '{"name":"TestRule","event_type":"single"}'

# System API
log ""
log "--- System API ---"
test_api "API_System_01_Info" "GET" "/api/system/info"
test_api "API_System_02_Metrics" "GET" "/api/system/metrics"
test_api "API_System_03_Processes" "GET" "/api/system/processes"
test_api "API_System_04_Network" "GET" "/api/system/network"
test_api "API_System_05_Env" "GET" "/api/system/env"
test_api "API_System_06_DLLs" "GET" "/api/system/dlls"
test_api "API_System_07_Drivers" "GET" "/api/system/drivers"
test_api "API_System_08_Users" "GET" "/api/system/users"
test_api "API_System_09_Registry" "GET" "/api/system/registry"
test_api "API_System_10_Tasks" "GET" "/api/system/tasks"

# Suppress API
log ""
log "--- Suppress API ---"
test_api "API_Suppress_01_List" "GET" "/api/suppress"

# UEBA API
log ""
log "--- UEBA API ---"
test_api "API_UEBA_01_Analyze" "POST" "/api/ueba/analyze" '{"username":"Administrator"}'
test_api "API_UEBA_02_Profiles" "GET" "/api/ueba/profiles"
test_api "API_UEBA_03_Anomaly" "GET" "/api/ueba/anomaly/unusual_time"

# Correlation API
log ""
log "--- Correlation API ---"
test_api "API_Correlation_01_Analyze" "POST" "/api/correlation/analyze" '{"window":"5m"}'

# Multi API
log ""
log "--- Multi API ---"
test_api "API_Multi_01_Analyze" "POST" "/api/multi/analyze" '{"sources":["security"],"query":"event_id:4624"}'
test_api "API_Multi_02_Lateral" "GET" "/api/multi/lateral"

# Query API
log ""
log "--- Query API ---"
test_api "API_Query_01_Execute" "POST" "/api/query/execute" '{"query":"SELECT 1 as test","limit":10}'

# Policy API
log ""
log "--- Policy API ---"
test_api "API_Policy_01_Templates" "GET" "/api/policy-templates"
test_api "API_Policy_02_Instances" "GET" "/api/policy-instances"

# Monitor API
log ""
log "--- Monitor API ---"
test_api "API_Monitor_01_Stats" "GET" "/api/monitor/stats"
test_api "API_Monitor_02_Events" "GET" "/api/monitor/events"
test_api "API_Monitor_03_Config" "POST" "/api/monitor/config" '{"enabled":true}'
test_api "API_Monitor_04_Action" "POST" "/api/monitor/action" '{"action":"start"}'

# Settings API
log ""
log "--- Settings API ---"
test_api "API_Settings_01_Get" "GET" "/api/settings"
test_api "API_Settings_02_Update" "POST" "/api/settings" '{"log_level":"info"}'
test_api "API_Settings_03_Reset" "POST" "/api/settings/reset"

# Persistence API
log ""
log "--- Persistence API ---"
test_api "API_Persistence_01_Detect" "GET" "/api/persistence/detect"
test_api "API_Persistence_02_Categories" "GET" "/api/persistence/categories"
test_api "API_Persistence_03_Techniques" "GET" "/api/persistence/techniques"

# Forensics API
log ""
log "--- Forensics API ---"
test_api "API_Forensics_01_Hash" "POST" "/api/forensics/hash" '{"paths":["/etc/passwd"],"algorithms":["md5"]}'
test_api "API_Forensics_02_Signature" "GET" "/api/forensics/signature?path=/bin/ls"
test_api "API_Forensics_03_IsSigned" "GET" "/api/forensics/is-signed?path=/bin/ls"
test_api "API_Forensics_04_Evidence" "GET" "/api/forensics/evidence"
test_api "API_Forensics_05_Manifest" "POST" "/api/forensics/manifest" '{"paths":["/tmp"],"include_hashes":true}'

# Analyze API
log ""
log "--- Analyze API ---"
test_api "API_Analyze_01_Analyze" "POST" "/api/analyze/hash" '{"target":"/bin/ls"}'
test_api "API_Analyze_02_Analyzers" "GET" "/api/analyzers"

# Collect API
log ""
log "--- Collect API ---"
test_api "API_Collect_01_Collect" "POST" "/api/collect" '{"sources":["security"]}'
test_api "API_Collect_02_Status" "GET" "/api/collect/status?task_id=test"

# UI API
log ""
log "--- UI API ---"
test_api "API_UI_01_Dashboard" "GET" "/api/ui/dashboard"
test_api "API_UI_02_AlertGroups" "GET" "/api/ui/alerts/groups"
test_api "API_UI_03_Metrics" "GET" "/api/ui/metrics"
test_api "API_UI_04_Distribution" "GET" "/api/ui/events/distribution"

# Health Check
log ""
log "--- Health Check ---"
test_api "API_Health_01_Check" "GET" "/api/health"

# ============================================================================
# SUMMARY
# ============================================================================
log ""
log "========================================"
log "TEST SUMMARY"
log "========================================"
log "Total CLI Commands Tested: ${#CLI_COMMANDS[@]}"
log "CLI Commands Successful: $CLI_SUCCESS"
log "CLI Commands Failed: $CLI_FAILED"
log ""
log "Results saved to: $OUTPUT_DIR"
log "Log file: $LOG_FILE"
log "========================================"
log "TEST COMPLETED"
log "========================================"

# Save summary
cat > "$OUTPUT_DIR/test_summary.json" << EOF
{
  "test_run": "$TIMESTAMP",
  "cli_total": ${#CLI_COMMANDS[@]},
  "cli_success": $CLI_SUCCESS,
  "cli_failed": $CLI_FAILED,
  "output_dir": "$OUTPUT_DIR",
  "log_file": "$LOG_FILE"
}
EOF
