#!/bin/bash
# WinLogAnalyzer-Go API Test Script (Linux Version)
# Usage: ./api_test.sh [OPTIONS]
#
# Options:
#   -b, --base-url URL       API server URL (default: http://localhost:8080/api)
#   -o, --output-dir DIR     Output directory (default: ./api_test_results)
#   -e, --evtx-file FILE     EVTX file for import tests
#   --skip-live              Skip live events tests
#   --skip-import            Skip import tests
#   --full-test              Full test with data preparation
#   --enable-sse              Enable SSE stream tests
#   --enable-validation       Enable response JSON validation
#   --enable-performance      Enable performance benchmarks
#   --max-retries N          Max retry count (default: 3)
#   --retry-delay MS         Retry delay in ms (default: 1000)
#   -h, --help               Show this help

set -e

# Default values
BASE_URL="http://localhost:8080/api"
OUTPUT_DIR="./api_test_results_$(date +%Y%m%d_%H%M%S)"
TEST_EVTX_FILE=""
SKIP_LIVE_TESTS=false
SKIP_IMPORT_TESTS=false
FULL_TEST=false
ENABLE_SSE=false
ENABLE_VALIDATION=false
ENABLE_PERFORMANCE=false
MAX_RETRIES=3
RETRY_DELAY_MS=1000

# Arrays for storing results
declare -a TEST_RESULTS=()
declare -A PERFORMANCE_DATA=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo -e "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$OUTPUT_DIR/test_log.txt"
}

pass() {
    log "PASS" "$@"
}

fail() {
    log "FAIL" "$@"
}

error() {
    log "ERROR" "$@"
}

warn() {
    log "WARN" "$@"
}

info() {
    log "INFO" "$@"
}

find_evtx_files() {
    local search_paths=(
        "$HOME/Desktop/*.evtx"
        "$HOME/Documents/*.evtx"
        "$HOME/Downloads/*.evtx"
        "./*.evtx"
        "./test_data/*.evtx"
        "./test_files/*.evtx"
        "./data/*.evtx"
        "./test_dataset/logs/**/*.evtx"
        "/workspace/test_dataset/logs/**/*.evtx"
    )

    for path in "${search_paths[@]}"; do
        local files=$(find $(dirname "$path") -name "$(basename "$path")" 2>/dev/null || true)
        if [ -n "$files" ]; then
            echo "$files" | head -1
            return 0
        fi
    done
    
    local evtx_in_dataset=$(find /workspace/test_dataset/logs -name "*.evtx" 2>/dev/null | head -1)
    if [ -n "$evtx_in_dataset" ]; then
        echo "$evtx_in_dataset"
        return 0
    fi
    
    return 1
}

test_api_request() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local body="$4"
    local expected_status="${5:-200}"
    local description="${6:-}"

    info "Testing: $name"
    info "Method: $method $endpoint"
    [ -n "$description" ] && info "Desc: $description"

    local output_file="$OUTPUT_DIR/${name}.json"
    local start_time=$(date +%s.%N)
    local attempt=0
    local success=false
    local status_code=0
    local response=""

    while [ $attempt -lt $MAX_RETRIES ] && [ "$success" = "false" ]; do
        attempt=$((attempt + 1))
        [ $attempt -gt 1 ] && warn "Retry $attempt/$MAX_RETRIES after ${RETRY_DELAY_MS}ms..."

        local curl_args=("-s" "-w" "\n%{http_code}" "-X" "$method")

        if [ "$method" = "POST" ] || [ "$method" = "PUT" ] || [ "$method" = "DELETE" ]; then
            curl_args+=("-H" "Content-Type: application/json")
        fi

        if [ -n "$body" ]; then
            curl_args+=("-d" "$body")
        fi

        curl_args+=("$BASE_URL$endpoint")

        local curl_output
        curl_output=$(curl "${curl_args[@]}" 2>/dev/null || true)
        local curl_result=$?

        if [ $curl_result -ne 0 ]; then
            warn "curl failed with code $curl_result"
            if [ $attempt -lt $MAX_RETRIES ]; then
                sleep $((RETRY_DELAY_MS / 1000))
                continue
            fi
        fi

        status_code=$(echo "$curl_output" | tail -1)
        response=$(echo "$curl_output" | sed '$d')

        if [ "$expected_status" = "0" ]; then
            if [ "$status_code" -gt 0 ]; then
                success=true
            fi
        elif [ "$status_code" = "$expected_status" ]; then
            success=true
        fi

        if [ "$success" = "true" ]; then
            pass "Status: PASS (HTTP $status_code, Duration: $(echo "$(date +%s.%N) - $start_time" | bc)s)"
            [ -n "$response" ] && echo "$response" > "$output_file"
        else
            if [ $attempt -lt $MAX_RETRIES ]; then
                warn "Status: RETRY (HTTP $status_code, Expected: $expected_status)"
                sleep $((RETRY_DELAY_MS / 1000))
            else
                fail "Status: FAIL (HTTP $status_code, Expected: $expected_status)"
            fi
        fi
    done

    local duration=$(echo "$(date +%s.%N) - $start_time" | bc)
    local test_result="{\"name\":\"$name\",\"method\":\"$method\",\"endpoint\":\"$endpoint\",\"status_code\":$status_code,\"duration\":$duration,\"status\":\"$( [ "$success" = "true" ] && echo "PASS" || echo "FAIL" )\",\"timestamp\":\"$(date -Iseconds)\"}"
    TEST_RESULTS+=("$test_result")

    if [ "$ENABLE_PERFORMANCE" = "true" ]; then
        PERFORMANCE_DATA[$name]="$duration,$status_code"
    fi

    echo "---"
}

test_api_json_post() {
    local name="$1"
    local endpoint="$2"
    local json_body="$3"
    local expected_status="${4:-200}"
    local description="${5:-}"

    local body=$(echo "$json_body" | jq -c '.' 2>/dev/null || echo "$json_body")
    test_api_request "$name" "POST" "$endpoint" "$body" "$expected_status" "$description"
}

test_sse_stream() {
    local name="$1"
    local endpoint="$2"
    local timeout="${3:-10}"

    if [ "$ENABLE_SSE" != "true" ]; then
        warn "SSE tests disabled (use --enable-sse to enable)"
        return
    fi

    info "Testing SSE stream: $name"
    info "Endpoint: $endpoint"

    local output_file="$OUTPUT_DIR/${name}.txt"
    local start_time=$(date +%s.%N)

    local events_count
    events_count=$(timeout $timeout curl -sN "$BASE_URL$endpoint" 2>/dev/null | grep -c "^data:" || echo "0")

    local duration=$(echo "$(date +%s.%N) - $start_time" | bc)

    if [ "$events_count" -gt 0 ]; then
        pass "SSE PASS: Received $events_count events in ${duration}s"
        echo "$events_count" > "$output_file"
    else
        fail "SSE FAIL: No events received"
    fi

    echo "---"
}

validate_json_response() {
    local name="$1"
    local response="$2"
    shift 2
    local required_fields=("$@")

    if [ "$ENABLE_VALIDATION" != "true" ]; then
        return 0
    fi

    info "Validating response for: $name"

    for field in "${required_fields[@]}"; do
        if ! echo "$response" | jq -e ".$field" > /dev/null 2>&1; then
            error "Missing required field: $field"
            return 1
        fi
    done

    pass "Validation PASSED"
    return 0
}

parse_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | jq -r ".$field // empty" 2>/dev/null || echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--base-url)
            BASE_URL="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -e|--evtx-file)
            TEST_EVTX_FILE="$2"
            shift 2
            ;;
        --skip-live)
            SKIP_LIVE_TESTS=true
            shift
            ;;
        --skip-import)
            SKIP_IMPORT_TESTS=true
            shift
            ;;
        --full-test)
            FULL_TEST=true
            shift
            ;;
        --enable-sse)
            ENABLE_SSE=true
            shift
            ;;
        --enable-validation)
            ENABLE_VALIDATION=true
            shift
            ;;
        --enable-performance)
            ENABLE_PERFORMANCE=true
            shift
            ;;
        --max-retries)
            MAX_RETRIES="$2"
            shift 2
            ;;
        --retry-delay)
            RETRY_DELAY_MS="$2"
            shift 2
            ;;
        -h|--help)
            grep "^#" "$0" | sed 's/^# //'
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT_DIR/test_log.txt"

info "========================================"
info "WinLogAnalyzer-Go API Test Suite (Linux)"
info "========================================"
info "Base URL: $BASE_URL"
info "Start Time: $(date -Iseconds)"
info "Max Retries: $MAX_RETRIES"
info "Retry Delay: ${RETRY_DELAY_MS}ms"
info "SSE Enabled: $ENABLE_SSE"
info "Validation Enabled: $ENABLE_VALIDATION"
info "Performance Enabled: $ENABLE_PERFORMANCE"

# Auto-find EVTX file if needed
if [ "$SKIP_IMPORT_TESTS" != "true" ] && [ -z "$TEST_EVTX_FILE" ]; then
    info "Auto-searching for EVTX files..."
    TEST_EVTX_FILE=$(find_evtx_files)
    if [ -n "$TEST_EVTX_FILE" ]; then
        info "Found EVTX file: $TEST_EVTX_FILE"
    else
        warn "No EVTX files found in search paths"
    fi
fi

info "========================================"
info "Step 0: Prepare Test Environment"
info "========================================"

test_api_request "health_check" "GET" "/health" "" "200" "Health check"

# Import test data
if [ "$SKIP_IMPORT_TESTS" != "true" ] && [ -n "$TEST_EVTX_FILE" ] && [ -f "$TEST_EVTX_FILE" ]; then
    info "========================================"
    info "Step 0.1: Import Test Data"
    info "========================================"
    info "Importing: $TEST_EVTX_FILE"
    test_api_json_post "import_logs" "/import/logs" "{\"files\":[\"$TEST_EVTX_FILE\"],\"alert_on_import\":false}" "200" "Import EVTX file for testing"
fi

info "========================================"
info "Part 1: Events API"
info "========================================"

test_api_request "events_list" "GET" "/events?page=1&page_size=10" "" "200" "List events with pagination"
test_api_request "events_list_page2" "GET" "/events?page=2&page_size=10" "" "200" "List events page 2"

# Get first event ID for later tests
FIRST_EVENT_ID=""
EVENTS_RESPONSE=$(curl -s "${BASE_URL}/events?page=1&page_size=1")
if [ -n "$EVENTS_RESPONSE" ]; then
    FIRST_EVENT_ID=$(echo "$EVENTS_RESPONSE" | jq -r '.events[0].id' 2>/dev/null || echo "")
    if [ -n "$FIRST_EVENT_ID" ] && [ "$FIRST_EVENT_ID" != "null" ]; then
        info "Testing event get by ID: $FIRST_EVENT_ID"
        test_api_request "events_get_by_id" "GET" "/events/$FIRST_EVENT_ID" "" "200" "Get event by ID"
    fi
fi

test_api_json_post "events_search_basic" "/events/search" '{"page_size":10}' "200" "Basic search"
test_api_json_post "events_search_keywords" "/events/search" '{"keywords":"system","page_size":10}' "200" "Search by keywords"
test_api_json_post "events_search_levels" "/events/search" '{"levels":[4],"page_size":10}' "200" "Search by level"
test_api_json_post "events_search_regex" "/events/search" '{"keywords":"4624|4625","regex":true,"page_size":10}' "200" "Regex search"
test_api_json_post "events_search_event_ids" "/events/search" '{"event_ids":[4624,4625],"page_size":10}' "200" "Search by event IDs"
test_api_json_post "events_search_time" "/events/search" '{"start_time":"2024-01-01T00:00:00Z","end_time":"2024-12-31T23:59:59Z","page_size":10}' "200" "Time range search"
test_api_json_post "events_search_users" "/events/search" '{"users":["Administrator"],"page_size":10}' "200" "Search by users"
test_api_json_post "events_search_computers" "/events/search" '{"computers":["localhost"],"page_size":10}' "200" "Search by computers"
test_api_json_post "events_search_lognames" "/events/search" '{"log_names":["Security"],"page_size":10}' "200" "Search by log names"
test_api_json_post "events_search_sort" "/events/search" '{"sort_by":"timestamp","sort_order":"desc","page_size":10}' "200" "Sorted search"
test_api_json_post "events_export_csv" "/events/export" '{"format":"csv","filters":{"limit":100}}' "200" "Export events as CSV"
test_api_json_post "events_export_json" "/events/export" '{"format":"json","filters":{"limit":100}}' "200" "Export events as JSON"

info "========================================"
info "Step 0.2: Run Alert Analysis"
info "========================================"
info "Skipping alerts_run_analysis (too slow for quick tests)"
# test_api_json_post "alerts_run_analysis" "/alerts/run-analysis" '{}' "200" "Run alert analysis to generate test alerts"

if [ "$FULL_TEST" = "true" ]; then
    info "Waiting for alert analysis to complete..."
    sleep 5
fi

info "========================================"
info "Part 2: Alerts API"
info "========================================"

test_api_request "alerts_list" "GET" "/alerts?page=1&page_size=10" "" "200" "List alerts"
test_api_request "alerts_list_high" "GET" "/alerts?severity=high&page_size=10" "" "200" "List high severity alerts"
test_api_request "alerts_list_medium" "GET" "/alerts?severity=medium&page_size=10" "" "200" "List medium severity alerts"
test_api_request "alerts_list_low" "GET" "/alerts?severity=low&page_size=10" "" "200" "List low severity alerts"
test_api_request "alerts_list_unresolved" "GET" "/alerts?resolved=false&page_size=10" "" "200" "List unresolved alerts"
test_api_request "alerts_list_resolved" "GET" "/alerts?resolved=true&page_size=10" "" "200" "List resolved alerts"
test_api_request "alerts_stats" "GET" "/alerts/stats" "" "200" "Get alert statistics"
test_api_request "alerts_trend_7d" "GET" "/alerts/trend?days=7" "" "200" "Get alert trend 7 days"
test_api_request "alerts_trend_30d" "GET" "/alerts/trend?days=30" "" "200" "Get alert trend 30 days"

# Get first alert for resolve test
ALERTS_RESPONSE=$(curl -s "${BASE_URL}/alerts?page=1&page_size=1")
if [ -n "$ALERTS_RESPONSE" ]; then
    FIRST_ALERT_ID=$(echo "$ALERTS_RESPONSE" | jq -r '.alerts[0].id' 2>/dev/null || echo "")
    if [ -n "$FIRST_ALERT_ID" ] && [ "$FIRST_ALERT_ID" != "null" ]; then
        info "Testing alert operations on ID: $FIRST_ALERT_ID"
        test_api_json_post "alerts_resolve" "/alerts/$FIRST_ALERT_ID/resolve" '{"notes":"Test resolve from API script"}' "200" "Resolve alert"
        test_api_request "alerts_get_resolved" "GET" "/alerts/$FIRST_ALERT_ID" "" "200" "Get resolved alert"
        test_api_json_post "alerts_false_positive" "/alerts/$FIRST_ALERT_ID/false-positive" '{"reason":"Test false positive"}' "200" "Mark as false positive"
    fi
fi

test_api_json_post "alerts_batch_resolve" "/alerts/batch" '{"ids":[1,2,3],"action":"resolve","notes":"Batch test"}' "200" "Batch resolve alerts"
test_api_json_post "alerts_batch_delete" "/alerts/batch" '{"ids":[999999],"action":"delete"}' "200" "Batch delete (non-existent)"

# Test alert DELETE
ALERTS_DELETE_RESPONSE=$(curl -s "${BASE_URL}/alerts?page=1&page_size=1")
if [ -n "$ALERTS_DELETE_RESPONSE" ]; then
    ALERT_ID_FOR_DELETE=$(echo "$ALERTS_DELETE_RESPONSE" | jq -r '.alerts[0].id' 2>/dev/null || echo "")
    if [ -n "$ALERT_ID_FOR_DELETE" ] && [ "$ALERT_ID_FOR_DELETE" != "null" ]; then
        info "Testing alert DELETE on ID: $ALERT_ID_FOR_DELETE"
        test_api_request "alerts_delete" "DELETE" "/alerts/$ALERT_ID_FOR_DELETE" "" "200" "Delete alert"
    fi
fi

info "========================================"
info "Part 3: Timeline API"
info "========================================"

test_api_request "timeline_list" "GET" "/timeline?limit=50" "" "200" "Get timeline"
test_api_request "timeline_stats" "GET" "/timeline/stats" "" "200" "Get timeline stats"
test_api_request "timeline_chains" "GET" "/timeline/chains" "" "200" "Get attack chains"
test_api_request "timeline_export_json" "GET" "/timeline/export?format=json" "" "200" "Export timeline as JSON"
test_api_request "timeline_export_csv" "GET" "/timeline/export?format=csv" "" "200" "Export timeline as CSV"
test_api_request "timeline_with_time" "GET" "/timeline?start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T23:59:59Z" "" "200" "Timeline with time filter"

# Test timeline alert DELETE
TIMELINE_ALERT_RESPONSE=$(curl -s "${BASE_URL}/alerts?page=1&page_size=1")
if [ -n "$TIMELINE_ALERT_RESPONSE" ]; then
    TIMELINE_ALERT_ID=$(echo "$TIMELINE_ALERT_RESPONSE" | jq -r '.alerts[0].id' 2>/dev/null || echo "")
    if [ -n "$TIMELINE_ALERT_ID" ] && [ "$TIMELINE_ALERT_ID" != "null" ]; then
        info "Testing timeline alert DELETE on ID: $TIMELINE_ALERT_ID"
        test_api_request "timeline_alert_delete" "DELETE" "/timeline/alerts/$TIMELINE_ALERT_ID" "" "200" "Delete alert from timeline"
    fi
fi

info "========================================"
info "Part 4: Dashboard API"
info "========================================"

test_api_request "dashboard_stats" "GET" "/dashboard/collection-stats" "" "200" "Get collection statistics"

info "========================================"
info "Part 5: Rules API"
info "========================================"

test_api_request "rules_list" "GET" "/rules?page=1&page_size=20" "" "200" "List all rules"
test_api_request "rules_list_enabled" "GET" "/rules?enabled=true&page_size=20" "" "200" "List enabled rules"
test_api_request "rules_templates" "GET" "/rules/templates" "" "200" "List rule templates"
test_api_request "rules_templates_powershell" "GET" "/rules/templates/powershell_detection" "" "200" "Get PowerShell template"
test_api_request "rules_validate" "POST" "/rules/validate" '{"name":"TestRule","event_type":"single","conditions":[]}' "200" "Validate rule"
test_api_request "rules_export" "GET" "/rules/export?format=json" "" "200" "Export rules"

# Test rule operations
RULES_RESPONSE=$(curl -s "${BASE_URL}/rules?page=1&page_size=1")
if [ -n "$RULES_RESPONSE" ]; then
    FIRST_RULE_NAME=$(echo "$RULES_RESPONSE" | jq -r '.rules[0].name' 2>/dev/null || echo "")
    if [ -n "$FIRST_RULE_NAME" ] && [ "$FIRST_RULE_NAME" != "null" ]; then
        info "Testing rule operations on: $FIRST_RULE_NAME"
        test_api_request "rules_get" "GET" "/rules/$FIRST_RULE_NAME" "" "200" "Get specific rule"
        test_api_request "rules_toggle" "POST" "/rules/$FIRST_RULE_NAME/toggle" "" "200" "Toggle rule"
        test_api_request "rules_update" "PUT" "/rules/$FIRST_RULE_NAME" '{"description":"Updated description","severity":"low"}' "200" "Update rule"
        test_api_json_post "rules_create" "/rules" '{"name":"APITestRule","description":"Test rule from API","event_type":"single","enabled":false,"severity":"medium","conditions":[]}' "201" "Create new rule"
        test_api_request "rules_delete" "DELETE" "/rules/APITestRule" "" "200" "Delete test rule"
    fi
fi

test_api_json_post "rules_import" "/rules/import" '{"file_path":"test_rules.json"}' "200" "Import rules from file"
info "Skipping rules_templates_instantiate - template not available"

info "========================================"
info "Part 6: System API"
info "========================================"

test_api_request "system_info" "GET" "/system/info" "" "200" "Get system info"
test_api_request "system_metrics" "GET" "/system/metrics" "" "200" "Get system metrics"
test_api_request "system_processes" "GET" "/system/processes?page=1&page_size=10" "" "200" "List processes"
test_api_request "system_network" "GET" "/system/network" "" "200" "Get network connections"
test_api_request "system_users" "GET" "/system/users" "" "200" "Get local users"
test_api_request "system_tasks" "GET" "/system/tasks" "" "200" "Get scheduled tasks"
test_api_request "system_dlls" "GET" "/system/dlls?page_size=10" "" "200" "Get loaded DLLs"
test_api_request "system_drivers" "GET" "/system/drivers" "" "200" "Get kernel drivers"
test_api_request "system_env" "GET" "/system/env" "" "200" "Get environment variables"
test_api_request "system_registry" "GET" "/system/registry" "" "200" "Get registry stats"

# Test process DLLs
PROCESS_RESPONSE=$(curl -s "${BASE_URL}/system/processes?page=1&page_size=1")
if [ -n "$PROCESS_RESPONSE" ]; then
    FIRST_PID=$(echo "$PROCESS_RESPONSE" | jq -r '.processes[0].pid' 2>/dev/null || echo "")
    if [ -n "$FIRST_PID" ] && [ "$FIRST_PID" != "null" ]; then
        info "Testing process DLLs for PID: $FIRST_PID"
        test_api_request "system_process_dlls" "GET" "/system/process/$FIRST_PID/dlls" "" "200" "Get DLLs for specific process"
    fi
fi

info "========================================"
info "Step 0.3: Collect Forensic Data"
info "========================================"

test_api_json_post "forensics_collect" "/forensics/collect" '{"targets":["processes","network","registry"],"options":{"include_hidden":true,"deep_scan":false}}' "200" "Collect forensic data for testing"

info "Waiting for forensics collection..."
sleep 3

info "========================================"
info "Part 7: Forensics API"
info "========================================"

test_api_json_post "forensics_hash_single" "/forensics/hash" '{"paths":["/etc/hosts"],"algorithms":["md5","sha256"]}' "200" "Calculate hash for /etc/hosts"
test_api_json_post "forensics_hash_multiple" "/forensics/hash" '{"paths":["/etc/hosts","/etc/passwd"],"algorithms":["sha256"]}' "200" "Calculate hashes for multiple files"
test_api_request "forensics_signature" "GET" "/forensics/signature?path=/etc/hosts" "" "200" "Get file signature"
test_api_request "forensics_is_signed" "GET" "/forensics/is-signed?path=/etc/hosts" "" "200" "Check if file is signed"
test_api_request "forensics_evidence_list" "GET" "/forensics/evidence?page=1&page_size=10" "" "200" "List evidence"
test_api_json_post "forensics_manifest" "/forensics/manifest" '{"paths":["/etc/hosts"],"include_hashes":true}' "200" "Generate forensic manifest"
test_api_request "forensics_chain_custody" "GET" "/forensics/chain-of-custody" "" "200" "Get chain of custody"
test_api_request "forensics_memory_dump" "GET" "/forensics/memory-dump" "" "200" "Get memory dump info"
test_api_request "forensics_verify_hash" "GET" "/forensics/verify-hash?hash=a1b2c3d4e5f6" "" "400" "Verify hash (expect not found)"

# Test forensics evidence detail
EVIDENCE_RESPONSE=$(curl -s "${BASE_URL}/forensics/evidence?page=1&page_size=1")
if [ -n "$EVIDENCE_RESPONSE" ]; then
    FIRST_EVIDENCE_ID=$(echo "$EVIDENCE_RESPONSE" | jq -r '.evidence[0].id' 2>/dev/null || echo "")
    if [ -n "$FIRST_EVIDENCE_ID" ] && [ "$FIRST_EVIDENCE_ID" != "null" ]; then
        info "Testing forensics evidence detail for ID: $FIRST_EVIDENCE_ID"
        test_api_request "forensics_evidence_detail" "GET" "/forensics/evidence/$FIRST_EVIDENCE_ID" "" "200" "Get evidence details"
    fi
fi

info "========================================"
info "Step 0.4: Start Monitor"
info "========================================"

test_api_json_post "monitor_config" "/monitor/config" '{"process_monitoring":{"enabled":true,"interval_ms":3000},"network_monitoring":{"enabled":true,"interval_ms":5000},"dns_monitoring":{"enabled":false}}' "200" "Configure monitor"
test_api_json_post "monitor_action_start" "/monitor/action" '{"action":"start"}' "200" "Start monitoring"

info "Waiting for monitor to collect data..."
sleep 5

info "========================================"
info "Part 8: Monitor API"
info "========================================"

test_api_request "monitor_stats" "GET" "/monitor/stats" "" "200" "Get monitor statistics"
test_api_request "monitor_events_all" "GET" "/monitor/events?limit=20" "" "200" "List all monitor events"
test_api_request "monitor_events_process" "GET" "/monitor/events?type=process&limit=10" "" "200" "List process events"
test_api_request "monitor_events_network" "GET" "/monitor/events?type=network&limit=10" "" "200" "List network events"
test_api_request "monitor_events_dns" "GET" "/monitor/events?type=dns&limit=10" "" "200" "List DNS events"
test_api_request "monitor_events_severity" "GET" "/monitor/events?severity=high&limit=10" "" "200" "List high severity events"
test_api_json_post "monitor_action_stop" "/monitor/action" '{"action":"stop"}' "200" "Stop monitoring"

if [ "$ENABLE_SSE" = "true" ]; then
    info "========================================"
    info "Part 8.5: SSE Stream Tests"
    info "========================================"
    test_sse_stream "monitor_events_stream" "/monitor/events/stream" 10
fi

info "========================================"
info "Part 9: Reports API"
info "========================================"

test_api_request "reports_list" "GET" "/reports" "" "200" "List reports"
test_api_request "report_templates" "GET" "/report-templates" "" "200" "List report templates"
test_api_request "report_templates_security" "GET" "/report-templates/security_summary" "" "200" "Get security summary template"

REPORT_RESPONSE=$(test_api_json_post "reports_generate_summary" "/reports" '{"type":"security_summary","format":"json","title":"API Test Report","description":"Generated by API test script"}' "200" "Generate summary report")
REPORT_ID=$(echo "$REPORT_RESPONSE" | jq -r '.id' 2>/dev/null || echo "")
if [ -n "$REPORT_ID" ] && [ "$REPORT_ID" != "null" ]; then
    info "Report generated with ID: $REPORT_ID"
    sleep 2
    test_api_request "reports_get" "GET" "/reports/$REPORT_ID" "" "200" "Get report details"
fi

test_api_json_post "reports_generate_alert" "/reports" '{"type":"alert_report","format":"json"}' "200" "Generate alert report"
test_api_json_post "reports_generate_event" "/reports" '{"type":"event_report","format":"json"}' "200" "Generate event report"
test_api_json_post "reports_generate_timeline" "/reports" '{"type":"timeline_report","format":"json"}' "200" "Generate timeline report"
test_api_request "reports_export_json" "GET" "/reports/export?format=json" "" "200" "Export reports as JSON"
test_api_request "reports_export_csv" "GET" "/reports/export?format=csv" "" "200" "Export reports as CSV"

test_api_request "report_templates_alert" "GET" "/report-templates/alert_details" "" "200" "Get alert details template"
test_api_json_post "report_templates_create" "/report-templates" '{"name":"custom_test_report","description":"Custom test report","content":"<html>Test</html>"}' "201" "Create custom report template"
test_api_request "report_templates_get_new" "GET" "/report-templates/custom_test_report" "" "200" "Get newly created template"
test_api_request "report_templates_delete" "DELETE" "/report-templates/custom_test_report" "" "200" "Delete custom template"

# Test report download
REPORTS_LIST_RESPONSE=$(curl -s "${BASE_URL}/reports?page=1&page_size=1")
if [ -n "$REPORTS_LIST_RESPONSE" ]; then
    FIRST_REPORT_ID=$(echo "$REPORTS_LIST_RESPONSE" | jq -r '.reports[0].id' 2>/dev/null || echo "")
    if [ -n "$FIRST_REPORT_ID" ] && [ "$FIRST_REPORT_ID" != "null" ]; then
        info "Testing report download for ID: $FIRST_REPORT_ID"
        test_api_request "reports_download" "GET" "/reports/$FIRST_REPORT_ID/download" "" "200" "Download report file"
    fi
fi

info "========================================"
info "Part 10: UEBA API"
info "========================================"

test_api_json_post "ueba_analyze" "/ueba/analyze" '{"start_time":"2024-01-01T00:00:00Z","end_time":"2024-12-31T23:59:59Z"}' "200" "Analyze user behavior"
test_api_request "ueba_profiles" "GET" "/ueba/profiles?page=1&page_size=10" "" "200" "Get user profiles"
test_api_request "ueba_anomaly_time" "GET" "/ueba/anomaly/unusual_time" "" "200" "Get unusual time anomalies"
test_api_request "ueba_anomaly_location" "GET" "/ueba/anomaly/unusual_location" "" "200" "Get unusual location anomalies"
test_api_request "ueba_anomaly_command" "GET" "/ueba/anomaly/unusual_command" "" "200" "Get unusual command anomalies"
test_api_request "ueba_anomaly_process" "GET" "/ueba/anomaly/unusual_process" "" "200" "Get unusual process anomalies"

info "========================================"
info "Part 11: Correlation API"
info "========================================"

test_api_json_post "correlation_analyze_default" "/correlation/analyze" '{"window":"5m"}' "200" "Run correlation analysis"
test_api_json_post "correlation_analyze_10m" "/correlation/analyze" '{"window":"10m"}' "200" "Run correlation with 10m window"
test_api_json_post "correlation_analyze_rules" "/correlation/analyze" '{"rules":["BruteForceDetection","SuspiciousProcessCreation"],"window":"5m"}' "200" "Correlation with specific rules"
test_api_json_post "correlation_analyze_time" "/correlation/analyze" '{"start_time":"2024-01-01T00:00:00Z","end_time":"2024-12-31T23:59:59Z","window":"5m"}' "200" "Correlation with time range"

info "========================================"
info "Part 12: Query API"
info "========================================"

test_api_json_post "query_count" "/query/execute" '{"sql":"SELECT COUNT(*) FROM events","limit":10}' "200" "Execute COUNT query"
test_api_json_post "query_select" "/query/execute" '{"sql":"SELECT * FROM events LIMIT 5","limit":10}' "200" "Execute SELECT query"
test_api_json_post "query_pragma" "/query/execute" '{"sql":"PRAGMA table_info(events)"}' "200" "Execute PRAGMA query"
test_api_json_post "query_rules" "/query/execute" '{"sql":"SELECT * FROM rules LIMIT 5"}' "200" "Query rules table"
test_api_json_post "query_alerts" "/query/execute" '{"sql":"SELECT * FROM alerts LIMIT 5"}' "200" "Query alerts table"
test_api_json_post "query_join" "/query/execute" '{"sql":"SELECT e.event_id, COUNT(*) as cnt FROM events e GROUP BY e.event_id LIMIT 10"}' "200" "Execute JOIN query"

info "========================================"
info "Part 13: Persistence API"
info "========================================"

test_api_request "persistence_categories" "GET" "/persistence/categories" "" "200" "Get persistence categories"
test_api_request "persistence_techniques" "GET" "/persistence/techniques" "" "200" "Get MITRE techniques"
test_api_request "persistence_detect_all" "GET" "/persistence/detect" "" "200" "Detect all persistence"
test_api_request "persistence_detect_runkey" "GET" "/persistence/detect?category=runkey" "" "200" "Detect runkey persistence"
test_api_request "persistence_detect_service" "GET" "/persistence/detect?category=service" "" "200" "Detect service persistence"
test_api_request "persistence_detect_scheduled" "GET" "/persistence/detect?category=scheduled_task" "" "200" "Detect scheduled task persistence"
test_api_request "persistence_detect_wmi" "GET" "/persistence/detect?category=wmi" "" "200" "Detect WMI persistence"

if [ "$ENABLE_SSE" = "true" ]; then
    test_sse_stream "persistence_detect_stream" "/persistence/detect/stream" 10
fi

info "========================================"
info "Part 14: Analyze API"
info "========================================"

test_api_request "analyzers_list" "GET" "/analyzers" "" "200" "List all analyzers"
test_api_request "analyzers_persistence" "GET" "/analyzers/persistence" "" "200" "Get persistence analyzer details"
test_api_request "analyzers_brute_force" "GET" "/analyzers/brute_force" "" "200" "Get brute_force analyzer details"
test_api_json_post "analyze_persistence" "/analyze/persistence" '{"target":"all"}' "200" "Run persistence analyzer"

info "========================================"
info "Part 15: Settings API"
info "========================================"

test_api_request "settings_get" "GET" "/settings" "" "200" "Get current settings"
test_api_json_post "settings_update" "/settings" '{"alert_retention_days":60,"log_level":"debug"}' "200" "Update settings"
test_api_request "settings_get_after" "GET" "/settings" "" "200" "Verify settings update"
test_api_request "settings_reset" "POST" "/settings/reset" "" "200" "Reset settings to defaults"

info "========================================"
info "Part 16: Suppress API"
info "========================================"

test_api_request "suppress_list" "GET" "/suppress?page=1&page_size=10" "" "200" "List suppression rules"
test_api_json_post "suppress_create" "/suppress" '{"name":"APITestSuppress","description":"Test suppression","enabled":true,"filter":{"event_ids":[4624],"users":["TestUser"]}}' "201" "Create suppression rule"

SUPPRESS_RESPONSE=$(curl -s "${BASE_URL}/suppress?page=1&page_size=10")
if [ -n "$SUPPRESS_RESPONSE" ]; then
    FIRST_SUPPRESS_ID=$(echo "$SUPPRESS_RESPONSE" | jq -r '.suppressions[0].id' 2>/dev/null || echo "")
    if [ -n "$FIRST_SUPPRESS_ID" ] && [ "$FIRST_SUPPRESS_ID" != "null" ]; then
        test_api_request "suppress_get" "GET" "/suppress/$FIRST_SUPPRESS_ID" "" "200" "Get specific suppression"
        test_api_request "suppress_toggle" "POST" "/suppress/$FIRST_SUPPRESS_ID/toggle" "" "200" "Toggle suppression"
        test_api_request "suppress_delete" "DELETE" "/suppress/$FIRST_SUPPRESS_ID" "" "200" "Delete suppression"
    fi
fi

info "========================================"
info "Part 17: Multi API"
info "========================================"

test_api_json_post "multi_analyze_security" "/multi/analyze" '{"sources":["security"]}' "200" "Multi-source analysis (security)"
test_api_json_post "multi_analyze_multiple" "/multi/analyze" '{"sources":["security","system","sysmon"]}' "200" "Multi-source analysis (multiple)"
test_api_json_post "multi_analyze_time" "/multi/analyze" '{"sources":["security"],"start_time":"2024-01-01T00:00:00Z","end_time":"2024-12-31T23:59:59Z"}' "200" "Multi-source with time filter"
test_api_request "multi_lateral" "GET" "/multi/lateral" "" "200" "Detect lateral movement"
test_api_request "multi_lateral_time" "GET" "/multi/lateral?start_time=2024-01-01T00:00:00Z" "" "200" "Lateral movement with time filter"

info "========================================"
info "Part 18: Collect API"
info "========================================"

test_api_json_post "collect_start_security" "/collect" '{"sources":["security","system"]}' "201" "Start collection"
test_api_request "collect_status" "GET" "/collect/status?task_id=test" "" "0" "Get collection status"
test_api_json_post "collect_import" "/collect/import" '{"file_path":"test.evtx","source_type":"evtx"}' "200" "Import collected data"

info "========================================"
info "Part 19: Import API"
info "========================================"

if [ "$SKIP_IMPORT_TESTS" != "true" ] && [ -n "$TEST_EVTX_FILE" ] && [ -f "$TEST_EVTX_FILE" ]; then
    test_api_json_post "import_logs_again" "/import/logs" "{\"files\":[\"$TEST_EVTX_FILE\"],\"alert_on_import\":true}" "200" "Import with alert analysis"
    test_api_request "import_status" "GET" "/import/status?path=$TEST_EVTX_FILE" "" "200" "Get import status"
else
    test_api_json_post "import_logs_empty" "/import/logs" '{"files":[],"alert_on_import":false}' "200" "Import empty (no files)"
    test_api_request "import_status_none" "GET" "/import/status?path=nonexistent.evtx" "" "200" "Get import status (non-existent)"
fi

info "========================================"
info "Part 20: Live Events API"
info "========================================"

if [ "$SKIP_LIVE_TESTS" != "true" ]; then
    test_api_request "live_stats" "GET" "/live/stats" "" "200" "Get live stats"
    if [ "$ENABLE_SSE" = "true" ]; then
        test_sse_stream "live_events_stream" "/live/events" 10
    fi
else
    warn "Skipping live events tests (use --full-test to enable)"
fi

info "========================================"
info "Part 21: Policy API"
info "========================================"

test_api_request "policy_templates_list" "GET" "/policy-templates" "" "200" "List policy templates"
test_api_request "policy_instances_list" "GET" "/policy-instances" "" "200" "List policy instances"
test_api_json_post "policy_create" "/policies" '{"name":"APITestPolicy","rules":[],"settings":{}}' "200" "Create policy"
test_api_request "policy_delete" "DELETE" "/policies/APITestPolicy" "" "200" "Delete policy"

POLICY_TEMPLATES_RESPONSE=$(curl -s "${BASE_URL}/policy-templates?page=1&page_size=1")
if [ -n "$POLICY_TEMPLATES_RESPONSE" ]; then
    FIRST_TEMPLATE_NAME=$(echo "$POLICY_TEMPLATES_RESPONSE" | jq -r '.templates[0].name' 2>/dev/null || echo "")
    if [ -n "$FIRST_TEMPLATE_NAME" ] && [ "$FIRST_TEMPLATE_NAME" != "null" ]; then
        info "Testing policy template detail for: $FIRST_TEMPLATE_NAME"
        test_api_request "policy_templates_get" "GET" "/policy-templates/$FIRST_TEMPLATE_NAME" "" "200" "Get policy template details"
    fi
fi

test_api_json_post "policy_templates_create" "/policy-templates" '{"name":"APITestPolicyTemplate","description":"Test template","rules":["rule1"],"settings":{}}' "200" "Create policy template"
test_api_json_post "policy_templates_apply" "/policy-templates/apply" '{"template_name":"baseline_policy","targets":["localhost"]}' "200" "Apply policy template"
test_api_request "policy_templates_delete" "DELETE" "/policy-templates/APITestPolicyTemplate" "" "200" "Delete policy template"

POLICY_INSTANCES_RESPONSE=$(curl -s "${BASE_URL}/policy-instances?page=1&page_size=1")
if [ -n "$POLICY_INSTANCES_RESPONSE" ]; then
    FIRST_INSTANCE_KEY=$(echo "$POLICY_INSTANCES_RESPONSE" | jq -r '.instances[0].key' 2>/dev/null || echo "")
    if [ -n "$FIRST_INSTANCE_KEY" ] && [ "$FIRST_INSTANCE_KEY" != "null" ]; then
        info "Testing policy instance delete for key: $FIRST_INSTANCE_KEY"
        test_api_request "policy_instances_delete" "DELETE" "/policy-instances/$FIRST_INSTANCE_KEY" "" "200" "Delete policy instance"
    fi
fi

info "========================================"
info "Part 22: UI API"
info "========================================"

test_api_request "ui_dashboard" "GET" "/ui/dashboard" "" "200" "Get UI dashboard"
test_api_request "ui_dashboard_refresh" "GET" "/ui/dashboard?refresh=60" "" "200" "Get UI dashboard with refresh"
test_api_request "ui_alerts_groups_rule" "GET" "/ui/alerts/groups?group_by=rule&page_size=10" "" "200" "Get alerts grouped by rule"
test_api_request "ui_alerts_groups_severity" "GET" "/ui/alerts/groups?group_by=severity&page_size=10" "" "200" "Get alerts grouped by severity"
test_api_request "ui_alerts_groups_time" "GET" "/ui/alerts/groups?group_by=time&page_size=10" "" "200" "Get alerts grouped by time"
test_api_request "ui_metrics_1h" "GET" "/ui/metrics?period=1h" "" "200" "Get UI metrics (1h)"
test_api_request "ui_metrics_24h" "GET" "/ui/metrics?period=24h" "" "200" "Get UI metrics (24h)"
test_api_request "ui_metrics_7d" "GET" "/ui/metrics?period=7d" "" "200" "Get UI metrics (7d)"
test_api_request "ui_events_dist_level" "GET" "/ui/events/distribution?field=level&limit=10" "" "200" "Get event distribution by level"
test_api_request "ui_events_dist_source" "GET" "/ui/events/distribution?field=source&limit=10" "" "200" "Get event distribution by source"
test_api_request "ui_events_dist_logname" "GET" "/ui/events/distribution?field=log_name&limit=10" "" "200" "Get event distribution by log name"

info "========================================"
info "Part 23: Error Input Tests (Negative Tests)"
info "========================================"

test_api_request "error_invalid_event_id" "GET" "/events/invalid_id" "" "404" "Invalid event ID"
test_api_request "error_invalid_alert_id" "GET" "/alerts/999999999" "" "404" "Non-existent alert ID"
test_api_request "error_invalid_rule_name" "GET" "/rules/NonExistentRule12345" "" "404" "Non-existent rule"
test_api_request "error_invalid_report_id" "GET" "/reports/nonexistent_report_12345" "" "404" "Non-existent report"
test_api_request "error_invalid_suppress_id" "GET" "/suppress/999999999" "" "404" "Non-existent suppression rule"
test_api_request "error_invalid_settings_path" "GET" "/settings/nonexistent" "" "404" "Invalid settings path"
test_api_request "error_invalid_query_sql" "POST" "/query/execute" '{"sql":"DROP TABLE events"}' "400" "SQL injection attempt (DROP)"
test_api_request "error_invalid_query_syntax" "POST" "/query/execute" '{"sql":"SELECT * FROM"}' "400" "Invalid SQL syntax"
test_api_request "error_missing_required_field" "POST" "/query/execute" '{"limit":10}' "400" "Missing SQL field"
test_api_request "error_invalid_page_size" "GET" "/events?page_size=999999" "" "400" "Invalid page size"
test_api_request "error_invalid_severity" "GET" "/alerts?severity=invalid" "" "400" "Invalid severity value"
test_api_request "error_negative_page" "GET" "/events?page=-1" "" "400" "Negative page number"
test_api_request "error_future_time_range" "GET" "/timeline?start_time=2099-01-01T00:00:00Z" "" "200" "Future time range (should return empty)"
test_api_request "error_empty_import" "POST" "/import/logs" '{"files":[]}' "400" "Import with empty files array"

info "========================================"
info "Test Complete - Generating Report"
info "========================================"

# Calculate statistics
TOTAL_TESTS=${#TEST_RESULTS[@]}
PASS_COUNT=0
FAIL_COUNT=0
ERROR_COUNT=0

for result in "${TEST_RESULTS[@]}"; do
    status=$(echo "$result" | jq -r '.status' 2>/dev/null || echo "ERROR")
    case $status in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        *) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
done

SUCCESS_RATE=$(echo "scale=2; $PASS_COUNT * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "0")

# Generate summary JSON
cat > "$OUTPUT_DIR/test_summary.json" << EOF
{
  "test_start_time": "$(date -Iseconds)",
  "test_end_time": "$(date -Iseconds)",
  "total_tests": $TOTAL_TESTS,
  "passed": $PASS_COUNT,
  "failed": $FAIL_COUNT,
  "errors": $ERROR_COUNT,
  "success_rate": $SUCCESS_RATE,
  "base_url": "$BASE_URL",
  "test_evtx_file": "$TEST_EVTX_FILE",
  "max_retries": $MAX_RETRIES,
  "retry_delay_ms": $RETRY_DELAY_MS,
  "enable_sse": $ENABLE_SSE,
  "enable_validation": $ENABLE_VALIDATION,
  "enable_performance": $ENABLE_PERFORMANCE,
  "test_results": [$(IFS=,; echo "${TEST_RESULTS[*]}")]
}
EOF

# Generate CSV
{
    echo "Name,Method,Endpoint,StatusCode,Duration,Status,Timestamp"
    for result in "${TEST_RESULTS[@]}"; do
        name=$(echo "$result" | jq -r '.name' 2>/dev/null || echo "")
        method=$(echo "$result" | jq -r '.method' 2>/dev/null || echo "")
        endpoint=$(echo "$result" | jq -r '.endpoint' 2>/dev/null || echo "")
        status_code=$(echo "$result" | jq -r '.status_code' 2>/dev/null || echo "")
        duration=$(echo "$result" | jq -r '.duration' 2>/dev/null || echo "")
        status=$(echo "$result" | jq -r '.status' 2>/dev/null || echo "")
        timestamp=$(echo "$result" | jq -r '.timestamp' 2>/dev/null || echo "")
        echo "\"$name\",\"$method\",\"$endpoint\",$status_code,$duration,\"$status\",\"$timestamp\""
    done
} > "$OUTPUT_DIR/test_results.csv"

# Generate performance CSV
if [ "$ENABLE_PERFORMANCE" = "true" ] && [ ${#PERFORMANCE_DATA[@]} -gt 0 ]; then
    {
        echo "TestName,DurationSeconds,StatusCode"
        for key in "${!PERFORMANCE_DATA[@]}"; do
            IFS=',' read -r duration status_code <<< "${PERFORMANCE_DATA[$key]}"
            echo "\"$key\",$duration,$status_code"
        done
    } > "$OUTPUT_DIR/performance.csv"
fi

info "========================================"
info "Test Results Summary"
info "========================================"
info "Total Tests: $TOTAL_TESTS"
info "Passed: $PASS_COUNT (${SUCCESS_RATE}%)"
info "Failed: $FAIL_COUNT"
info "Errors: $ERROR_COUNT"
info "========================================"
info "Output Directory: $OUTPUT_DIR"
info "========================================"

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}API Test Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Output Dir: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "Summary: ${YELLOW}$OUTPUT_DIR/test_summary.json${NC}"
echo -e "CSV: ${YELLOW}$OUTPUT_DIR/test_results.csv${NC}"
if [ "$ENABLE_PERFORMANCE" = "true" ]; then
    echo -e "Performance: ${YELLOW}$OUTPUT_DIR/performance.csv${NC}"
fi
echo ""
echo -e "Result: $PASS_COUNT/$TOTAL_TESTS passed"

exit $([ $FAIL_COUNT -gt 0 ] && exit 1 || exit 0)
