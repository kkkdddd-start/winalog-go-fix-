#!/bin/bash
# WinLogAnalyzer-Go CLI Full Functionality Test Script (Linux Version)
# Usage: ./cli_test.sh [OPTIONS]
#
# Options:
#   -p, --winalog-path PATH   Path to winalog binary (default: ./winalog)
#   -o, --output-dir DIR      Output directory (default: ./cli_test_results)
#   -e, --evtx-file FILE      EVTX file for import tests
#   --full-test               Full test with all features
#   --test-import             Enable import tests
#   --test-live               Enable live monitoring tests
#   --test-tui                Enable TUI tests
#   -h, --help                Show this help

set -e

# Default values
WINALOG_PATH="./winalog"
OUTPUT_DIR="./cli_test_results_$(date +%Y%m%d_%H%M%S)"
TEST_EVTX_FILE=""
FULL_TEST=false
TEST_IMPORT=false
TEST_LIVE=false
TEST_TUI=false
MAX_SEARCH_RESULTS=100

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Arrays for storing results
declare -a TEST_RESULTS=()

# Functions
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo -e "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$OUTPUT_DIR/test_execution.log"
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
    )

    for path in "${search_paths[@]}"; do
        local files=$(ls $path 2>/dev/null || true)
        if [ -n "$files" ]; then
            echo "$files" | head -1
            return 0
        fi
    done
    return 1
}

test_command() {
    local name="$1"
    local args="$2"
    local description="${3:-}"
    local expected_exit="${4:-0}"
    local allow_nonzero="${5:-false}"

    info "Executing: $name"
    info "Args: $args"
    [ -n "$description" ] && info "Desc: $description"

    local output_file="$OUTPUT_DIR/command_outputs/${name}.txt"
    local output_file_err="$OUTPUT_DIR/command_outputs/${name}.err"
    local start_time=$(date +%s.%N)

    mkdir -p "$OUTPUT_DIR/command_outputs"

    local exit_code=0
    local output=""
    local error_output=""

    if [ -n "$args" ]; then
        $WINALOG_PATH $args > "$output_file" 2> "$output_file_err" || exit_code=$?
    else
        $WINALOG_PATH > "$output_file" 2> "$output_file_err" || exit_code=$?
    fi

    local duration=$(echo "$(date +%s.%N) - $start_time" | bc)

    if [ -f "$output_file" ]; then
        output=$(cat "$output_file" 2>/dev/null || echo "")
    fi

    if [ -f "$output_file_err" ]; then
        error_output=$(cat "$output_file_err" 2>/dev/null || echo "")
        if [ -n "$error_output" ]; then
            output="$output\n[STDERR]\n$error_output"
        fi
    fi

    local status="FAIL"
    if [ "$allow_nonzero" = "true" ]; then
        [ "$exit_code" -eq 0 ] || [ "$exit_code" -eq 255 ] && status="PASS"
    else
        [ "$exit_code" -eq "$expected_exit" ] && status="PASS"
    fi

    if [ "$status" = "PASS" ]; then
        pass "Status: PASS (ExitCode: $exit_code, Duration: ${duration}s)"
    else
        fail "Status: FAIL (ExitCode: $exit_code, Expected: $expected_exit)"
    fi

    local test_result="{\"name\":\"$name\",\"args\":\"$args\",\"description\":\"$description\",\"exit_code\":$exit_code,\"duration\":$duration,\"status\":\"$status\",\"timestamp\":\"$(date -Iseconds)\"}"
    TEST_RESULTS+=("$test_result")

    echo "---"
}

get_version() {
    $WINALOG_PATH --version 2>&1 || echo "Unknown"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--winalog-path)
            WINALOG_PATH="$2"
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
        --full-test)
            FULL_TEST=true
            TEST_IMPORT=true
            TEST_LIVE=true
            shift
            ;;
        --test-import)
            TEST_IMPORT=true
            shift
            ;;
        --test-live)
            TEST_LIVE=true
            shift
            ;;
        --test-tui)
            TEST_TUI=true
            shift
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

# Create output directories
mkdir -p "$OUTPUT_DIR/command_outputs"
mkdir -p "$OUTPUT_DIR/screenshots"
mkdir -p "$OUTPUT_DIR/exports"
mkdir -p "$OUTPUT_DIR/reports"
mkdir -p "$OUTPUT_DIR/logs"
touch "$OUTPUT_DIR/test_execution.log"

info "========================================"
info "WinLogAnalyzer-Go CLI Full Function Test (Linux)"
info "========================================"

info "Hostname: $(hostname)"
info "User: $(whoami)"
info "OS: $(uname -s) $(uname -r)"
info "WinLogAnalyzer Version: $(get_version)"
info "Test Start Time: $(date -Iseconds)"

# Save system info
cat > "$OUTPUT_DIR/system_info.json" << EOF
{
  "hostname": "$(hostname)",
  "user": "$(whoami)",
  "os": "$(uname -s)",
  "os_version": "$(uname -r)",
  "architecture": "$(uname -m)",
  "test_start_time": "$(date -Iseconds)",
  "winalog_version": "$(get_version)"
}
EOF

# Check if winalog exists
if [ ! -f "$WINALOG_PATH" ]; then
    error "Cannot find winalog at $WINALOG_PATH"
    exit 1
fi

info "========================================"
info "Part 1: Help and Version"
info "========================================"

test_command "help" "--help" "Show full help"
test_command "version" "--version" "Show version"

info "========================================"
info "Part 2: Status and System Info"
info "========================================"

test_command "status" "status" "Show system status"
test_command "info" "info" "Show system info"
test_command "info_process" "info --process" "Show process info"
test_command "info_network" "info --network" "Show network connections"
test_command "info_users" "info --users" "Show local users"
test_command "info_registry" "info --registry" "Show registry persistence"
test_command "info_tasks" "info --tasks" "Show scheduled tasks"
test_command "info_save" "info --save" "Save system info to DB"
test_command "info_all" "info --process --network --users --registry --tasks" "Show all system info"

info "========================================"
info "Part 3: Database Operations"
info "========================================"

test_command "db_status" "db status" "Show DB status"
test_command "db_clean" "db clean" "Clean old data (90 days)"
test_command "db_clean_30" "db clean --days 30" "Clean 30 days data"
test_command "metrics" "metrics" "Show Prometheus metrics"

info "========================================"
info "Part 3.5: Forensic Collection"
info "========================================"
info "NOTE: Collect tests are skipped on Linux (requires Windows)"

info "========================================"
info "Part 4: Rules Management"
info "========================================"

test_command "rules_list" "rules list" "List all rules"
test_command "rules_status" "rules status" "Show rules status"
test_command "rules_status_detail" "rules status failed-login-threshold" "Show specific rule status"
info "Skipping rules_validate (requires rule file parameter)"
test_command "rules_disable" "rules disable failed-login-threshold" "Disable rule"
test_command "rules_enable" "rules enable failed-login-threshold" "Enable rule"

info "========================================"
info "Part 5: Alert Management"
info "========================================"

test_command "alert_list" "alert list" "List alerts"
test_command "alert_list_json" "alert list --format json --limit 20" "List alerts in JSON"
test_command "alert_stats" "alert stats" "Show alert stats"
test_command "alert_list_high" "alert list --severity high --limit 10" "List high severity alerts"
test_command "alert_list_medium" "alert list --severity medium --limit 10" "List medium severity alerts"
test_command "alert_list_resolved" "alert list --resolved --limit 10" "List resolved alerts"
test_command "alert_run" "alert run" "Run alert analysis"
test_command "alert_run_batch" "alert run --batch-size 1000" "Run alert analysis with batch"
test_command "alert_export" "alert export $OUTPUT_DIR/alerts_export.json --format json" "Export alerts"

info "========================================"
info "Part 6: Search Function"
info "========================================"

test_command "search_basic" "search" "Basic search (all events)"
test_command "search_level4" "search --level 4 --limit $MAX_SEARCH_RESULTS" "Search info level events"
test_command "search_page" "search --page 1 --page-size 50" "Paged search"
test_command "search_sort" "search --sort-by timestamp --sort-order desc --limit 20" "Sorted search"
test_command "search_keywords" "search --keywords system --limit 20" "Keyword search"
test_command "search_event_id" "search --event-id 4624,4625 --limit 20" "Search by event ID"
test_command "search_regex" "search --regex --keywords 4624" "Regex search"
test_command "search_time_range" "search --start-time 2024-01-01T00:00:00Z --end-time 2024-12-31T23:59:59Z --limit 20" "Time range search"
test_command "search_computer" "search --computer localhost --limit 20" "Search by computer"
test_command "search_user" "search --user Administrator --limit 20" "Search by user"
test_command "search_log_name" "search --log-name Security --limit 20" "Search by log name"

info "========================================"
info "Part 7: Import Function"
info "========================================"

if [ "$TEST_IMPORT" = "true" ]; then
    if [ -z "$TEST_EVTX_FILE" ]; then
        info "Auto-searching for EVTX files..."
        TEST_EVTX_FILE=$(find_evtx_files)
        if [ -n "$TEST_EVTX_FILE" ]; then
            info "Found EVTX file: $TEST_EVTX_FILE"
        else
            warn "No EVTX files found in search paths"
        fi
    fi

    if [ -n "$TEST_EVTX_FILE" ] && [ -f "$TEST_EVTX_FILE" ]; then
        info "Using test file: $TEST_EVTX_FILE"
        test_command "import" "import \"$TEST_EVTX_FILE\" --log-name TestImport --workers 4" "Import EVTX file"
        test_command "search_after_import" "search --log-name TestImport --limit 50" "Search imported events"
    else
        warn "Skipping import test (no valid EVTX file)"
        info "Tip: Use -e or --evtx-file to specify a file manually"
    fi
else
    warn "Skipping import test (use --test-import to enable)"
fi

info "========================================"
info "Part 8: Export Function"
info "========================================"

test_command "export_json" "export json $OUTPUT_DIR/exports/events.json --limit 100" "Export to JSON"
test_command "export_csv" "export csv $OUTPUT_DIR/exports/events.csv --limit 100" "Export to CSV"

info "========================================"
info "Part 9: Report Generation"
info "========================================"

test_command "report_list" "report" "List reports"
test_command "report_generate_summary" "report generate summary --format json --output $OUTPUT_DIR/reports/summary.json" "Generate summary report"
test_command "report_generate_security" "report generate security --format json --output $OUTPUT_DIR/reports/security.json --time-range 24h" "Generate security report"
test_command "report_generate_threat" "report generate threat --format json --output $OUTPUT_DIR/reports/threat.json --time-range 24h" "Generate threat report"
test_command "report_generate_compliance" "report generate compliance --format json --output $OUTPUT_DIR/reports/compliance.json --time-range 24h" "Generate compliance report"
test_command "report_generate_html" "report generate security --format html --output $OUTPUT_DIR/reports/security.html" "Generate HTML report"

info "========================================"
info "Part 10: Timeline Analysis"
info "========================================"

test_command "timeline_query" "timeline query --limit 50" "Query timeline"
test_command "timeline_query_time" "timeline query --start 2024-01-01T00:00:00Z --end 2024-12-31T23:59:59Z --limit 50" "Time range query"
test_command "timeline_query_category" "timeline query --category Security --limit 50" "Query by category"
test_command "timeline_query_computer" "timeline query --computer localhost --limit 50" "Query by computer"
test_command "timeline_build" "timeline build" "Build timeline index"

info "========================================"
info "Part 11: Threat Analysis"
info "========================================"

test_command "analyze_list" "analyze list" "List analyzers"
test_command "analyze_bruteforce" "analyze brute_force --hours 24" "Brute force analysis"
test_command "analyze_login" "analyze login --hours 24" "Login analysis"
test_command "analyze_kerberos" "analyze kerberos --hours 24" "Kerberos analysis"
test_command "analyze_powershell" "analyze powershell --hours 24" "PowerShell analysis"
test_command "analyze_data_exfiltration" "analyze data_exfiltration --hours 24" "Data exfiltration analysis"
test_command "analyze_lateral_movement" "analyze lateral_movement --hours 24" "Lateral movement analysis"
test_command "analyze_privilege_escalation" "analyze privilege_escalation --hours 24" "Privilege escalation analysis"
test_command "analyze_persistence" "analyze persistence --hours 24" "Persistence analysis"
test_command "analyze_time_window" "analyze --time-window 72h --format json" "Analysis with time window"
test_command "analyze_output" "analyze --output $OUTPUT_DIR/analysis.json --format json" "Analysis output to file"

info "========================================"
info "Part 12: Correlation Analysis"
info "========================================"

test_command "correlate" "correlate --time-window 24h" "Correlation analysis"
test_command "correlate_json" "correlate --format json --output $OUTPUT_DIR/correlation.json" "Correlation analysis (JSON)"
test_command "correlate_48h" "correlate --time-window 48h" "Correlation analysis (48h)"
test_command "correlate_rules" "correlate --rules LateralMovement,BruteForce --time-window 24h" "Correlation with specific rules"

info "========================================"
info "Part 13: Multi-Machine Analysis"
info "========================================"

test_command "multi_analyze" "multi analyze" "Multi-machine analysis"
test_command "multi_analyze_48h" "multi analyze --time-window 48h" "Multi-machine analysis (48h)"
test_command "multi_lateral" "multi lateral" "Lateral movement detection"

info "========================================"
info "Part 14: UEBA Analysis"
info "========================================"

test_command "ueba_profiles" "ueba profiles" "Show user profiles"
test_command "ueba_profiles_user" "ueba profiles --user Administrator" "Show specific user profile"
test_command "ueba_analyze" "ueba analyze --hours 24" "UEBA analysis"
test_command "ueba_analyze_save" "ueba analyze --hours 24 --save-alerts" "UEBA analysis and save alerts"
test_command "ueba_analyze_7d" "ueba analyze -H 168" "UEBA analysis (7 days)"
test_command "ueba_baseline" "ueba baseline" "Show user baseline"
test_command "ueba_baseline_learn" "ueba baseline --action learn --hours 168" "Learn user baseline"
test_command "ueba_baseline_clear" "ueba baseline --action clear" "Clear user baseline"

info "========================================"
info "Part 15: Real-time Monitoring"
info "========================================"

if [ "$TEST_LIVE" = "true" ]; then
    info "Starting real-time monitoring test (5 seconds)"
    test_command "live_collect" "live collect" "Real-time event collection" "0" "true"
else
    warn "Skipping real-time monitoring test (requires --test-live flag)"
fi

info "========================================"
info "Part 16: Forensics"
info "========================================"

test_command "forensics_hash_notepad" "forensics hash /etc/hosts" "Calculate /etc/hosts hash"
test_command "forensics_verify_notepad" "forensics verify /etc/hosts" "Verify /etc/hosts signature"
test_command "forensics_collect" "forensics collect" "Collect forensics data"

info "========================================"
info "Part 17: Persistence Detection"
info "========================================"

test_command "persistence_detect" "persistence detect" "Detect all persistence mechanisms"
test_command "persistence_detect_json" "persistence detect --format json --output $OUTPUT_DIR/persistence.json" "Detect persistence (JSON)"
test_command "persistence_categories" "persistence detect --category registry" "Detect registry persistence"
test_command "persistence_category_wmi" "persistence detect --category WMI" "Detect WMI persistence"
test_command "persistence_category_service" "persistence detect --category Service" "Detect service persistence"
test_command "persistence_category_scheduled" "persistence detect --category ScheduledTask" "Detect scheduled task persistence"
test_command "persistence_technique" "persistence detect --technique T1546.003" "Detect specific MITRE technique"
test_command "persistence_technique2" "persistence detect --technique T1547.001" "Detect T1547.001 technique"
test_command "persistence_text" "persistence detect --format text" "Text format output"
test_command "persistence_progress" "persistence detect --progress" "Show detection progress"

info "========================================"
info "Part 18: Whitelist Management"
info "========================================"

test_command "whitelist_list" "whitelist list" "List whitelist"
test_command "whitelist_add" "whitelist add TestRule001 --event-id 4624 --reason Test --scope global --duration 1440 --enabled" "Add whitelist rule"
test_command "whitelist_add_user" "whitelist add TestRule002 --event-id 4625 --reason Test --scope user --duration 60 --enabled" "Add user scope whitelist"
test_command "whitelist_add_computer" "whitelist add TestRule003 --event-id 4672 --reason Test --scope computer --duration 0 --enabled" "Add computer scope whitelist"
test_command "whitelist_list_after" "whitelist list" "List whitelist (after add)"
test_command "whitelist_remove" "whitelist remove TestRule001" "Remove whitelist rule"
test_command "whitelist_remove2" "whitelist remove TestRule002" "Remove second whitelist"
test_command "whitelist_remove3" "whitelist remove TestRule003" "Remove third whitelist"

info "========================================"
info "Part 19: Config Management"
info "========================================"

test_command "config_get_all" "config get" "Get all config"
test_command "config_get_retention" "config get alert.retention_days" "Get retention config"
test_command "config_set_retention" "config set alert.retention_days 180" "Set retention"
test_command "config_get_retention_after" "config get alert.retention_days" "Verify retention set"
test_command "config_set_restore" "config set alert.retention_days 90" "Restore default retention"

info "========================================"
info "Part 20: SQL Query"
info "========================================"

test_command "query_count" 'query "SELECT COUNT(*) FROM events"' "Count events"
test_command "query_events" 'query "SELECT * FROM events LIMIT 10"' "Query events"
test_command "query_rules" 'query "SELECT name, enabled FROM rules LIMIT 10"' "Query rules"
test_command "query_alerts" 'query "SELECT * FROM alerts LIMIT 10"' "Query alerts"
test_command "query_pragma" 'query "PRAGMA table_info(events)"' "View table schema"

info "========================================"
info "Part 21: Dashboard"
info "========================================"

test_command "dashboard" "dashboard" "Show dashboard"
test_command "dashboard_json" "dashboard --format json" "Dashboard (JSON)"

info "========================================"
info "Part 22: Database Maintenance"
info "========================================"

test_command "db_vacuum" "db vacuum" "Database VACUUM"
test_command "db_status_after" "db status" "Database status (after)"

info "========================================"
info "Part 23: File Verification"
info "========================================"

test_command "verify_calc" "verify /bin/ls" "Verify ls"
test_command "verify_cmd" "verify /bin/bash" "Verify bash"
test_command "verify_powershell" "verify /usr/bin/zsh" "Verify zsh"
test_command "verify_batch" "verify /bin/ls /bin/bash" "Batch verify files"

info "========================================"
info "Part 24: EVTX Conversion"
info "========================================"

if [ -z "$TEST_EVTX_FILE" ]; then
    info "Auto-searching for EVTX files for conversion test..."
    TEST_EVTX_FILE=$(find_evtx_files)
    if [ -n "$TEST_EVTX_FILE" ]; then
        info "Found EVTX file: $TEST_EVTX_FILE"
    fi
fi

if [ -n "$TEST_EVTX_FILE" ] && [ -f "$TEST_EVTX_FILE" ]; then
    info "Testing EVTX to CSV: $TEST_EVTX_FILE"
    test_command "evtx2csv" "evtx2csv \"$TEST_EVTX_FILE\" \"$OUTPUT_DIR/exports/converted.csv\" --limit 500" "EVTX to CSV"

    if [ -f "$OUTPUT_DIR/exports/converted.csv" ]; then
        local csv_preview
        csv_preview=$(head -10 "$OUTPUT_DIR/exports/converted.csv" 2>/dev/null || echo "")
        info "CSV Preview: $csv_preview"
    fi
else
    warn "Skipping EVTX conversion test (no valid file)"
fi

info "========================================"
info "Part 25: TUI Interface"
info "========================================"

info "TUI test: Testing startup with timeout"
local start_time_tui=$(date +%s.%N)

timeout 3 $WINALOG_PATH tui > /dev/null 2>&1 &
local tui_pid=$!

sleep 1

if kill -0 $tui_pid 2>/dev/null; then
    kill $tui_pid 2>/dev/null || true
    pass "Status: PASS (TUI started successfully)"
    local tui_status="PASS"
else
    fail "Status: FAIL (TUI exited immediately)"
    local tui_status="FAIL"
fi

local tui_duration=$(echo "$(date +%s.%N) - $start_time_tui" | bc)
TEST_RESULTS+=("{\"name\":\"tui_start\",\"args\":\"tui\",\"description\":\"TUI interface startup\",\"exit_code\":0,\"duration\":$tui_duration,\"status\":\"$tui_status\",\"timestamp\":\"$(date -Iseconds)\"}")

info "========================================"
info "Part 26: API Service"
info "========================================"

info "Starting API service test (background for 5 seconds)"
local serve_port=18080
local serve_output_file="$OUTPUT_DIR/command_outputs/serve_test.log"
local serve_err_file="$OUTPUT_DIR/command_outputs/serve_test.err"
local serve_start_time=$(date +%s.%N)

$WINALOG_PATH serve --port $serve_port > "$serve_output_file" 2> "$serve_err_file" &
local serve_pid=$!

sleep 5

if kill -0 $serve_pid 2>/dev/null; then
    pass "API service started successfully (PID: $serve_pid)"

    test_command "api_health" "query health" "API health check"
    test_command "api_stats" "stats" "API stats endpoint"

    kill $serve_pid 2>/dev/null || true
    wait $serve_pid 2>/dev/null || true
    info "API service stopped"

    local serve_duration=$(echo "$(date +%s.%N) - $serve_start_time" | bc)
    TEST_RESULTS+=("{\"name\":\"serve_start\",\"args\":\"serve --port $serve_port\",\"description\":\"API service startup\",\"exit_code\":0,\"duration\":$serve_duration,\"status\":\"PASS\",\"timestamp\":\"$(date -Iseconds)\"}")
else
    fail "API service failed to start, exit code: $?"
    if [ -f "$serve_err_file" ]; then
        local err_content
        err_content=$(cat "$serve_err_file" 2>/dev/null || echo "")
        error "Error output: $err_content"
    fi

    local serve_duration=$(echo "$(date +%s.%N) - $serve_start_time" | bc)
    TEST_RESULTS+=("{\"name\":\"serve_start\",\"args\":\"serve --port $serve_port\",\"description\":\"API service startup\",\"exit_code\":1,\"duration\":$serve_duration,\"status\":\"FAIL\",\"timestamp\":\"$(date -Iseconds)\"}")
fi

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
  "winalog_path": "$WINALOG_PATH",
  "test_evtx_file": "$TEST_EVTX_FILE",
  "test_results": [$(IFS=,; echo "${TEST_RESULTS[*]}")]
}
EOF

# Generate CSV
{
    echo "CommandName,Arguments,Description,ExitCode,DurationSeconds,Status,Timestamp,OutputFile"
    for result in "${TEST_RESULTS[@]}"; do
        name=$(echo "$result" | jq -r '.name' 2>/dev/null || echo "")
        args=$(echo "$result" | jq -r '.args' 2>/dev/null || echo "")
        description=$(echo "$result" | jq -r '.description' 2>/dev/null || echo "")
        exit_code=$(echo "$result" | jq -r '.exit_code' 2>/dev/null || echo "")
        duration=$(echo "$result" | jq -r '.duration' 2>/dev/null || echo "")
        status=$(echo "$result" | jq -r '.status' 2>/dev/null || echo "")
        timestamp=$(echo "$result" | jq -r '.timestamp' 2>/dev/null || echo "")
        output_file="$OUTPUT_DIR/command_outputs/${name}.txt"
        echo "\"$name\",\"$args\",\"$description\",$exit_code,$duration,\"$status\",\"$timestamp\",\"$output_file\""
    done
} > "$OUTPUT_DIR/test_results.csv"

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
echo -e "${GREEN}CLI Test Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Output Dir: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "Details: ${YELLOW}$OUTPUT_DIR/test_summary.json${NC}"
echo -e "CSV: ${YELLOW}$OUTPUT_DIR/test_results.csv${NC}"
echo ""
echo -e "Result: $PASS_COUNT/$TOTAL_TESTS passed"

exit $([ $FAIL_COUNT -gt 0 ] && exit 1 || exit 0)
