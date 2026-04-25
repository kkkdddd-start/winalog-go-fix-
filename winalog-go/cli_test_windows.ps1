# WinLogAnalyzer-Go CLI Test Script
# Tests all CLI commands and records raw data
# Usage: powershell -ExecutionPolicy Bypass -File cli_test_windows.ps1

param(
    [string]$WinalogPath = ".\winalog.exe",
    [string]$OutputDir = ".\cli_test_results",
    [string]$TestEvtxFile = "",
    [switch]$SkipImport = $false,
    [switch]$SkipLive = $false,
    [switch]$SkipTUI = $false
)

$ErrorActionPreference = "Continue"
$Script:TestResults = @()
$Script:TestStartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path "$OutputDir\test_log.txt" -Value $logMessage
}

function Test-Command {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Description,
        [int]$ExpectedExitCode = 0
    )
    
    Write-TestLog "Test: $Name"
    Write-TestLog "Command: $Command"
    Write-TestLog "Description: $Description"
    
    $outputFile = "$OutputDir\$($Name -replace '[^\w]', '_').txt"
    $errorFile = "$OutputDir\$($Name -replace '[^\w]', '_')_error.txt"
    
    $startTime = Get-Date
    
    try {
        if ($Command -match '\|') {
            $scriptBlock = [scriptblock]::Create($Command)
            $result = & $scriptBlock 2>&1
            $exitCode = $LASTEXITCODE
            $output = $result | Out-String
        } else {
            $output = & $WinalogPath $Command 2>&1
            $exitCode = $LASTEXITCODE
        }
        
        $duration = (Get-Date) - $startTime
        
        $output | Out-File -FilePath $outputFile -Encoding UTF8
        if ($exitCode -ne 0) {
            $output | Out-File -FilePath $errorFile -Encoding UTF8
        }
        
        $status = if ($exitCode -eq $ExpectedExitCode) { "PASS" } else { "FAIL" }
        
        $testResult = @{
            Name = $Name
            Command = "$WinalogPath $Command"
            Description = $Description
            ExitCode = $exitCode
            ExpectedExitCode = $ExpectedExitCode
            Duration = $duration.TotalSeconds
            Status = $status
            OutputFile = $outputFile
            ErrorFile = $errorFile
            Timestamp = $startTime
        }
        
        Write-TestLog "Status: $status (ExitCode: $exitCode, Duration: $($duration.TotalSeconds)s)"
        Write-TestLog "Output: $outputFile"
        
        if ($status -eq "FAIL") {
            Write-TestLog "Error output: $errorFile" "WARN"
        }
        
        $Script:TestResults += $testResult
        
        return $status -eq "PASS"
    }
    catch {
        $duration = (Get-Date) - $startTime
        Write-TestLog "Exception: $($_.Exception.Message)" "ERROR"
        
        $testResult = @{
            Name = $Name
            Command = "$WinalogPath $Command"
            Description = $Description
            ExitCode = -1
            ExpectedExitCode = $ExpectedExitCode
            Duration = $duration.TotalSeconds
            Status = "ERROR"
            Error = $_.Exception.Message
            Timestamp = $startTime
        }
        
        $Script:TestResults += $testResult
        return $false
    }
}

function Find-EvtxFiles {
    $searchPaths = @(
        "$env:USERPROFILE\Desktop\*.evtx",
        "$env:USERPROFILE\Documents\*.evtx",
        "$env:USERPROFILE\Downloads\*.evtx",
        ".\*.evtx",
        ".\test_data\*.evtx",
        ".\test_files\*.evtx",
        ".\data\*.evtx",
        "$env:SystemRoot\System32\winevt\Logs\*.evtx"
    )
    
    $foundFiles = @()
    
    foreach ($path in $searchPaths) {
        $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
        if ($files) {
            $foundFiles += $files
        }
    }
    
    if ($foundFiles.Count -gt 0) {
        $sortedFiles = $foundFiles | Sort-Object LastWriteTime -Descending
        return $sortedFiles[0].FullName
    }
    
    return $null
}

function Find-AllEvtxFiles {
    $searchPaths = @(
        "$env:USERPROFILE\Desktop\*.evtx",
        "$env:USERPROFILE\Documents\*.evtx",
        "$env:USERPROFILE\Downloads\*.evtx",
        ".\*.evtx",
        ".\test_data\*.evtx",
        ".\test_files\*.evtx",
        ".\data\*.evtx",
        "$env:SystemRoot\System32\winevt\Logs\*.evtx"
    )
    
    $foundFiles = @()
    
    foreach ($path in $searchPaths) {
        $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
        if ($files) {
            $foundFiles += $files
        }
    }
    
    if ($foundFiles.Count -gt 0) {
        return ($foundFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 10)
    }
    
    return $null
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-TestLog "========================================" "INFO"
Write-TestLog "WinLogAnalyzer-Go CLI Test" "INFO"
Write-TestLog "========================================" "INFO"
Write-TestLog "Start Time: $Script:TestStartTime" "INFO"

if (-not $SkipImport) {
    if (-not $TestEvtxFile) {
        Write-TestLog "Auto-searching for EVTX files..." "INFO"
        $foundFile = Find-EvtxFiles
        if ($foundFile) {
            $TestEvtxFile = $foundFile
            Write-TestLog "Found EVTX file: $TestEvtxFile" "SUCCESS"
        } else {
            Write-TestLog "No EVTX files found in search paths" "WARN"
        }
    }
}

if (-not (Test-Path $WinalogPath)) {
    Write-TestLog "Error: Cannot find winalog.exe at $WinalogPath" "ERROR"
    exit 1
}

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 1: Help and Version" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "help" -Command "--help" -Description "Show help"
Test-Command -Name "version" -Command "--version" -Description "Show version"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 2: Status and System Info" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "status" -Command "status" -Description "Show system status"
Test-Command -Name "info" -Command "info" -Description "Show system info"
Test-Command -Name "info_process" -Command "info --process" -Description "Show process info"
Test-Command -Name "info_network" -Command "info --network" -Description "Show network connections"
Test-Command -Name "info_users" -Command "info --users" -Description "Show user list"
Test-Command -Name "info_registry" -Command "info --registry" -Description "Show registry persistence"
Test-Command -Name "info_tasks" -Command "info --tasks" -Description "Show scheduled tasks"
Test-Command -Name "info_save" -Command "info --save" -Description "Save system info"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 3: Database Operations" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "db_status" -Command "db status" -Description "Show database status"
Test-Command -Name "db_clean" -Command "db clean --days 365" -Description "Clean old data"
Test-Command -Name "db_vacuum" -Command "db vacuum" -Description "Optimize database"
Test-Command -Name "metrics" -Command "metrics" -Description "Show Prometheus metrics"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 4: Rules Management" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "rules_list" -Command "rules list" -Description "List all rules"
Test-Command -Name "rules_status" -Command "rules status" -Description "Show rules status"
Test-Command -Name "rules_status_detail" -Command "rules status brute-force-attack" -Description "Show specific rule"
Test-Command -Name "rules_disable" -Command "rules disable brute-force-attack" -Description "Disable rule"
Test-Command -Name "rules_enable" -Command "rules enable brute-force-attack" -Description "Enable rule"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 5: Alert Management" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "alert_list" -Command "alert list" -Description "List alerts"
Test-Command -Name "alert_stats" -Command "alert stats" -Description "Show alert stats"
Test-Command -Name "alert_list_json" -Command "alert list --format json" -Description "List alerts in JSON"
Test-Command -Name "alert_list_limit" -Command "alert list --limit 10" -Description "Limit alert count"
Test-Command -Name "alert_list_high" -Command "alert list --severity high" -Description "List high severity alerts"
Test-Command -Name "alert_run" -Command "alert run" -Description "Run alert analysis"
Test-Command -Name "alert_export" -Command "alert export $OutputDir\alerts.json --format json" -Description "Export alerts"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 6: Search Function" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "search_empty" -Command "search" -Description "Empty search"
Test-Command -Name "search_level" -Command "search --level 4" -Description "Filter by level"
Test-Command -Name "search_page" -Command "search --page 1 --page-size 10" -Description "Paged search"
Test-Command -Name "search_keywords" -Command "search --keywords system --page-size 20" -Description "Keyword search"
Test-Command -Name "search_event_id" -Command "search --event-id 4624 --page-size 20" -Description "Search by event ID"
Test-Command -Name "search_regex" -Command "search --regex --keywords 4624" -Description "Regex search"
Test-Command -Name "search_time" -Command "search --start-time 2024-01-01T00:00:00Z --end-time 2024-12-31T23:59:59Z" -Description "Time range search"
Test-Command -Name "search_computer" -Command "search --computer localhost" -Description "Search by computer"
Test-Command -Name "search_user" -Command "search --user Administrator" -Description "Search by user"
Test-Command -Name "search_logname" -Command "search --log-name Security" -Description "Search by log name"

if (-not $SkipImport -and $TestEvtxFile -and (Test-Path $TestEvtxFile)) {
    Write-TestLog "========================================" "INFO"
    Write-TestLog "Part 7: Import Function" "INFO"
    Write-TestLog "========================================" "INFO"
    
    $importCmd = "import `"$TestEvtxFile`" --log-name TestLog --workers 4"
    Test-Command -Name "import_evtx" -Command $importCmd -Description "Import EVTX file"
    Test-Command -Name "search_after_import" -Command "search --log-name TestLog" -Description "Search imported events"
}

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 8: Export Function" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "export_json" -Command "export json $OutputDir\events.json --limit 100" -Description "Export to JSON"
Test-Command -Name "export_csv" -Command "export csv $OutputDir\events.csv --limit 100" -Description "Export to CSV"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 9: Report Generation" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "report_list" -Command "report" -Description "List reports"
Test-Command -Name "report_summary" -Command "report generate summary --format json --time-range 24h" -Description "Generate summary report"
Test-Command -Name "report_security" -Command "report generate security --format json --time-range 24h" -Description "Generate security report"
Test-Command -Name "report_threat" -Command "report generate threat --format json --time-range 24h" -Description "Generate threat report"
Test-Command -Name "report_compliance" -Command "report generate compliance --format json --time-range 24h" -Description "Generate compliance report"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 10: Timeline Analysis" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "timeline_query" -Command "timeline query" -Description "Query timeline"
Test-Command -Name "timeline_query_time" -Command "timeline query --start 2024-01-01T00:00:00Z --end 2024-12-31T23:59:59Z" -Description "Time range query"
Test-Command -Name "timeline_query_category" -Command "timeline query --category Security" -Description "Query by category"
Test-Command -Name "timeline_build" -Command "timeline build" -Description "Build timeline"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 11: Threat Analysis" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "analyze_list" -Command "analyze list" -Description "List analyzers"
Test-Command -Name "analyze_bruteforce" -Command "analyze brute_force --hours 24" -Description "Brute force analysis"
Test-Command -Name "analyze_login" -Command "analyze login --hours 24" -Description "Login analysis"
Test-Command -Name "analyze_kerberos" -Command "analyze kerberos --hours 24" -Description "Kerberos analysis"
Test-Command -Name "analyze_powershell" -Command "analyze powershell --hours 24" -Description "PowerShell analysis"
Test-Command -Name "analyze_data_exfiltration" -Command "analyze data_exfiltration --hours 24" -Description "Data exfiltration analysis"
Test-Command -Name "analyze_lateral_movement" -Command "analyze lateral_movement --hours 24" -Description "Lateral movement analysis"
Test-Command -Name "analyze_privilege_escalation" -Command "analyze privilege_escalation --hours 24" -Description "Privilege escalation analysis"
Test-Command -Name "analyze_persistence" -Command "analyze persistence --hours 24" -Description "Persistence analysis"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 12: Correlation Analysis" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "correlate" -Command "correlate --time-window 24h" -Description "Correlation analysis"
Test-Command -Name "correlate_json" -Command "correlate --format json --time-window 24h" -Description "Correlation analysis (JSON)"
Test-Command -Name "correlate_rules" -Command "correlate --rules LateralMovement,BruteForce" -Description "Correlation with rules"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 13: Multi-Machine Analysis" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "multi_analyze" -Command "multi analyze" -Description "Multi-machine analysis"
Test-Command -Name "multi_lateral" -Command "multi lateral" -Description "Lateral movement detection"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 14: UEBA Analysis" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "ueba_profiles" -Command "ueba profiles" -Description "Show user profiles"
Test-Command -Name "ueba_analyze" -Command "ueba analyze --hours 24" -Description "UEBA analysis"
Test-Command -Name "ueba_analyze_save" -Command "ueba analyze --hours 24 --save-alerts" -Description "UEBA with alerts"
Test-Command -Name "ueba_baseline" -Command "ueba baseline" -Description "Show user baseline"
Test-Command -Name "ueba_baseline_learn" -Command "ueba baseline --action learn --hours 168" -Description "Learn baseline"
Test-Command -Name "ueba_baseline_clear" -Command "ueba baseline --action clear" -Description "Clear baseline"

if (-not $SkipLive) {
    Write-TestLog "========================================" "INFO"
    Write-TestLog "Part 15: Real-time Monitoring" "INFO"
    Write-TestLog "========================================" "INFO"
    
    Test-Command -Name "live_collect" -Command "live collect" -Description "Real-time monitoring" -ExpectedExitCode -1
}

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 16: Forensics" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "forensics_hash" -Command "forensics hash `"$env:SystemRoot\system32\notepad.exe`"" -Description "Calculate hash"
Test-Command -Name "forensics_verify" -Command "forensics verify `"$env:SystemRoot\system32\notepad.exe`"" -Description "Verify signature"
Test-Command -Name "forensics_collect" -Command "forensics collect" -Description "Collect forensics"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 17: Whitelist Management" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "whitelist_list" -Command "whitelist list" -Description "List whitelist"
Test-Command -Name "whitelist_add" -Command "whitelist add TestRule --event-id 4624 --reason Test --scope global --duration 60 --enabled" -Description "Add whitelist rule"
Test-Command -Name "whitelist_list_after" -Command "whitelist list" -Description "List after add"
Test-Command -Name "whitelist_remove" -Command "whitelist remove TestRule" -Description "Remove whitelist rule"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 18: Config Management" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "config_get" -Command "config get" -Description "Get all config"
Test-Command -Name "config_get_specific" -Command "config get alert.retention_days" -Description "Get specific config"
Test-Command -Name "config_set" -Command "config set alert.retention_days 180" -Description "Set config"
Test-Command -Name "config_restore" -Command "config set alert.retention_days 90" -Description "Restore default"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 19: SQL Query" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "query_count" -Command 'query "SELECT COUNT(*) FROM events"' -Description "SQL COUNT"
Test-Command -Name "query_events" -Command 'query "SELECT * FROM events LIMIT 5"' -Description "SQL query events"
Test-Command -Name "query_alerts" -Command 'query "SELECT * FROM alerts LIMIT 5"' -Description "SQL query alerts"
Test-Command -Name "query_pragma" -Command 'query "PRAGMA table_info(events)"' -Description "View schema"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 20: Dashboard" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "dashboard" -Command "dashboard" -Description "Show dashboard"
Test-Command -Name "dashboard_json" -Command "dashboard --format json" -Description "Dashboard (JSON)"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 21: Collect" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "collect_basic" -Command "collect" -Description "Basic collection"
Test-Command -Name "collect_output" -Command "collect --include-system-info --include-registry" -Description "Collection with options"

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 22: EVTX Conversion" "INFO"
Write-TestLog "========================================" "INFO"

if ($TestEvtxFile -and (Test-Path $TestEvtxFile)) {
    $evtx2csvCmd = "evtx2csv `"$TestEvtxFile`" `"$OutputDir\converted.csv`" --limit 100"
    Test-Command -Name "evtx2csv" -Command $evtx2csvCmd -Description "EVTX to CSV"
}

Write-TestLog "========================================" "INFO"
Write-TestLog "Part 23: Verify" "INFO"
Write-TestLog "========================================" "INFO"

Test-Command -Name "verify_file" -Command "verify `"$env:SystemRoot\system32\notepad.exe`"" -Description "Verify file"

if (-not $SkipTUI) {
    Write-TestLog "========================================" "INFO"
    Write-TestLog "Part 24: TUI" "INFO"
    Write-TestLog "========================================" "INFO"
    
    Test-Command -Name "tui_check" -Command "tui" -Description "TUI launch test" -ExpectedExitCode -1
}

Write-TestLog "========================================" "INFO"
Write-TestLog "Test Complete" "INFO"
Write-TestLog "========================================" "INFO"

$passCount = ($Script:TestResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($Script:TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
$errorCount = ($Script:TestResults | Where-Object { $_.Status -eq "ERROR" }).Count
$totalCount = $Script:TestResults.Count

Write-TestLog "Total Tests: $totalCount" "INFO"
Write-TestLog "Passed: $passCount ($([math]::Round($passCount/$totalCount*100, 1))%)" "INFO"
Write-TestLog "Failed: $failCount" $(if ($failCount -gt 0) { "WARN" } else { "INFO" })
Write-TestLog "Errors: $errorCount" $(if ($errorCount -gt 0) { "ERROR" } else { "INFO" })

$Script:TestResults | ConvertTo-Json -Depth 5 | Out-File "$OutputDir\test_results.json" -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CLI Test Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Results: $OutputDir\test_results.json" -ForegroundColor Yellow
Write-Host "Passed: $passCount/$totalCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })

exit $(if ($failCount -gt 0) { 1 } else { 0 })
