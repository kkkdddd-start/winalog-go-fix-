# WinLogAnalyzer-Go CLI Full Functionality Test Script
# Requires Administrator privileges on Windows
# Usage: powershell -ExecutionPolicy Bypass -File winalog_full_test.ps1

param(
    [string]$WinalogPath = ".\winalog.exe",
    [string]$OutputDir = ".\winalog_cli_test_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$TestEvtxFile = "",
    [int]$MaxSearchResults = 100,
    [switch]$FullTest,
    [switch]$TestImport,
    [switch]$TestLive,
    [switch]$TestTUI,
    [switch]$SkipEvtxConversion
)

$ErrorActionPreference = "Continue"
$Script:TestResults = New-Object System.Collections.ArrayList
$Script:TestStartTime = Get-Date

function Initialize-TestEnvironment {
    param([string]$OutputDir)
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    New-Item -ItemType Directory -Path "$OutputDir\command_outputs" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\screenshots" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\exports" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\reports" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\logs" -Force | Out-Null
    
    $env:WINLOG_TEST_OUTPUT = $OutputDir
    
    return $OutputDir
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFile = "$OutputDir\test_execution.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "White" }
        default { "White" }
    })
    
    Add-Content -Path $LogFile -Value $logEntry
}

function Get-WinalogVersion {
    try {
        $output = & $WinalogPath --version 2>&1
        return $output | Out-String
    } catch {
        return "Unknown"
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

function Test-WinalogCommand {
    param(
        [string]$CommandName,
        [string]$Arguments,
        [string]$Description,
        [hashtable]$Options = @{},
        [int]$ExpectedExitCode = 0,
        [switch]$AllowNonZero,
        [switch]$CaptureOutput
    )
    
    $result = @{
        CommandName = $CommandName
        Arguments = $Arguments
        Description = $Description
        ExitCode = -1
        Output = ""
        OutputFile = ""
        ErrorOutput = ""
        Duration = 0
        Status = "NOT_RUN"
        Timestamp = Get-Date
        Options = $Options
    }
    
    $outputFileName = "$($CommandName -replace '[^\w]', '_')_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
    $outputFile = "$OutputDir\command_outputs\$outputFileName"
    
    Write-Log "Executing: $CommandName" "INFO"
    Write-Log "Args: $Arguments" "INFO"
    Write-Log "Desc: $Description" "INFO"
    
    $startTime = Get-Date
    
    try {
        $fullArgs = if ($Arguments) { "$Arguments" -split ' ' } else { @() }
        
        $processInfo = Start-Process -FilePath $WinalogPath -ArgumentList $fullArgs -NoNewWindow -PassThru -RedirectStandardOutput $outputFile -RedirectStandardError "$outputFile.err" -Wait
        
        $result.ExitCode = $processInfo.ExitCode
        $result.Duration = (Get-Date) - $startTime
        
        if (Test-Path $outputFile) {
            $result.Output = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
            $result.OutputFile = $outputFile
        }
        
        if (Test-Path "$outputFile.err") {
            $errContent = Get-Content "$outputFile.err" -Raw -ErrorAction SilentlyContinue
            if ($errContent) {
                $result.ErrorOutput = $errContent
                $result.Output += "`n[STDERR]`n$errContent"
            }
        }
        
        if ($AllowNonZero) {
            $result.Status = if ($result.ExitCode -eq 0 -or $result.ExitCode -eq -1) { "PASS" } else { "FAIL" }
        } else {
            $result.Status = if ($result.ExitCode -eq $ExpectedExitCode) { "PASS" } else { "FAIL" }
        }
        
        if ($result.Status -eq "PASS") {
            Write-Log "Status: PASS (ExitCode: $($result.ExitCode), Duration: $($result.Duration.TotalSeconds)s)" "SUCCESS"
        } else {
            Write-Log "Status: FAIL (ExitCode: $($result.ExitCode), Expected: $ExpectedExitCode)" "ERROR"
        }
    }
    catch {
        $result.Status = "ERROR"
        $result.Output = "Exception: $($_.Exception.Message)"
        $result.Duration = (Get-Date) - $startTime
        Write-Log "Exception: $($_.Exception.Message)" "ERROR"
    }
    
    $script:TestResults.Add($result) | Out-Null
    
    Write-Log "---" "INFO"
    
    return $result
}

function Get-SystemInfo {
    $info = @{
        Hostname = $env:COMPUTERNAME
        User = $env:USERNAME
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
        Architecture = $env:PROCESSOR_ARCHITECTURE
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        TestStartTime = $Script:TestStartTime
        WinalogVersion = Get-WinalogVersion
    }
    return $info
}

Initialize-TestEnvironment $OutputDir

Write-Log "========================================" "INFO"
Write-Log "WinLogAnalyzer-Go CLI Full Function Test" "INFO"
Write-Log "========================================" "INFO"

$systemInfo = Get-SystemInfo
Write-Log "Hostname: $($systemInfo.Hostname)" "INFO"
Write-Log "User: $($systemInfo.User)" "INFO"
Write-Log "OS: $($systemInfo.OS)" "INFO"
Write-Log "WinLogAnalyzer Version: $($systemInfo.WinalogVersion)" "INFO"
Write-Log "Test Start Time: $($systemInfo.TestStartTime)" "INFO"

$systemInfo | ConvertTo-Json -Depth 5 | Out-File "$OutputDir\system_info.json" -Encoding UTF8

if (-not (Test-Path $WinalogPath)) {
    Write-Log "Error: Cannot find winalog.exe at $WinalogPath" "ERROR"
    exit 1
}

Write-Log "========================================" "INFO"
Write-Log "Part 1: Help and Version" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "help" -Arguments "--help" -Description "Show full help"
Test-WinalogCommand -CommandName "version" -Arguments "--version" -Description "Show version"

Write-Log "========================================" "INFO"
Write-Log "Part 2: Status and System Info" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "status" -Arguments "status" -Description "Show system status"
Test-WinalogCommand -CommandName "info" -Arguments "info" -Description "Show system info"
Test-WinalogCommand -CommandName "info_process" -Arguments "info --process" -Description "Show process info"
Test-WinalogCommand -CommandName "info_network" -Arguments "info --network" -Description "Show network connections"
Test-WinalogCommand -CommandName "info_users" -Arguments "info --users" -Description "Show local users"
Test-WinalogCommand -CommandName "info_registry" -Arguments "info --registry" -Description "Show registry persistence"
Test-WinalogCommand -CommandName "info_tasks" -Arguments "info --tasks" -Description "Show scheduled tasks"
Test-WinalogCommand -CommandName "info_save" -Arguments "info --save" -Description "Save system info to DB"
Test-WinalogCommand -CommandName "info_all" -Arguments "info --process --network --users --registry --tasks" -Description "Show all system info"

Write-Log "========================================" "INFO"
Write-Log "Part 3: Database Operations" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "db_status" -Arguments "db status" -Description "Show DB status"
Test-WinalogCommand -CommandName "db_clean" -Arguments "db clean" -Description "Clean old data (90 days)"
Test-WinalogCommand -CommandName "db_clean_30" -Arguments "db clean --days 30" -Description "Clean 30 days data"
Test-WinalogCommand -CommandName "metrics" -Arguments "metrics" -Description "Show Prometheus metrics"

Write-Log "========================================" "INFO"
Write-Log "Part 3.5: Forensic Collection" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "collect_basic" -Arguments "collect" -Description "Basic forensic collection"
Test-WinalogCommand -CommandName "collect_output" -Arguments "collect -o $OutputDir\forensic_collect.zip" -Description "Collection with output"
Test-WinalogCommand -CommandName "collect_compress" -Arguments "collect --compress-level 9" -Description "High compression"
Test-WinalogCommand -CommandName "collect_workers" -Arguments "collect --workers 8" -Description "Multi-thread collection"
Test-WinalogCommand -CommandName "collect_sysinfo" -Arguments "collect --include-system-info" -Description "Collect system info"
Test-WinalogCommand -CommandName "collect_registry" -Arguments "collect --include-registry" -Description "Collect registry persistence"
Test-WinalogCommand -CommandName "collect_tasks" -Arguments "collect --include-tasks" -Description "Collect scheduled tasks"
Test-WinalogCommand -CommandName "collect_prefetch" -Arguments "collect --include-prefetch" -Description "Collect Prefetch files"

Write-Log "========================================" "INFO"
Write-Log "Part 4: Rules Management" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "rules_list" -Arguments "rules list" -Description "List all rules"
Test-WinalogCommand -CommandName "rules_list_enabled" -Arguments "rules list --enabled" -Description "List enabled rules"
Test-WinalogCommand -CommandName "rules_status" -Arguments "rules status" -Description "Show rules status"
Test-WinalogCommand -CommandName "rules_status_detail" -Arguments "rules status BruteForce" -Description "Show specific rule status"
Test-WinalogCommand -CommandName "rules_validate" -Arguments "rules validate" -Description "Validate rules file"
Test-WinalogCommand -CommandName "rules_disable" -Arguments "rules disable BruteForce" -Description "Disable rule"
Test-WinalogCommand -CommandName "rules_enable" -Arguments "rules enable BruteForce" -Description "Enable rule"

Write-Log "========================================" "INFO"
Write-Log "Part 5: Alert Management" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "alert_list" -Arguments "alert list" -Description "List alerts"
Test-WinalogCommand -CommandName "alert_list_json" -Arguments "alert list --format json --limit 20" -Description "List alerts in JSON"
Test-WinalogCommand -CommandName "alert_stats" -Arguments "alert stats" -Description "Show alert stats"
Test-WinalogCommand -CommandName "alert_list_high" -Arguments "alert list --severity high --limit 10" -Description "List high severity alerts"
Test-WinalogCommand -CommandName "alert_list_medium" -Arguments "alert list --severity medium --limit 10" -Description "List medium severity alerts"
Test-WinalogCommand -CommandName "alert_list_resolved" -Arguments "alert list --resolved --limit 10" -Description "List resolved alerts"
Test-WinalogCommand -CommandName "alert_run" -Arguments "alert run" -Description "Run alert analysis"
Test-WinalogCommand -CommandName "alert_run_batch" -Arguments "alert run --batch-size 1000" -Description "Run alert analysis with batch"
Test-WinalogCommand -CommandName "alert_export" -Arguments "alert export $OutputDir\alerts_export.json --format json" -Description "Export alerts"

Write-Log "========================================" "INFO"
Write-Log "Part 6: Search Function" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "search_basic" -Arguments "search" -Description "Basic search (all events)"
Test-WinalogCommand -CommandName "search_level4" -Arguments "search --level 4 --limit $MaxSearchResults" -Description "Search info level events"
Test-WinalogCommand -CommandName "search_page" -Arguments "search --page 1 --page-size 50" -Description "Paged search"
Test-WinalogCommand -CommandName "search_sort" -Arguments "search --sort-by timestamp --sort-order desc --limit 20" -Description "Sorted search"
Test-WinalogCommand -CommandName "search_keywords" -Arguments "search --keywords system --limit 20" -Description "Keyword search"
Test-WinalogCommand -CommandName "search_event_id" -Arguments "search --event-id 4624,4625 --limit 20" -Description "Search by event ID"
Test-WinalogCommand -CommandName "search_regex" -Arguments "search --regex --keywords 4624" -Description "Regex search"
Test-WinalogCommand -CommandName "search_time_range" -Arguments "search --start-time 2024-01-01T00:00:00Z --end-time 2024-12-31T23:59:59Z --limit 20" -Description "Time range search"
Test-WinalogCommand -CommandName "search_computer" -Arguments "search --computer localhost --limit 20" -Description "Search by computer"
Test-WinalogCommand -CommandName "search_user" -Arguments "search --user Administrator --limit 20" -Description "Search by user"
Test-WinalogCommand -CommandName "search_log_name" -Arguments "search --log-name Security --limit 20" -Description "Search by log name"

Write-Log "========================================" "INFO"
Write-Log "Part 7: Import Function" "INFO"
Write-Log "========================================" "INFO"

if ($TestImport) {
    if (-not $TestEvtxFile) {
        Write-Log "Auto-searching for EVTX files..." "INFO"
        $foundFile = Find-EvtxFiles
        if ($foundFile) {
            $TestEvtxFile = $foundFile
            Write-Log "Found EVTX file: $TestEvtxFile" "SUCCESS"
        } else {
            Write-Log "No EVTX files found in search paths" "WARN"
        }
    }
    
    if ($TestEvtxFile -and (Test-Path $TestEvtxFile)) {
        Write-Log "Using test file: $TestEvtxFile" "INFO"
        Test-WinalogCommand -CommandName "import" -Arguments "import `"$TestEvtxFile`" --log-name TestImport --workers 4" -Description "Import EVTX file"
        Test-WinalogCommand -CommandName "search_after_import" -Arguments "search --log-name TestImport --limit 50" -Description "Search imported events"
    } else {
        Write-Log "Skipping import test (no valid EVTX file)" "WARN"
        Write-Log "Tip: Use -TestEvtxFile to specify a file manually" "INFO"
    }
} else {
    Write-Log "Skipping import test (use -TestImport to enable)" "WARN"
}

Write-Log "========================================" "INFO"
Write-Log "Part 8: Export Function" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "export_json" -Arguments "export json $OutputDir\exports\events.json --limit 100" -Description "Export to JSON"
Test-WinalogCommand -CommandName "export_csv" -Arguments "export csv $OutputDir\exports\events.csv --limit 100" -Description "Export to CSV"

Write-Log "========================================" "INFO"
Write-Log "Part 9: Report Generation" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "report_list" -Arguments "report" -Description "List reports"
Test-WinalogCommand -CommandName "report_generate_summary" -Arguments "report generate summary --format json --output $OutputDir\reports\summary.json" -Description "Generate summary report"
Test-WinalogCommand -CommandName "report_generate_security" -Arguments "report generate security --format json --output $OutputDir\reports\security.json --time-range 24h" -Description "Generate security report"
Test-WinalogCommand -CommandName "report_generate_threat" -Arguments "report generate threat --format json --output $OutputDir\reports\threat.json --time-range 24h" -Description "Generate threat report"
Test-WinalogCommand -CommandName "report_generate_compliance" -Arguments "report generate compliance --format json --output $OutputDir\reports\compliance.json --time-range 24h" -Description "Generate compliance report"
Test-WinalogCommand -CommandName "report_generate_html" -Arguments "report generate security --format html --output $OutputDir\reports\security.html" -Description "Generate HTML report"

Write-Log "========================================" "INFO"
Write-Log "Part 10: Timeline Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "timeline_query" -Arguments "timeline query --limit 50" -Description "Query timeline"
Test-WinalogCommand -CommandName "timeline_query_time" -Arguments "timeline query --start 2024-01-01T00:00:00Z --end 2024-12-31T23:59:59Z --limit 50" -Description "Time range query"
Test-WinalogCommand -CommandName "timeline_query_category" -Arguments "timeline query --category Security --limit 50" -Description "Query by category"
Test-WinalogCommand -CommandName "timeline_query_computer" -Arguments "timeline query --computer localhost --limit 50" -Description "Query by computer"
Test-WinalogCommand -CommandName "timeline_build" -Arguments "timeline build" -Description "Build timeline index"

Write-Log "========================================" "INFO"
Write-Log "Part 11: Threat Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "analyze_list" -Arguments "analyze list" -Description "List analyzers"
Test-WinalogCommand -CommandName "analyze_bruteforce" -Arguments "analyze brute_force --hours 24" -Description "Brute force analysis"
Test-WinalogCommand -CommandName "analyze_login" -Arguments "analyze login --hours 24" -Description "Login analysis"
Test-WinalogCommand -CommandName "analyze_kerberos" -Arguments "analyze kerberos --hours 24" -Description "Kerberos analysis"
Test-WinalogCommand -CommandName "analyze_powershell" -Arguments "analyze powershell --hours 24" -Description "PowerShell analysis"
Test-WinalogCommand -CommandName "analyze_data_exfiltration" -Arguments "analyze data_exfiltration --hours 24" -Description "Data exfiltration analysis"
Test-WinalogCommand -CommandName "analyze_lateral_movement" -Arguments "analyze lateral_movement --hours 24" -Description "Lateral movement analysis"
Test-WinalogCommand -CommandName "analyze_privilege_escalation" -Arguments "analyze privilege_escalation --hours 24" -Description "Privilege escalation analysis"
Test-WinalogCommand -CommandName "analyze_persistence" -Arguments "analyze persistence --hours 24" -Description "Persistence analysis"
Test-WinalogCommand -CommandName "analyze_time_window" -Arguments "analyze --time-window 72h --format json" -Description "Analysis with time window"
Test-WinalogCommand -CommandName "analyze_output" -Arguments "analyze --output $OutputDir\analysis.json --format json" -Description "Analysis output to file"

Write-Log "========================================" "INFO"
Write-Log "Part 12: Correlation Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "correlate" -Arguments "correlate --time-window 24h" -Description "Correlation analysis"
Test-WinalogCommand -CommandName "correlate_json" -Arguments "correlate --format json --output $OutputDir\correlation.json" -Description "Correlation analysis (JSON)"
Test-WinalogCommand -CommandName "correlate_48h" -Arguments "correlate --time-window 48h" -Description "Correlation analysis (48h)"
Test-WinalogCommand -CommandName "correlate_rules" -Arguments "correlate --rules LateralMovement,BruteForce --time-window 24h" -Description "Correlation with specific rules"

Write-Log "========================================" "INFO"
Write-Log "Part 13: Multi-Machine Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "multi_analyze" -Arguments "multi analyze" -Description "Multi-machine analysis"
Test-WinalogCommand -CommandName "multi_analyze_48h" -Arguments "multi analyze --time-window 48h" -Description "Multi-machine analysis (48h)"
Test-WinalogCommand -CommandName "multi_lateral" -Arguments "multi lateral" -Description "Lateral movement detection"

Write-Log "========================================" "INFO"
Write-Log "Part 14: UEBA Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "ueba_profiles" -Arguments "ueba profiles" -Description "Show user profiles"
Test-WinalogCommand -CommandName "ueba_profiles_user" -Arguments "ueba profiles --user Administrator" -Description "Show specific user profile"
Test-WinalogCommand -CommandName "ueba_analyze" -Arguments "ueba analyze --hours 24" -Description "UEBA analysis"
Test-WinalogCommand -CommandName "ueba_analyze_save" -Arguments "ueba analyze --hours 24 --save-alerts" -Description "UEBA analysis and save alerts"
Test-WinalogCommand -CommandName "ueba_analyze_7d" -Arguments "ueba analyze -H 168" -Description "UEBA analysis (7 days)"
Test-WinalogCommand -CommandName "ueba_baseline" -Arguments "ueba baseline" -Description "Show user baseline"
Test-WinalogCommand -CommandName "ueba_baseline_learn" -Arguments "ueba baseline --action learn --hours 168" -Description "Learn user baseline"
Test-WinalogCommand -CommandName "ueba_baseline_clear" -Arguments "ueba baseline --action clear" -Description "Clear user baseline"

Write-Log "========================================" "INFO"
Write-Log "Part 15: Real-time Monitoring" "INFO"
Write-Log "========================================" "INFO"

if ($TestLive) {
    Write-Log "Starting real-time monitoring test (5 seconds)" "INFO"
    $liveJob = Start-Job -ScriptBlock {
        param($exe, $sec)
        $proc = Start-Process -FilePath $exe -ArgumentList "live", "collect" -PassThru
        Start-Sleep -Seconds $sec
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    } -ArgumentList $WinalogPath, 5
    
    Test-WinalogCommand -CommandName "live_collect" -Arguments "live collect" -Description "Real-time event collection" -AllowNonZero
    
    if ($liveJob.State -eq "Running") {
        Stop-Job $liveJob -ErrorAction SilentlyContinue
        Remove-Job $liveJob -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Log "Skipping real-time monitoring test (requires -TestLive flag)" "WARN"
}

Write-Log "========================================" "INFO"
Write-Log "Part 16: Forensics" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "forensics_hash_notepad" -Arguments "forensics hash `"$env:SystemRoot\system32\notepad.exe`"" -Description "Calculate notepad.exe hash"
Test-WinalogCommand -CommandName "forensics_verify_notepad" -Arguments "forensics verify `"$env:SystemRoot\system32\notepad.exe`"" -Description "Verify notepad.exe signature"
Test-WinalogCommand -CommandName "forensics_collect" -Arguments "forensics collect" -Description "Collect forensics data"

Write-Log "========================================" "INFO"
Write-Log "Part 17: Persistence Detection" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "persistence_detect" -Arguments "persistence detect" -Description "Detect all persistence mechanisms"
Test-WinalogCommand -CommandName "persistence_detect_json" -Arguments "persistence detect --format json --output $OutputDir\persistence.json" -Description "Detect persistence (JSON)"
Test-WinalogCommand -CommandName "persistence_categories" -Arguments "persistence detect --category registry" -Description "Detect registry persistence"
Test-WinalogCommand -CommandName "persistence_category_wmi" -Arguments "persistence detect --category WMI" -Description "Detect WMI persistence"
Test-WinalogCommand -CommandName "persistence_category_service" -Arguments "persistence detect --category Service" -Description "Detect service persistence"
Test-WinalogCommand -CommandName "persistence_category_scheduled" -Arguments "persistence detect --category ScheduledTask" -Description "Detect scheduled task persistence"
Test-WinalogCommand -CommandName "persistence_technique" -Arguments "persistence detect --technique T1546.003" -Description "Detect specific MITRE technique"
Test-WinalogCommand -CommandName "persistence_technique2" -Arguments "persistence detect --technique T1547.001" -Description "Detect T1547.001 technique"
Test-WinalogCommand -CommandName "persistence_text" -Arguments "persistence detect --format text" -Description "Text format output"
Test-WinalogCommand -CommandName "persistence_progress" -Arguments "persistence detect --progress" -Description "Show detection progress"

Write-Log "========================================" "INFO"
Write-Log "Part 18: Whitelist Management" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "whitelist_list" -Arguments "whitelist list" -Description "List whitelist"
Test-WinalogCommand -CommandName "whitelist_add" -Arguments "whitelist add TestRule001 --event-id 4624 --reason Test --scope global --duration 1440 --enabled" -Description "Add whitelist rule"
Test-WinalogCommand -CommandName "whitelist_add_user" -Arguments "whitelist add TestRule002 --event-id 4625 --reason Test --scope user --duration 60 --enabled" -Description "Add user scope whitelist"
Test-WinalogCommand -CommandName "whitelist_add_computer" -Arguments "whitelist add TestRule003 --event-id 4672 --reason Test --scope computer --duration 0 --enabled" -Description "Add computer scope whitelist"
Test-WinalogCommand -CommandName "whitelist_list_after" -Arguments "whitelist list" -Description "List whitelist (after add)"
Test-WinalogCommand -CommandName "whitelist_remove" -Arguments "whitelist remove TestRule001" -Description "Remove whitelist rule"
Test-WinalogCommand -CommandName "whitelist_remove2" -Arguments "whitelist remove TestRule002" -Description "Remove second whitelist"
Test-WinalogCommand -CommandName "whitelist_remove3" -Arguments "whitelist remove TestRule003" -Description "Remove third whitelist"

Write-Log "========================================" "INFO"
Write-Log "Part 19: Config Management" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "config_get_all" -Arguments "config get" -Description "Get all config"
Test-WinalogCommand -CommandName "config_get_retention" -Arguments "config get alert.retention_days" -Description "Get retention config"
Test-WinalogCommand -CommandName "config_set_retention" -Arguments "config set alert.retention_days 180" -Description "Set retention"
Test-WinalogCommand -CommandName "config_get_retention_after" -Arguments "config get alert.retention_days" -Description "Verify retention set"
Test-WinalogCommand -CommandName "config_set_restore" -Arguments "config set alert.retention_days 90" -Description "Restore default retention"

Write-Log "========================================" "INFO"
Write-Log "Part 20: SQL Query" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "query_count" -Arguments "query `"SELECT COUNT(*) FROM events`"" -Description "Count events"
Test-WinalogCommand -CommandName "query_events" -Arguments "query `"SELECT * FROM events LIMIT 10`"" -Description "Query events"
Test-WinalogCommand -CommandName "query_rules" -Arguments "query `"SELECT name, enabled FROM rules LIMIT 10`"" -Description "Query rules"
Test-WinalogCommand -CommandName "query_alerts" -Arguments "query `"SELECT * FROM alerts LIMIT 10`"" -Description "Query alerts"
Test-WinalogCommand -CommandName "query_pragma" -Arguments "query `"PRAGMA table_info(events)`"" -Description "View table schema"

Write-Log "========================================" "INFO"
Write-Log "Part 21: Dashboard" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "dashboard" -Arguments "dashboard" -Description "Show dashboard"
Test-WinalogCommand -CommandName "dashboard_json" -Arguments "dashboard --format json" -Description "Dashboard (JSON)"

Write-Log "========================================" "INFO"
Write-Log "Part 22: Database Maintenance" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "db_vacuum" -Arguments "db vacuum" -Description "Database VACUUM"
Test-WinalogCommand -CommandName "db_status_after" -Arguments "db status" -Description "Database status (after)"

Write-Log "========================================" "INFO"
Write-Log "Part 23: File Verification" "INFO"
Write-Log "========================================" "INFO"

Test-WinalogCommand -CommandName "verify_calc" -Arguments "verify `"$env:SystemRoot\system32\calc.exe`"" -Description "Verify calc.exe"
Test-WinalogCommand -CommandName "verify_cmd" -Arguments "verify `"$env:SystemRoot\system32\cmd.exe`"" -Description "Verify cmd.exe"
Test-WinalogCommand -CommandName "verify_powershell" -Arguments "verify `"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`"" -Description "Verify PowerShell"
Test-WinalogCommand -CommandName "verify_batch" -Arguments "verify `"$env:SystemRoot\system32\calc.exe`" `"$env:SystemRoot\system32\cmd.exe`"" -Description "Batch verify files"

Write-Log "========================================" "INFO"
Write-Log "Part 24: EVTX Conversion" "INFO"
Write-Log "========================================" "INFO"

if (-not $SkipEvtxConversion) {
    if (-not $TestEvtxFile) {
        Write-Log "Auto-searching for EVTX files for conversion test..." "INFO"
        $foundFile = Find-EvtxFiles
        if ($foundFile) {
            $TestEvtxFile = $foundFile
            Write-Log "Found EVTX file: $TestEvtxFile" "SUCCESS"
        }
    }
    
    if ($TestEvtxFile -and (Test-Path $TestEvtxFile)) {
        Write-Log "Testing EVTX to CSV: $TestEvtxFile" "INFO"
        Test-WinalogCommand -CommandName "evtx2csv" -Arguments "evtx2csv `"$TestEvtxFile`" `"$OutputDir\exports\converted.csv`" --limit 500" -Description "EVTX to CSV"
        
        if (Test-Path "$OutputDir\exports\converted.csv") {
            $csvInfo = Get-Content "$OutputDir\exports\converted.csv" -TotalCount 10
            Write-Log "CSV Preview: $csvInfo" "INFO"
        }
    } else {
        Write-Log "Skipping EVTX conversion test (no valid file)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 25: TUI Interface" "INFO"
Write-Log "========================================" "INFO"

Write-Log "TUI test: Testing startup with timeout" "INFO"
$startTime = Get-Date
try {
    $tuiProc = Start-Process -FilePath $WinalogPath -ArgumentList "tui" -PassThru
    Start-Sleep -Seconds 3
    if (-not $tuiProc.HasExited) {
        Stop-Process -Id $tuiProc.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Status: PASS (TUI started successfully)" "SUCCESS"
        $script:TestResults.Add(@{
            CommandName = "tui_start"
            Arguments = "tui"
            Description = "TUI interface startup"
            ExitCode = 0
            Duration = (Get-Date) - $startTime
            Status = "PASS"
            Timestamp = Get-Date
        }) | Out-Null
    } else {
        Write-Log "Status: FAIL (TUI exited immediately)" "ERROR"
        $script:TestResults.Add(@{
            CommandName = "tui_start"
            Arguments = "tui"
            Description = "TUI interface startup"
            ExitCode = $tuiProc.ExitCode
            Duration = (Get-Date) - $startTime
            Status = "FAIL"
            Timestamp = Get-Date
        }) | Out-Null
    }
} catch {
    Write-Log "TUI test exception: $($_.Exception.Message)" "ERROR"
}

Write-Log "========================================" "INFO"
Write-Log "Part 26: API Service" "INFO"
Write-Log "========================================" "INFO"

Write-Log "Starting API service test (background for 5 seconds)" "INFO"
$servePort = 18080
$serveOutputFile = "$OutputDir\command_outputs\serve_test.log"
$serveErrFile = "$OutputDir\command_outputs\serve_test.err"
try {
    $serveProc = Start-Process -FilePath $WinalogPath -ArgumentList "serve", "--port", "$servePort" -PassThru -RedirectStandardOutput $serveOutputFile -RedirectStandardError $serveErrFile
    Start-Sleep -Seconds 5
    
    if (-not $serveProc.HasExited) {
        Write-Log "API service started successfully (PID: $($serveProc.Id))" "SUCCESS"
        
        Test-WinalogCommand -CommandName "api_health" -Arguments "query health" -Description "API health check"
        Test-WinalogCommand -CommandName "api_stats" -Arguments "stats" -Description "API stats endpoint"
        
        Stop-Process -Id $serveProc.Id -Force -ErrorAction SilentlyContinue
        Write-Log "API service stopped" "INFO"
        
        $script:TestResults.Add(@{
            CommandName = "serve_start"
            Arguments = "serve --port $servePort"
            Description = "API service startup"
            ExitCode = 0
            Duration = (Get-Date) - $startTime
            Status = "PASS"
            Timestamp = Get-Date
        }) | Out-Null
    } else {
        Write-Log "API service failed to start, exit code: $($serveProc.ExitCode)" "ERROR"
        if (Test-Path $serveErrFile) {
            $errContent = Get-Content $serveErrFile -Raw -ErrorAction SilentlyContinue
            Write-Log "Error output: $errContent" "ERROR"
        }
        $script:TestResults.Add(@{
            CommandName = "serve_start"
            Arguments = "serve --port $servePort"
            Description = "API service startup"
            ExitCode = $serveProc.ExitCode
            Duration = (Get-Date) - $startTime
            Status = "FAIL"
            Timestamp = Get-Date
        }) | Out-Null
    }
} catch {
    Write-Log "API service test exception: $($_.Exception.Message)" "ERROR"
}

Write-Log "========================================" "INFO"
Write-Log "Test Complete - Generating Report" "INFO"
Write-Log "========================================" "INFO"

$passCount = ($Script:TestResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($Script:TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
$errorCount = ($Script:TestResults | Where-Object { $_.Status -eq "ERROR" }).Count
$totalCount = $Script:TestResults.Count

$summary = @{
    TestStartTime = $Script:TestStartTime.ToString("yyyy-MM-dd HH:mm:ss")
    TestEndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    TotalTests = $totalCount
    Passed = $passCount
    Failed = $failCount
    Errors = $errorCount
    SuccessRate = if ($totalCount -gt 0) { [math]::Round($passCount/$totalCount*100, 2) } else { 0 }
    SystemInfo = $systemInfo
    TestResults = $Script:TestResults
} | ConvertTo-Json -Depth 10

$summary | Out-File "$OutputDir\test_summary.json" -Encoding UTF8

$resultsCsv = $Script:TestResults | ForEach-Object {
    [PSCustomObject]@{
        CommandName = $_.CommandName
        Arguments = $_.Arguments
        Description = $_.Description
        ExitCode = $_.ExitCode
        DurationSeconds = [math]::Round($_.Duration.TotalSeconds, 3)
        Status = $_.Status
        Timestamp = $_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
        OutputFile = $_.OutputFile
    }
}
$resultsCsv | Export-Csv -Path "$OutputDir\test_results.csv" -NoTypeInformation -Encoding UTF8

Write-Log "========================================" "INFO"
Write-Log "Test Results Summary" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Total Tests: $totalCount" "INFO"
Write-Log "Passed: $passCount ($([math]::Round($passCount/$totalCount*100, 1))%)" $(if ($failCount -eq 0 -and $errorCount -eq 0) { "SUCCESS" } else { "WARN" })
Write-Log "Failed: $failCount" $(if ($failCount -gt 0) { "ERROR" } else { "SUCCESS" })
Write-Log "Errors: $errorCount" $(if ($errorCount -gt 0) { "ERROR" } else { "SUCCESS" })
Write-Log "========================================" "INFO"
Write-Log "Output Directory: $OutputDir" "INFO"
Write-Log "========================================" "INFO"

$failedTests = $Script:TestResults | Where-Object { $_.Status -ne "PASS" }
if ($failedTests) {
    Write-Log "Failed Tests:" "ERROR"
    foreach ($test in $failedTests) {
        Write-Log "  - $($test.CommandName): $($test.Description)" "ERROR"
        if ($test.Output) {
            Write-Log "    Output: $($test.Output.Substring(0, [math]::Min(200, $test.Output.Length)))" "ERROR"
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CLI Test Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Output Dir: $OutputDir" -ForegroundColor Yellow
Write-Host "Details: $OutputDir\test_summary.json" -ForegroundColor Yellow
Write-Host "CSV: $OutputDir\test_results.csv" -ForegroundColor Yellow
Write-Host ""
Write-Host "Result: $passCount/$totalCount passed" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })

exit $(if ($failCount -gt 0 -or $errorCount -gt 0) { 1 } else { 0 })
