# WinLogAnalyzer-Go Web API Test Script
# Tests all API endpoints with data preparation
# Usage: powershell -ExecutionPolicy Bypass -File api_test.ps1

param(
    [string]$BaseUrl = "http://localhost:8080/api",
    [string]$OutputDir = ".\api_test_results",
    [string]$TestEvtxFile = "",
    [switch]$SkipLiveTests,
    [switch]$SkipImportTests,
    [switch]$FullTest,
    [int]$MaxRetries = 3,
    [int]$RetryDelayMs = 1000,
    [switch]$EnableSSE,
    [switch]$EnableValidation,
    [switch]$EnablePerformance
)

$ErrorActionPreference = "Continue"
$Script:TestResults = New-Object System.Collections.ArrayList
$Script:TestStartTime = Get-Date
$Script:BaseUrl = $BaseUrl
$Script:PreparedData = @{}
$Script:PerformanceData = @{}
$Script:RetryCount = $MaxRetries
$Script:RetryDelay = $RetryDelayMs

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "White" }
        default { "White" }
    })
    Add-Content -Path "$OutputDir\test_log.txt" -Value $logEntry
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

function Test-ApiRequest {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Endpoint,
        [string]$Body = "",
        [string]$Description = "",
        [int]$ExpectedStatus = 200,
        [switch]$AllowRedirect,
        [switch]$SaveResponse,
        [switch]$SkipRetry
    )
    
    $result = @{
        Name = $Name
        Method = $Method
        Endpoint = $Endpoint
        Description = $Description
        StatusCode = 0
        Response = ""
        Duration = 0
        Status = "NOT_RUN"
        Timestamp = Get-Date
        RetryCount = 0
    }
    
    $outputFile = "$OutputDir\$($Name -replace '[^\w]', '_').json"
    
    Write-Log "Testing: $Name" "INFO"
    Write-Log "Method: $Method $Endpoint" "INFO"
    if ($Description) { Write-Log "Desc: $Description" "INFO" }
    
    $startTime = Get-Date
    $attempt = 0
    $success = $false
    
    while ($attempt -lt $Script:RetryCount -and -not $success -and -not $SkipRetry) {
        $attempt++
        if ($attempt -gt 1) {
            Write-Log "Retry $attempt/$Script:RetryCount after $($Script:RetryDelay)ms..." "WARN"
            Start-Sleep -Milliseconds $Script:RetryDelay
        }
        
        $result.RetryCount = $attempt - 1
        
        try {
            $headers = @{"Content-Type" = "application/json"}
            
            $params = @{
                Uri = "$Script:BaseUrl$Endpoint"
                Method = $Method
                Headers = $headers
                TimeoutSec = 60
            }
            
            if ($Body) {
                $params.Body = $Body
            }
            
            if ($AllowRedirect) {
                $params.AllowRedirect = $true
            }
            
            $response = Invoke-WebRequest @params -ErrorAction SilentlyContinue
            
            $result.StatusCode = $response.StatusCode
            $result.Duration = (Get-Date) - $startTime
            
            $content = $response.Content
            $result.Response = $content
            
            if ($SaveResponse) {
                $content | Out-File -FilePath $outputFile -Encoding UTF8
            }
            
            if ($result.StatusCode -eq $ExpectedStatus -or ($ExpectedStatus -eq 0 -and $result.StatusCode -gt 0)) {
                $result.Status = "PASS"
                Write-Log "Status: PASS (HTTP $($result.StatusCode), Duration: $($result.Duration.TotalSeconds)s)" "SUCCESS"
                $success = $true
            } else {
                if ($attempt -lt $Script:RetryCount) {
                    Write-Log "Status: RETRY (HTTP $($result.StatusCode), Expected: $ExpectedStatus)" "WARN"
                } else {
                    $result.Status = "FAIL"
                    Write-Log "Status: FAIL (HTTP $($result.StatusCode), Expected: $ExpectedStatus)" "ERROR"
                }
            }
        }
        catch {
            if ($attempt -lt $Script:RetryCount) {
                Write-Log "Retry on exception: $($_.Exception.Message)" "WARN"
            } else {
                $result.Status = "ERROR"
                $result.Response = $_.Exception.Message
                $result.Duration = (Get-Date) - $startTime
                Write-Log "Error: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    if ($EnablePerformance) {
        $Script:PerformanceData[$Name] = @{
            Duration = $result.Duration.TotalSeconds
            StatusCode = $result.StatusCode
            RetryCount = $result.RetryCount
        }
    }
    
    $script:TestResults.Add($result) | Out-Null
    Write-Log "---" "INFO"
    
    return $result
}

function Test-ApiJsonPost {
    param(
        [string]$Name,
        [string]$Endpoint,
        [hashtable]$JsonBody,
        [string]$Description = "",
        [int]$ExpectedStatus = 200,
        [switch]$SaveResponse,
        [switch]$SkipRetry
    )
    
    $body = $JsonBody | ConvertTo-Json -Compress
    return Test-ApiRequest -Name $Name -Method "POST" -Endpoint $Endpoint -Body $body -Description $Description -ExpectedStatus $ExpectedStatus -SaveResponse:$SaveResponse -SkipRetry:$SkipRetry
}

function Validate-JsonResponse {
    param(
        [string]$Name,
        [string]$Response,
        [string[]]$RequiredFields,
        [switch]$IsArray
    )
    
    if (-not $EnableValidation) { return $true }
    
    Write-Log "Validating response for: $Name" "INFO"
    
    try {
        $data = $Response | ConvertFrom-Json
        
        if ($IsArray) {
            if ($data.Count -eq 0) {
                Write-Log "Warning: Response is empty array" "WARN"
                return $false
            }
            $item = $data[0]
        } else {
            $item = $data
        }
        
        foreach ($field in $RequiredFields) {
            if (-not $item.PSObject.Properties[$field]) {
                Write-Log "Missing required field: $field" "ERROR"
                return $false
            }
        }
        
        Write-Log "Validation PASSED" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Validation error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-SseStream {
    param(
        [string]$Name,
        [string]$Endpoint,
        [int]$TimeoutSeconds = 10
    )
    
    if (-not $EnableSSE) {
        Write-Log "SSE tests disabled (use -EnableSSE to enable)" "WARN"
        return $null
    }
    
    Write-Log "Testing SSE stream: $Name" "INFO"
    Write-Log "Endpoint: $Endpoint" "INFO"
    
    $result = @{
        Name = $Name
        Endpoint = $Endpoint
        Status = "NOT_RUN"
        EventsReceived = 0
        Duration = 0
        Error = ""
    }
    
    $startTime = Get-Date
    
    try {
        $params = @{
            Uri = "$Script:BaseUrl$Endpoint"
            Method = "GET"
            TimeoutSec = $TimeoutSeconds
        }
        
        $response = Invoke-WebRequest @params -DisableKeepAlive -UseBasicParsing
        
        $result.Duration = (Get-Date) - $startTime
        
        if ($response.StatusCode -eq 200) {
            $content = $response.Content
            $lines = $content -split "`n"
            $eventLines = $lines | Where-Object { $_ -match "^data:" }
            $result.EventsReceived = $eventLines.Count
            $result.Status = "PASS"
            Write-Log "SSE PASS: Received $($result.EventsReceived) events in $($result.Duration.TotalSeconds)s" "SUCCESS"
        } else {
            $result.Status = "FAIL"
            Write-Log "SSE FAIL: HTTP $($response.StatusCode)" "ERROR"
        }
    }
    catch {
        $result.Status = "ERROR"
        $result.Error = $_.Exception.Message
        $result.Duration = (Get-Date) - $startTime
        Write-Log "SSE ERROR: $($_.Exception.Message)" "ERROR"
    }
    
    $script:TestResults.Add($result) | Out-Null
    return $result
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Log "========================================" "INFO"
Write-Log "WinLogAnalyzer-Go API Test Suite" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Base URL: $BaseUrl" "INFO"
Write-Log "Start Time: $Script:TestStartTime" "INFO"
Write-Log "Max Retries: $MaxRetries" "INFO"
Write-Log "Retry Delay: ${RetryDelayMs}ms" "INFO"
Write-Log "SSE Enabled: $EnableSSE" "INFO"
Write-Log "Validation Enabled: $EnableValidation" "INFO"
Write-Log "Performance Enabled: $EnablePerformance" "INFO"

if (-not $SkipImportTests) {
    if ($TestEvtxFile) {
        if (Test-Path $TestEvtxFile) {
            Write-Log "Using specified EVTX: $TestEvtxFile" "INFO"
        } else {
            Write-Log "Specified EVTX not found: $TestEvtxFile" "ERROR"
            Write-Log "Auto-searching for EVTX files..." "INFO"
            $TestEvtxFile = $null
        }
    }
    
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
}

Write-Log "========================================" "INFO"
Write-Log "Step 0: Prepare Test Environment" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "health_check" -Method "GET" -Endpoint "/health" -Description "Health check"

if (-not $SkipImportTests -and $TestEvtxFile -and (Test-Path $TestEvtxFile)) {
    Write-Log "========================================" "INFO"
    Write-Log "Step 0.1: Import Test Data" "INFO"
    Write-Log "========================================" "INFO"
    
    Write-Log "Importing: $TestEvtxFile" "INFO"
    Test-ApiJsonPost -Name "import_logs" -Endpoint "/import/logs" -JsonBody @{files=@($TestEvtxFile);alert_on_import=$false} -Description "Import EVTX file for testing" -SaveResponse
    
    $Script:PreparedData.EvtxImported = $true
} else {
    Write-Log "Skipping EVTX import (no valid file found)" "WARN"
    Write-Log "Tip: Use -TestEvtxFile to specify a file manually" "INFO"
}

Write-Log "========================================" "INFO"
Write-Log "Part 1: Events API (with test data)" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "events_list" -Method "GET" -Endpoint "/events?page=1&page_size=10" -Description "List events with pagination" -SaveResponse
Test-ApiRequest -Name "events_list_page2" -Method "GET" -Endpoint "/events?page=2&page_size=10" -Description "List events page 2"
Test-ApiRequest -Name "events_search_basic" -Method "POST" -Endpoint "/events/search" -Body '{"page_size":10}' -Description "Basic search"
Test-ApiRequest -Name "events_search_keywords" -Method "POST" -Endpoint "/events/search" -Body '{"keywords":"system","page_size":10}' -Description "Search by keywords"
Test-ApiRequest -Name "events_search_levels" -Method "POST" -Endpoint "/events/search" -Body '{"levels":[4],"page_size":10}' -Description "Search by level"
Test-ApiRequest -Name "events_search_regex" -Method "POST" -Endpoint "/events/search" -Body '{"keywords":"4624|4625","regex":true,"page_size":10}' -Description "Regex search"
Test-ApiRequest -Name "events_search_event_ids" -Method "POST" -Endpoint "/events/search" -Body '{"event_ids":[4624,4625],"page_size":10}' -Description "Search by event IDs"
Test-ApiRequest -Name "events_search_time" -Method "POST" -Endpoint "/events/search" -Body '{"start_time":"2024-01-01T00:00:00Z","end_time":"2024-12-31T23:59:59Z","page_size":10}' -Description "Time range search"
Test-ApiRequest -Name "events_search_users" -Method "POST" -Endpoint "/events/search" -Body '{"users":["Administrator"],"page_size":10}' -Description "Search by users"
Test-ApiRequest -Name "events_search_computers" -Method "POST" -Endpoint "/events/search" -Body '{"computers":["localhost"],"page_size":10}' -Description "Search by computers"
Test-ApiRequest -Name "events_search_lognames" -Method "POST" -Endpoint "/events/search" -Body '{"log_names":["Security"],"page_size":10}' -Description "Search by log names"
Test-ApiRequest -Name "events_search_sort" -Method "POST" -Endpoint "/events/search" -Body '{"sort_by":"timestamp","sort_order":"desc","page_size":10}' -Description "Sorted search"
Test-ApiRequest -Name "events_export_csv" -Method "POST" -Endpoint "/events/export" -Body '{"format":"csv","filters":{"limit":100}}' -Description "Export events as CSV"
Test-ApiRequest -Name "events_export_json" -Method "POST" -Endpoint "/events/export" -Body '{"format":"json","filters":{"limit":100}}' -Description "Export events as JSON"

$eventsResponse = Test-ApiRequest -Name "events_list_first" -Method "GET" -Endpoint "/events?page=1&page_size=1" -Description "Get first event for ID test"
if ($eventsResponse.Status -eq "PASS" -and $eventsResponse.Response) {
    try {
        $eventData = $eventsResponse.Response | ConvertFrom-Json
        if ($eventData.events -and $eventData.events.Count -gt 0) {
            $firstEventId = $eventData.events[0].id
            Write-Log "Testing event get by ID: $firstEventId" "INFO"
            Test-ApiRequest -Name "events_get_by_id" -Method "GET" -Endpoint "/events/$firstEventId" -Description "Get event by ID" -SaveResponse
        }
    } catch {
        Write-Log "Could not parse events response for ID extraction: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Step 0.2: Run Alert Analysis" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "alerts_run_analysis" -Endpoint "/alerts/run-analysis" -JsonBody @{} -Description "Run alert analysis to generate test alerts" -SaveResponse

if ($FullTest) {
    Write-Log "Waiting for alert analysis to complete..." "INFO"
    Start-Sleep -Seconds 5
}

Write-Log "========================================" "INFO"
Write-Log "Part 2: Alerts API (with alerts generated)" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "alerts_list" -Method "GET" -Endpoint "/alerts?page=1&page_size=10" -Description "List alerts" -SaveResponse
Test-ApiRequest -Name "alerts_list_high" -Method "GET" -Endpoint "/alerts?severity=high&page_size=10" -Description "List high severity alerts"
Test-ApiRequest -Name "alerts_list_medium" -Method "GET" -Endpoint "/alerts?severity=medium&page_size=10" -Description "List medium severity alerts"
Test-ApiRequest -Name "alerts_list_low" -Method "GET" -Endpoint "/alerts?severity=low&page_size=10" -Description "List low severity alerts"
Test-ApiRequest -Name "alerts_list_unresolved" -Method "GET" -Endpoint "/alerts?resolved=false&page_size=10" -Description "List unresolved alerts"
Test-ApiRequest -Name "alerts_list_resolved" -Method "GET" -Endpoint "/alerts?resolved=true&page_size=10" -Description "List resolved alerts"
Test-ApiRequest -Name "alerts_stats" -Method "GET" -Endpoint "/alerts/stats" -Description "Get alert statistics" -SaveResponse
Test-ApiRequest -Name "alerts_trend_7d" -Method "GET" -Endpoint "/alerts/trend?days=7" -Description "Get alert trend 7 days"
Test-ApiRequest -Name "alerts_trend_30d" -Method "GET" -Endpoint "/alerts/trend?days=30" -Description "Get alert trend 30 days"

$alertsResponse = Test-ApiRequest -Name "alerts_list_first" -Method "GET" -Endpoint "/alerts?page=1&page_size=1" -Description "Get first alert for resolve test"
if ($alertsResponse.Status -eq "PASS" -and $alertsResponse.Response) {
    try {
        $alertData = $alertsResponse.Response | ConvertFrom-Json
        if ($alertData.alerts -and $alertData.alerts.Count -gt 0) {
            $firstAlertId = $alertData.alerts[0].id
            Write-Log "Testing alert operations on ID: $firstAlertId" "INFO"
            
            Test-ApiJsonPost -Name "alerts_resolve" -Endpoint "/alerts/$firstAlertId/resolve" -JsonBody @{notes="Test resolve from API script"} -Description "Resolve alert"
            Test-ApiRequest -Name "alerts_get_resolved" -Method "GET" -Endpoint "/alerts/$firstAlertId" -Description "Get resolved alert"
            
            Test-ApiJsonPost -Name "alerts_false_positive" -Endpoint "/alerts/$firstAlertId/false-positive" -JsonBody @{reason="Test false positive"} -Description "Mark as false positive"
        }
    } catch {
        Write-Log "Could not parse alerts response for ID extraction: $($_.Exception.Message)" "WARN"
    }
}

Test-ApiJsonPost -Name "alerts_batch_resolve" -Endpoint "/alerts/batch" -JsonBody @{ids=@(1,2,3);action="resolve";notes="Batch test"} -Description "Batch resolve alerts"
Test-ApiJsonPost -Name "alerts_batch_delete" -Endpoint "/alerts/batch" -JsonBody @{ids=@(999999);action="delete"} -Description "Batch delete (non-existent)"

$alertForDelete = Test-ApiRequest -Name "alerts_list_for_delete" -Method "GET" -Endpoint "/alerts?page=1&page_size=1" -Description "Get alert for delete test"
if ($alertForDelete.Status -eq "PASS" -and $alertForDelete.Response) {
    try {
        $alertData = $alertForDelete.Response | ConvertFrom-Json
        if ($alertData.alerts -and $alertData.alerts.Count -gt 0) {
            $alertIdToDelete = $alertData.alerts[0].id
            Write-Log "Testing alert DELETE on ID: $alertIdToDelete" "INFO"
            Test-ApiRequest -Name "alerts_delete" -Method "DELETE" -Endpoint "/alerts/$alertIdToDelete" -Description "Delete alert"
        }
    } catch {
        Write-Log "Could not parse alerts response for delete test: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 3: Timeline API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "timeline_list" -Method "GET" -Endpoint "/timeline?limit=50" -Description "Get timeline" -SaveResponse
Test-ApiRequest -Name "timeline_stats" -Method "GET" -Endpoint "/timeline/stats" -Description "Get timeline stats" -SaveResponse
Test-ApiRequest -Name "timeline_chains" -Method "GET" -Endpoint "/timeline/chains" -Description "Get attack chains"
Test-ApiRequest -Name "timeline_export_json" -Method "GET" -Endpoint "/timeline/export?format=json" -Description "Export timeline as JSON"
Test-ApiRequest -Name "timeline_export_csv" -Method "GET" -Endpoint "/timeline/export?format=csv" -Description "Export timeline as CSV"
Test-ApiRequest -Name "timeline_with_time" -Method "GET" -Endpoint "/timeline?start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T23:59:59Z" -Description "Timeline with time filter"

$alertsResponse = Test-ApiRequest -Name "alerts_list_for_timeline_delete" -Method "GET" -Endpoint "/alerts?page=1&page_size=1" -Description "Get alert for timeline delete test"
if ($alertsResponse.Status -eq "PASS" -and $alertsResponse.Response) {
    try {
        $alertData = $alertsResponse.Response | ConvertFrom-Json
        if ($alertData.alerts -and $alertData.alerts.Count -gt 0) {
            $alertIdToDelete = $alertData.alerts[0].id
            Write-Log "Testing timeline alert DELETE on ID: $alertIdToDelete" "INFO"
            Test-ApiRequest -Name "timeline_alert_delete" -Method "DELETE" -Endpoint "/timeline/alerts/$alertIdToDelete" -Description "Delete alert from timeline"
        }
    } catch {
        Write-Log "Could not parse alerts response for timeline delete: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 4: Dashboard API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "dashboard_stats" -Method "GET" -Endpoint "/dashboard/collection-stats" -Description "Get collection statistics" -SaveResponse

Write-Log "========================================" "INFO"
Write-Log "Part 5: Rules API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "rules_list" -Method "GET" -Endpoint "/rules?page=1&page_size=20" -Description "List all rules" -SaveResponse
Test-ApiRequest -Name "rules_list_enabled" -Method "GET" -Endpoint "/rules?enabled=true&page_size=20" -Description "List enabled rules"
Test-ApiRequest -Name "rules_templates" -Method "GET" -Endpoint "/rules/templates" -Description "List rule templates"
Test-ApiRequest -Name "rules_templates_powershell" -Method "GET" -Endpoint "/rules/templates/powershell_detection" -Description "Get PowerShell template"
Test-ApiRequest -Name "rules_validate" -Method "POST" -Endpoint "/rules/validate" -Body '{"name":"TestRule","event_type":"single","conditions":[]}' -Description "Validate rule"
Test-ApiRequest -Name "rules_export" -Method "GET" -Endpoint "/rules/export?format=json" -Description "Export rules"

$rulesResponse = Test-ApiRequest -Name "rules_list_first" -Method "GET" -Endpoint "/rules?page=1&page_size=1" -Description "Get first rule"
if ($rulesResponse.Status -eq "PASS" -and $rulesResponse.Response) {
    try {
        $ruleData = $rulesResponse.Response | ConvertFrom-Json
        if ($ruleData.rules -and $ruleData.rules.Count -gt 0) {
            $firstRuleName = $ruleData.rules[0].name
            Write-Log "Testing rule operations on: $firstRuleName" "INFO"
            
            Test-ApiRequest -Name "rules_get" -Method "GET" -Endpoint "/rules/$firstRuleName" -Description "Get specific rule"
            Test-ApiRequest -Name "rules_toggle" -Method "POST" -Endpoint "/rules/$firstRuleName/toggle" -Description "Toggle rule"
            Test-ApiRequest -Name "rules_update" -Method "PUT" -Endpoint "/rules/$firstRuleName" -Body '{"description":"Updated description","severity":"low"}' -Description "Update rule"
            Test-ApiJsonPost -Name "rules_create" -Endpoint "/rules" -JsonBody @{name="APITestRule";description="Test rule from API";event_type="single";enabled=$false;severity="medium";conditions=@()} -Description "Create new rule"
            Test-ApiRequest -Name "rules_delete" -Method "DELETE" -Endpoint "/rules/APITestRule" -Description "Delete test rule"
        }
    } catch {
        Write-Log "Could not parse rules response: $($_.Exception.Message)" "WARN"
    }
}

Test-ApiJsonPost -Name "rules_import" -Endpoint "/rules/import" -JsonBody @{file_path="test_rules.json"} -Description "Import rules from file"
Test-ApiJsonPost -Name "rules_templates_instantiate" -Endpoint "/rules/templates/powershell_detection/instantiate" -JsonBody @{name="APITestPowerShellRule";parameters=@{event_id=4103}} -Description "Instantiate rule from template"

Write-Log "========================================" "INFO"
Write-Log "Part 6: System API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "system_info" -Method "GET" -Endpoint "/system/info" -Description "Get system info" -SaveResponse
Test-ApiRequest -Name "system_metrics" -Method "GET" -Endpoint "/system/metrics" -Description "Get system metrics"
Test-ApiRequest -Name "system_processes" -Method "GET" -Endpoint "/system/processes?page=1&page_size=10" -Description "List processes" -SaveResponse
Test-ApiRequest -Name "system_network" -Method "GET" -Endpoint "/system/network" -Description "Get network connections"
Test-ApiRequest -Name "system_users" -Method "GET" -Endpoint "/system/users" -Description "Get local users"
Test-ApiRequest -Name "system_tasks" -Method "GET" -Endpoint "/system/tasks" -Description "Get scheduled tasks"
Test-ApiRequest -Name "system_dlls" -Method "GET" -Endpoint "/system/dlls?page_size=10" -Description "Get loaded DLLs"
Test-ApiRequest -Name "system_drivers" -Method "GET" -Endpoint "/system/drivers" -Description "Get kernel drivers"
Test-ApiRequest -Name "system_env" -Method "GET" -Endpoint "/system/env" -Description "Get environment variables"
Test-ApiRequest -Name "system_registry" -Method "GET" -Endpoint "/system/registry" -Description "Get registry stats"

$processesResponse = Test-ApiRequest -Name "system_processes_first" -Method "GET" -Endpoint "/system/processes?page=1&page_size=1" -Description "Get first process for DLL test"
if ($processesResponse.Status -eq "PASS" -and $processesResponse.Response) {
    try {
        $procData = $processesResponse.Response | ConvertFrom-Json
        if ($procData.processes -and $procData.processes.Count -gt 0) {
            $firstPid = $procData.processes[0].pid
            Write-Log "Testing process DLLs for PID: $firstPid" "INFO"
            Test-ApiRequest -Name "system_process_dlls" -Method "GET" -Endpoint "/system/process/$firstPid/dlls" -Description "Get DLLs for specific process"
        }
    } catch {
        Write-Log "Could not parse processes response: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Step 0.3: Collect Forensic Data" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "forensics_collect" -Endpoint "/forensics/collect" -JsonBody @{targets=@("processes","network","registry");options=@{include_hidden=$true;deep_scan=$false}} -Description "Collect forensic data for testing" -SaveResponse

Write-Log "Waiting for forensics collection..." "INFO"
Start-Sleep -Seconds 3

Write-Log "========================================" "INFO"
Write-Log "Part 7: Forensics API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "forensics_hash_single" -Endpoint "/forensics/hash" -JsonBody @{paths=@("$env:SystemRoot\System32\notepad.exe");algorithms=@("md5","sha256")} -Description "Calculate hash for notepad.exe"
Test-ApiJsonPost -Name "forensics_hash_multiple" -Endpoint "/forensics/hash" -JsonBody @{paths=@("$env:SystemRoot\System32\notepad.exe","$env:SystemRoot\System32\cmd.exe");algorithms=@("sha256")} -Description "Calculate hashes for multiple files"
Test-ApiRequest -Name "forensics_signature" -Method "GET" -Endpoint "/forensics/signature?path=C:\Windows\System32\notepad.exe" -Description "Get file signature"
Test-ApiRequest -Name "forensics_is_signed" -Method "GET" -Endpoint "/forensics/is-signed?path=C:\Windows\System32\notepad.exe" -Description "Check if file is signed"
Test-ApiRequest -Name "forensics_evidence_list" -Method "GET" -Endpoint "/forensics/evidence?page=1&page_size=10" -Description "List evidence" -SaveResponse
Test-ApiJsonPost -Name "forensics_manifest" -Endpoint "/forensics/manifest" -JsonBody @{paths=@("$env:SystemRoot\System32\notepad.exe");include_hashes=$true} -Description "Generate forensic manifest"
Test-ApiRequest -Name "forensics_chain_custody" -Method "GET" -Endpoint "/forensics/chain-of-custody" -Description "Get chain of custody"
Test-ApiRequest -Name "forensics_memory_dump" -Method "GET" -Endpoint "/forensics/memory-dump" -Description "Get memory dump info"
Test-ApiRequest -Name "forensics_verify_hash" -Method "GET" -Endpoint "/forensics/verify-hash?hash=a1b2c3d4e5f6" -Description "Verify hash (expect not found)"

$evidenceResponse = Test-ApiRequest -Name "forensics_evidence_first" -Method "GET" -Endpoint "/forensics/evidence?page=1&page_size=1" -Description "Get first evidence for detail test"
if ($evidenceResponse.Status -eq "PASS" -and $evidenceResponse.Response) {
    try {
        $evidenceData = $evidenceResponse.Response | ConvertFrom-Json
        if ($evidenceData.evidence -and $evidenceData.evidence.Count -gt 0) {
            $firstEvidenceId = $evidenceData.evidence[0].id
            Write-Log "Testing forensics evidence detail for ID: $firstEvidenceId" "INFO"
            Test-ApiRequest -Name "forensics_evidence_detail" -Method "GET" -Endpoint "/forensics/evidence/$firstEvidenceId" -Description "Get evidence details"
        }
    } catch {
        Write-Log "Could not parse evidence response: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Step 0.4: Start Monitor" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "monitor_config" -Endpoint "/monitor/config" -JsonBody @{process_monitoring=@{enabled=$true;interval_ms=3000};network_monitoring=@{enabled=$true;interval_ms=5000};dns_monitoring=@{enabled=$false}} -Description "Configure monitor"
Test-ApiJsonPost -Name "monitor_action_start" -Endpoint "/monitor/action" -JsonBody @{action="start"} -Description "Start monitoring"

Write-Log "Waiting for monitor to collect data..." "INFO"
Start-Sleep -Seconds 5

Write-Log "========================================" "INFO"
Write-Log "Part 8: Monitor API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "monitor_stats" -Method "GET" -Endpoint "/monitor/stats" -Description "Get monitor statistics" -SaveResponse
Test-ApiRequest -Name "monitor_events_all" -Method "GET" -Endpoint "/monitor/events?limit=20" -Description "List all monitor events"
Test-ApiRequest -Name "monitor_events_process" -Method "GET" -Endpoint "/monitor/events?type=process&limit=10" -Description "List process events"
Test-ApiRequest -Name "monitor_events_network" -Method "GET" -Endpoint "/monitor/events?type=network&limit=10" -Description "List network events"
Test-ApiRequest -Name "monitor_events_dns" -Method "GET" -Endpoint "/monitor/events?type=dns&limit=10" -Description "List DNS events"
Test-ApiRequest -Name "monitor_events_severity" -Method "GET" -Endpoint "/monitor/events?severity=high&limit=10" -Description "List high severity events"
Test-ApiJsonPost -Name "monitor_action_stop" -Endpoint "/monitor/action" -JsonBody @{action="stop"} -Description "Stop monitoring"

if ($EnableSSE) {
    Write-Log "========================================" "INFO"
    Write-Log "Part 8.5: SSE Stream Tests" "INFO"
    Write-Log "========================================" "INFO"
    
    Test-SseStream -Name "monitor_events_stream" -Endpoint "/monitor/events/stream" -TimeoutSeconds 10
}

Write-Log "========================================" "INFO"
Write-Log "Part 9: Reports API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "reports_list" -Method "GET" -Endpoint "/reports" -Description "List reports" -SaveResponse
Test-ApiRequest -Name "report_templates" -Method "GET" -Endpoint "/report-templates" -Description "List report templates"
Test-ApiRequest -Name "report_templates_security" -Method "GET" -Endpoint "/report-templates/security_summary" -Description "Get security summary template"

$reportResponse = Test-ApiJsonPost -Name "reports_generate_summary" -Endpoint "/reports" -JsonBody @{type="security_summary";format="json";title="API Test Report";description="Generated by API test script"} -Description "Generate summary report" -SaveResponse
if ($reportResponse.Status -eq "PASS" -and $reportResponse.Response) {
    try {
        $reportData = $reportResponse.Response | ConvertFrom-Json
        if ($reportData.id) {
            Write-Log "Report generated with ID: $($reportData.id)" "INFO"
            Start-Sleep -Seconds 2
            
            Test-ApiRequest -Name "reports_get" -Method "GET" -Endpoint "/reports/$($reportData.id)" -Description "Get report details"
        }
    } catch {
        Write-Log "Could not parse report response: $($_.Exception.Message)" "WARN"
    }
}

Test-ApiJsonPost -Name "reports_generate_alert" -Endpoint "/reports" -JsonBody @{type="alert_report";format="json"} -Description "Generate alert report"
Test-ApiJsonPost -Name "reports_generate_event" -Endpoint "/reports" -JsonBody @{type="event_report";format="json"} -Description "Generate event report"
Test-ApiJsonPost -Name "reports_generate_timeline" -Endpoint "/reports" -JsonBody @{type="timeline_report";format="json"} -Description "Generate timeline report"
Test-ApiRequest -Name "reports_export_json" -Method "GET" -Endpoint "/reports/export?format=json" -Description "Export reports as JSON"
Test-ApiRequest -Name "reports_export_csv" -Method "GET" -Endpoint "/reports/export?format=csv" -Description "Export reports as CSV"

Test-ApiRequest -Name "report_templates_alert" -Method "GET" -Endpoint "/report-templates/alert_details" -Description "Get alert details template"
Test-ApiJsonPost -Name "report_templates_create" -Endpoint "/report-templates" -JsonBody @{name="custom_test_report";description="Custom test report";content="<html>Test</html>"} -Description "Create custom report template"
Test-ApiRequest -Name "report_templates_get_new" -Method "GET" -Endpoint "/report-templates/custom_test_report" -Description "Get newly created template"
Test-ApiRequest -Name "report_templates_delete" -Method "DELETE" -Endpoint "/report-templates/custom_test_report" -Description "Delete custom template"

$reportsListResponse = Test-ApiRequest -Name "reports_list_first" -Method "GET" -Endpoint "/reports?page=1&page_size=1" -Description "Get first report for download test"
if ($reportsListResponse.Status -eq "PASS" -and $reportsListResponse.Response) {
    try {
        $reportsData = $reportsListResponse.Response | ConvertFrom-Json
        if ($reportsData.reports -and $reportsData.reports.Count -gt 0) {
            $firstReportId = $reportsData.reports[0].id
            Write-Log "Testing report download for ID: $firstReportId" "INFO"
            Test-ApiRequest -Name "reports_download" -Method "GET" -Endpoint "/reports/$firstReportId/download" -Description "Download report file" -AllowRedirect
        }
    } catch {
        Write-Log "Could not parse reports response for download test: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 10: UEBA API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "ueba_analyze" -Endpoint "/ueba/analyze" -JsonBody @{start_time="2024-01-01T00:00:00Z";end_time="2024-12-31T23:59:59Z"} -Description "Analyze user behavior" -SaveResponse
Test-ApiRequest -Name "ueba_profiles" -Method "GET" -Endpoint "/ueba/profiles?page=1&page_size=10" -Description "Get user profiles" -SaveResponse
Test-ApiRequest -Name "ueba_anomaly_time" -Method "GET" -Endpoint "/ueba/anomaly/unusual_time" -Description "Get unusual time anomalies"
Test-ApiRequest -Name "ueba_anomaly_location" -Method "GET" -Endpoint "/ueba/anomaly/unusual_location" -Description "Get unusual location anomalies"
Test-ApiRequest -Name "ueba_anomaly_command" -Method "GET" -Endpoint "/ueba/anomaly/unusual_command" -Description "Get unusual command anomalies"
Test-ApiRequest -Name "ueba_anomaly_process" -Method "GET" -Endpoint "/ueba/anomaly/unusual_process" -Description "Get unusual process anomalies"

Write-Log "========================================" "INFO"
Write-Log "Part 11: Correlation API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "correlation_analyze_default" -Endpoint "/correlation/analyze" -JsonBody @{window="5m"} -Description "Run correlation analysis" -SaveResponse
Test-ApiJsonPost -Name "correlation_analyze_10m" -Endpoint "/correlation/analyze" -JsonBody @{window="10m"} -Description "Run correlation with 10m window"
Test-ApiJsonPost -Name "correlation_analyze_rules" -Endpoint "/correlation/analyze" -JsonBody @{rules=@("BruteForceDetection","SuspiciousProcessCreation");window="5m"} -Description "Correlation with specific rules"
Test-ApiJsonPost -Name "correlation_analyze_time" -Endpoint "/correlation/analyze" -JsonBody @{start_time="2024-01-01T00:00:00Z";end_time="2024-12-31T23:59:59Z";window="5m"} -Description "Correlation with time range"

Write-Log "========================================" "INFO"
Write-Log "Part 12: Query API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "query_count" -Endpoint "/query/execute" -JsonBody @{sql="SELECT COUNT(*) FROM events";limit=10} -Description "Execute COUNT query"
Test-ApiJsonPost -Name "query_select" -Endpoint "/query/execute" -JsonBody @{sql="SELECT * FROM events LIMIT 5";limit=10} -Description "Execute SELECT query"
Test-ApiJsonPost -Name "query_pragma" -Endpoint "/query/execute" -JsonBody @{sql="PRAGMA table_info(events)"} -Description "Execute PRAGMA query"
Test-ApiJsonPost -Name "query_rules" -Endpoint "/query/execute" -JsonBody @{sql="SELECT * FROM rules LIMIT 5"} -Description "Query rules table"
Test-ApiJsonPost -Name "query_alerts" -Endpoint "/query/execute" -JsonBody @{sql="SELECT * FROM alerts LIMIT 5"} -Description "Query alerts table"
Test-ApiJsonPost -Name "query_join" -Endpoint "/query/execute" -JsonBody @{sql="SELECT e.event_id, COUNT(*) as cnt FROM events e GROUP BY e.event_id LIMIT 10"} -Description "Execute JOIN query"

Write-Log "========================================" "INFO"
Write-Log "Part 13: Persistence API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "persistence_categories" -Method "GET" -Endpoint "/persistence/categories" -Description "Get persistence categories" -SaveResponse
Test-ApiRequest -Name "persistence_techniques" -Method "GET" -Endpoint "/persistence/techniques" -Description "Get MITRE techniques" -SaveResponse
Test-ApiRequest -Name "persistence_detect_all" -Method "GET" -Endpoint "/persistence/detect" -Description "Detect all persistence" -SaveResponse
Test-ApiRequest -Name "persistence_detect_runkey" -Method "GET" -Endpoint "/persistence/detect?category=runkey" -Description "Detect runkey persistence"
Test-ApiRequest -Name "persistence_detect_service" -Method "GET" -Endpoint "/persistence/detect?category=service" -Description "Detect service persistence"
Test-ApiRequest -Name "persistence_detect_scheduled" -Method "GET" -Endpoint "/persistence/detect?category=scheduled_task" -Description "Detect scheduled task persistence"
Test-ApiRequest -Name "persistence_detect_wmi" -Method "GET" -Endpoint "/persistence/detect?category=wmi" -Description "Detect WMI persistence"

if ($EnableSSE) {
    Test-SseStream -Name "persistence_detect_stream" -Endpoint "/persistence/detect/stream" -TimeoutSeconds 10
}

Write-Log "========================================" "INFO"
Write-Log "Part 14: Analyze API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "analyzers_list" -Method "GET" -Endpoint "/analyzers" -Description "List all analyzers" -SaveResponse
Test-ApiRequest -Name "analyzers_hash" -Method "GET" -Endpoint "/analyzers/hash" -Description "Get hash analyzer details"
Test-ApiRequest -Name "analyzers_memory" -Method "GET" -Endpoint "/analyzers/memory" -Description "Get memory analyzer details"
Test-ApiJsonPost -Name "analyze_hash" -Endpoint "/analyze/hash" -JsonBody @{target="$env:SystemRoot\System32\notepad.exe";options=@{deep_scan=$false}} -Description "Analyze file hash"

Write-Log "========================================" "INFO"
Write-Log "Part 15: Settings API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "settings_get" -Method "GET" -Endpoint "/settings" -Description "Get current settings" -SaveResponse
Test-ApiJsonPost -Name "settings_update" -Endpoint "/settings" -JsonBody @{alert_retention_days=60;log_level="debug"} -Description "Update settings"
Test-ApiRequest -Name "settings_get_after" -Method "GET" -Endpoint "/settings" -Description "Verify settings update"
Test-ApiRequest -Name "settings_reset" -Method "POST" -Endpoint "/settings/reset" -Description "Reset settings to defaults"

Write-Log "========================================" "INFO"
Write-Log "Part 16: Suppress API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "suppress_list" -Method "GET" -Endpoint "/suppress?page=1&page_size=10" -Description "List suppression rules" -SaveResponse
Test-ApiJsonPost -Name "suppress_create" -Endpoint "/suppress" -JsonBody @{name="APITestSuppress";description="Test suppression";enabled=$true;filter=@{event_ids=@(4624);users=@("TestUser")}} -Description "Create suppression rule"

$suppressResponse = Test-ApiRequest -Name "suppress_list_after" -Method "GET" -Endpoint "/suppress?page=1&page_size=10" -Description "List suppressions after create"
if ($suppressResponse.Status -eq "PASS" -and $suppressResponse.Response) {
    try {
        $suppressData = $suppressResponse.Response | ConvertFrom-Json
        if ($suppressData.suppressions -and $suppressData.suppressions.Count -gt 0) {
            $firstSuppress = $suppressData.suppressions[0]
            if ($firstSuppress.id) {
                Test-ApiRequest -Name "suppress_get" -Method "GET" -Endpoint "/suppress/$($firstSuppress.id)" -Description "Get specific suppression"
                Test-ApiRequest -Name "suppress_toggle" -Method "POST" -Endpoint "/suppress/$($firstSuppress.id)/toggle" -Description "Toggle suppression"
                Test-ApiRequest -Name "suppress_delete" -Method "DELETE" -Endpoint "/suppress/$($firstSuppress.id)" -Description "Delete suppression"
            }
        }
    } catch {
        Write-Log "Could not parse suppress response: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 17: Multi API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "multi_analyze_security" -Endpoint "/multi/analyze" -JsonBody @{sources=@("security")} -Description "Multi-source analysis (security)"
Test-ApiJsonPost -Name "multi_analyze_multiple" -Endpoint "/multi/analyze" -JsonBody @{sources=@("security","system","sysmon")} -Description "Multi-source analysis (multiple)"
Test-ApiJsonPost -Name "multi_analyze_time" -Endpoint "/multi/analyze" -JsonBody @{sources=@("security");start_time="2024-01-01T00:00:00Z";end_time="2024-12-31T23:59:59Z"} -Description "Multi-source with time filter"
Test-ApiRequest -Name "multi_lateral" -Method "GET" -Endpoint "/multi/lateral" -Description "Detect lateral movement"
Test-ApiRequest -Name "multi_lateral_time" -Method "GET" -Endpoint "/multi/lateral?start_time=2024-01-01T00:00:00Z" -Description "Lateral movement with time filter"

Write-Log "========================================" "INFO"
Write-Log "Part 18: Collect API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiJsonPost -Name "collect_start_security" -Endpoint "/collect" -JsonBody @{sources=@("security","system")} -Description "Start collection"
Test-ApiRequest -Name "collect_status" -Method "GET" -Endpoint "/collect/status?task_id=test" -Description "Get collection status" -ExpectedStatus 0
Test-ApiJsonPost -Name "collect_import" -Endpoint "/collect/import" -JsonBody @{file_path="test.evtx";source_type="evtx"} -Description "Import collected data"

Write-Log "========================================" "INFO"
Write-Log "Part 19: Import API" "INFO"
Write-Log "========================================" "INFO"

if (-not $SkipImportTests -and $TestEvtxFile -and (Test-Path $TestEvtxFile)) {
    Test-ApiJsonPost -Name "import_logs_again" -Endpoint "/import/logs" -JsonBody @{files=@($TestEvtxFile);alert_on_import=$true} -Description "Import with alert analysis"
    Test-ApiRequest -Name "import_status" -Method "GET" -Endpoint "/import/status?path=$TestEvtxFile" -Description "Get import status"
} else {
    Test-ApiJsonPost -Name "import_logs_empty" -Endpoint "/import/logs" -JsonBody @{files=@();alert_on_import=$false} -Description "Import empty (no files)"
    Test-ApiRequest -Name "import_status_none" -Method "GET" -Endpoint "/import/status?path=nonexistent.evtx" -Description "Get import status (non-existent)"
}

Write-Log "========================================" "INFO"
Write-Log "Part 20: Live Events API" "INFO"
Write-Log "========================================" "INFO"

if (-not $SkipLiveTests) {
    Test-ApiRequest -Name "live_stats" -Method "GET" -Endpoint "/live/stats" -Description "Get live stats"
    
    if ($EnableSSE) {
        Test-SseStream -Name "live_events_stream" -Endpoint "/live/events" -TimeoutSeconds 10
    }
} else {
    Write-Log "Skipping live events tests (use -FullTest to enable)" "WARN"
}

Write-Log "========================================" "INFO"
Write-Log "Part 21: Policy API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "policy_templates_list" -Method "GET" -Endpoint "/policy-templates" -Description "List policy templates"
Test-ApiRequest -Name "policy_instances_list" -Method "GET" -Endpoint "/policy-instances" -Description "List policy instances"
Test-ApiJsonPost -Name "policy_create" -Endpoint "/policies" -JsonBody @{name="APITestPolicy";rules=@();settings=@{}} -Description "Create policy"
Test-ApiRequest -Name "policy_delete" -Method "DELETE" -Endpoint "/policies/APITestPolicy" -Description "Delete policy"

$policyTemplatesResponse = Test-ApiRequest -Name "policy_templates_first" -Method "GET" -Endpoint "/policy-templates?page=1&page_size=1" -Description "Get first policy template"
if ($policyTemplatesResponse.Status -eq "PASS" -and $policyTemplatesResponse.Response) {
    try {
        $templateData = $policyTemplatesResponse.Response | ConvertFrom-Json
        if ($templateData.templates -and $templateData.templates.Count -gt 0) {
            $firstTemplateName = $templateData.templates[0].name
            Write-Log "Testing policy template detail for: $firstTemplateName" "INFO"
            Test-ApiRequest -Name "policy_templates_get" -Method "GET" -Endpoint "/policy-templates/$firstTemplateName" -Description "Get policy template details"
        }
    } catch {
        Write-Log "Could not parse policy templates response: $($_.Exception.Message)" "WARN"
    }
}

Test-ApiJsonPost -Name "policy_templates_create" -Endpoint "/policy-templates" -JsonBody @{name="APITestPolicyTemplate";description="Test template";rules=@("rule1");settings=@{}} -Description "Create policy template"
Test-ApiJsonPost -Name "policy_templates_apply" -Endpoint "/policy-templates/apply" -JsonBody @{template_name="baseline_policy";targets=@("localhost")} -Description "Apply policy template"
Test-ApiRequest -Name "policy_templates_delete" -Method "DELETE" -Endpoint "/policy-templates/APITestPolicyTemplate" -Description "Delete policy template"

$policyInstancesResponse = Test-ApiRequest -Name "policy_instances_first" -Method "GET" -Endpoint "/policy-instances?page=1&page_size=1" -Description "Get first policy instance"
if ($policyInstancesResponse.Status -eq "PASS" -and $policyInstancesResponse.Response) {
    try {
        $instanceData = $policyInstancesResponse.Response | ConvertFrom-Json
        if ($instanceData.instances -and $instanceData.instances.Count -gt 0) {
            $firstInstanceKey = $instanceData.instances[0].key
            Write-Log "Testing policy instance delete for key: $firstInstanceKey" "INFO"
            Test-ApiRequest -Name "policy_instances_delete" -Method "DELETE" -Endpoint "/policy-instances/$firstInstanceKey" -Description "Delete policy instance"
        }
    } catch {
        Write-Log "Could not parse policy instances response: $($_.Exception.Message)" "WARN"
    }
}

Write-Log "========================================" "INFO"
Write-Log "Part 22: UI API" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "ui_dashboard" -Method "GET" -Endpoint "/ui/dashboard" -Description "Get UI dashboard" -SaveResponse
Test-ApiRequest -Name "ui_dashboard_refresh" -Method "GET" -Endpoint "/ui/dashboard?refresh=60" -Description "Get UI dashboard with refresh"
Test-ApiRequest -Name "ui_alerts_groups_rule" -Method "GET" -Endpoint "/ui/alerts/groups?group_by=rule&page_size=10" -Description "Get alerts grouped by rule"
Test-ApiRequest -Name "ui_alerts_groups_severity" -Method "GET" -Endpoint "/ui/alerts/groups?group_by=severity&page_size=10" -Description "Get alerts grouped by severity"
Test-ApiRequest -Name "ui_alerts_groups_time" -Method "GET" -Endpoint "/ui/alerts/groups?group_by=time&page_size=10" -Description "Get alerts grouped by time"
Test-ApiRequest -Name "ui_metrics_1h" -Method "GET" -Endpoint "/ui/metrics?period=1h" -Description "Get UI metrics (1h)"
Test-ApiRequest -Name "ui_metrics_24h" -Method "GET" -Endpoint "/ui/metrics?period=24h" -Description "Get UI metrics (24h)"
Test-ApiRequest -Name "ui_metrics_7d" -Method "GET" -Endpoint "/ui/metrics?period=7d" -Description "Get UI metrics (7d)"
Test-ApiRequest -Name "ui_events_dist_level" -Method "GET" -Endpoint "/ui/events/distribution?field=level&limit=10" -Description "Get event distribution by level"
Test-ApiRequest -Name "ui_events_dist_source" -Method "GET" -Endpoint "/ui/events/distribution?field=source&limit=10" -Description "Get event distribution by source"
Test-ApiRequest -Name "ui_events_dist_logname" -Method "GET" -Endpoint "/ui/events/distribution?field=log_name&limit=10" -Description "Get event distribution by log name"

Write-Log "========================================" "INFO"
Write-Log "Part 23: Error Input Tests (Negative Tests)" "INFO"
Write-Log "========================================" "INFO"

Test-ApiRequest -Name "error_invalid_event_id" -Method "GET" -Endpoint "/events/invalid_id" -Description "Invalid event ID" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_alert_id" -Method "GET" -Endpoint "/alerts/999999999" -Description "Non-existent alert ID" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_rule_name" -Method "GET" -Endpoint "/rules/NonExistentRule12345" -Description "Non-existent rule" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_report_id" -Method "GET" -Endpoint "/reports/nonexistent_report_12345" -Description "Non-existent report" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_suppress_id" -Method "GET" -Endpoint "/suppress/999999999" -Description "Non-existent suppression rule" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_settings_path" -Method "GET" -Endpoint "/settings/nonexistent" -Description "Invalid settings path" -ExpectedStatus 404
Test-ApiRequest -Name "error_invalid_query_sql" -Method "POST" -Endpoint "/query/execute" -Body '{"sql":"DROP TABLE events"}' -Description "SQL injection attempt (DROP)" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_invalid_query_syntax" -Method "POST" -Endpoint "/query/execute" -Body '{"sql":"SELECT * FROM"}' -Description "Invalid SQL syntax" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_missing_required_field" -Method "POST" -Endpoint "/query/execute" -Body '{"limit":10}' -Description "Missing SQL field" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_invalid_page_size" -Method "GET" -Endpoint "/events?page_size=999999" -Description "Invalid page size" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_invalid_severity" -Method "GET" -Endpoint "/alerts?severity=invalid" -Description "Invalid severity value" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_negative_page" -Method "GET" -Endpoint "/events?page=-1" -Description "Negative page number" -ExpectedStatus 400 -SkipRetry
Test-ApiRequest -Name "error_future_time_range" -Method "GET" -Endpoint "/timeline?start_time=2099-01-01T00:00:00Z" -Description "Future time range (should return empty)" -ExpectedStatus 200 -SkipRetry
Test-ApiRequest -Name "error_empty_import" -Method "POST" -Endpoint "/import/logs" -Body '{"files":[]}' -Description "Import with empty files array" -ExpectedStatus 400 -SkipRetry

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
    BaseUrl = $Script:BaseUrl
    TestEvtxFile = $TestEvtxFile
    MaxRetries = $MaxRetries
    RetryDelayMs = $RetryDelayMs
    EnableSSE = $EnableSSE
    EnableValidation = $EnableValidation
    EnablePerformance = $EnablePerformance
    PreparedData = $Script:PreparedData
    PerformanceData = $Script:PerformanceData
    TestResults = $Script:TestResults
} | ConvertTo-Json -Depth 10

$summary | Out-File "$OutputDir\test_summary.json" -Encoding UTF8

$resultsCsv = $Script:TestResults | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Method = $_.Method
        Endpoint = $_.Endpoint
        Description = $_.Description
        StatusCode = $_.StatusCode
        DurationSeconds = [math]::Round($_.Duration.TotalSeconds, 3)
        Status = $_.Status
        RetryCount = $_.RetryCount
        Timestamp = $_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
    }
}
$resultsCsv | Export-Csv -Path "$OutputDir\test_results.csv" -NoTypeInformation -Encoding UTF8

if ($EnablePerformance -and $Script:PerformanceData.Count -gt 0) {
    $perfData = @()
    foreach ($key in $Script:PerformanceData.Keys) {
        $perfData += [PSCustomObject]@{
            TestName = $key
            DurationSeconds = [math]::Round($Script:PerformanceData[$key].Duration, 3)
            StatusCode = $Script:PerformanceData[$key].StatusCode
            RetryCount = $Script:PerformanceData[$key].RetryCount
        }
    }
    $perfData | Sort-Object DurationSeconds -Descending | Export-Csv -Path "$OutputDir\performance.csv" -NoTypeInformation -Encoding UTF8
}

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
        Write-Log "  - $($test.Name): $($test.Method) $($test.Endpoint)" "ERROR"
        if ($test.Response -and $test.Response.Length -gt 0) {
            $responsePreview = $test.Response
            if ($responsePreview.Length -gt 200) {
                $responsePreview = $responsePreview.Substring(0, 200) + "..."
            }
            Write-Log "    Response: $responsePreview" "ERROR"
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "API Test Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Output Dir: $OutputDir" -ForegroundColor Yellow
Write-Host "Summary: $OutputDir\test_summary.json" -ForegroundColor Yellow
Write-Host "CSV: $OutputDir\test_results.csv" -ForegroundColor Yellow
if ($EnablePerformance) {
    Write-Host "Performance: $OutputDir\performance.csv" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Result: $passCount/$totalCount passed" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })

exit $(if ($failCount -gt 0 -or $errorCount -gt 0) { 1 } else { 0 })
