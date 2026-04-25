# Windows Build Script for WinLogAnalyzer-Go
#
# 使用方法:
#   .\build.ps1                    - Build for amd64 (default)
#   .\build.ps1 -Target 386       - Build for 32-bit
#   .\build.ps1 -Target arm64     - Build for ARM64
#   .\build.ps1 -Clean             - Clean build artifacts

param(
    [string]$Target = "amd64",
    [string]$Output = "dist",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Get project root - parent of scripts directory
$PROJECT_ROOT = Split-Path -Parent $PSScriptRoot

if (-not $PROJECT_ROOT -or $PROJECT_ROOT -eq "") {
    $PROJECT_ROOT = $PSScriptRoot
}

# Normalize path
$PROJECT_ROOT = (Resolve-Path $PROJECT_ROOT -ErrorAction SilentlyContinue).Path
if (-not $PROJECT_ROOT) {
    Write-Host "[ERROR] Could not determine project root" -ForegroundColor Red
    exit 1
}

Write-Host "=== WinLogAnalyzer Windows Build ===" -ForegroundColor Cyan
Write-Host "Project: $PROJECT_ROOT"
Write-Host "Target:  $Target"
Write-Host "Output:  $Output"
Write-Host ""

if ($Clean) {
    Write-Host "[CLEAN] Removing previous build artifacts..." -ForegroundColor Yellow
    $distPath = Join-Path $PROJECT_ROOT $Output
    if (Test-Path $distPath) {
        Remove-Item -Recurse -Force $distPath
    }
    $exePath = Join-Path $PROJECT_ROOT "winalog.exe"
    if (Test-Path $exePath) {
        Remove-Item -Force $exePath
    }
    Write-Host "[CLEAN] Done" -ForegroundColor Green
    Write-Host ""
}

$outputPath = Join-Path $PROJECT_ROOT $Output
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

switch ($Target) {
    "amd64" { $GOOS = "windows"; $GOARCH = "amd64" }
    "386"   { $GOOS = "windows"; $GOARCH = "386" }
    "arm64" { $GOOS = "windows"; $GOARCH = "arm64" }
    default {
        Write-Host "[ERROR] Unknown target: $Target" -ForegroundColor Red
        Write-Host "Valid targets: amd64, 386, arm64" -ForegroundColor Yellow
        exit 1
    }
}

$OUTPUT_NAME = "winalog-$Target.exe"
$OUTPUT_FILE = Join-Path $outputPath $OUTPUT_NAME

Write-Host "[BUILD] Compiling for $GOOS/$GOARCH..." -ForegroundColor Yellow

$env:GOOS = $GOOS
$env:GOARCH = $GOARCH

try {
    Push-Location $PROJECT_ROOT
    
    # Ensure output directory exists
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }
    
    # Copy static files for embedding
    $statichDir = Join-Path $PROJECT_ROOT "internal\api\_statich"
    if (-not (Test-Path $statichDir)) {
        New-Item -ItemType Directory -Path $statichDir -Force | Out-Null
    }
    $guiDist = Join-Path $PROJECT_ROOT "internal\gui\dist"
    if (Test-Path $guiDist) {
        Copy-Item -Path "$guiDist\*" -Destination $statichDir -Recurse -Force
    }
    
    go build -ldflags="-s -w" -o $OUTPUT_FILE ./cmd/winalog
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
    
    Pop-Location
    
    if (-not (Test-Path $OUTPUT_FILE)) {
        throw "Build completed but output file not found: $OUTPUT_FILE"
    }
    
    $fileSize = (Get-Item $OUTPUT_FILE).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    
    Write-Host ""
    Write-Host "[BUILD] Success!" -ForegroundColor Green
    Write-Host "  Output: $OUTPUT_FILE"
    Write-Host "  Size:   $fileSizeMB MB"
    Write-Host ""
    
    # Verify PE header
    if (Test-Path $OUTPUT_FILE) {
        Write-Host "[VERIFY] File exists: OK" -ForegroundColor Green
        $bytes = [System.IO.File]::ReadAllBytes($OUTPUT_FILE)[0..1]
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            Write-Host "[VERIFY] PE header: OK (MZ)" -ForegroundColor Green
        } else {
            Write-Host "[VERIFY] PE header: WARNING (not a valid Windows executable)" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host ""
    Write-Host "[ERROR] Build failed: $_" -ForegroundColor Red
    if (Test-Path $PROJECT_ROOT) {
        Pop-Location 2>$null
    }
    exit 1
}

Write-Host "=== Build Complete ===" -ForegroundColor Cyan
