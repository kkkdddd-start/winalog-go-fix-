@echo off
REM Windows Build Script for WinLogAnalyzer-Go
REM
REM Usage:
REM   build.bat            - Build for amd64 (default)
REM   build.bat 386        - Build for 32-bit
REM   build.bat arm64      - Build for ARM64
REM   build.bat clean      - Clean build artifacts

setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0.."
set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

if "%1"=="clean" goto clean
if "%1"=="386" goto build_386
if "%1"=="arm64" goto build_arm64

:build_amd64
echo === Building WinLogAnalyzer for Windows amd64 ===
go build -ldflags="-s -w" -o "%PROJECT_ROOT%\dist\winalog-amd64.exe" ./cmd/winalog
if errorlevel 1 goto error
echo Build complete: %PROJECT_ROOT%\dist\winalog-amd64.exe
goto end

:build_386
echo === Building WinLogAnalyzer for Windows 386 ===
go build -ldflags="-s -w" -o "%PROJECT_ROOT%\dist\winalog-386.exe" ./cmd/winalog
if errorlevel 1 goto error
echo Build complete: %PROJECT_ROOT%\dist\winalog-386.exe
goto end

:build_arm64
echo === Building WinLogAnalyzer for Windows ARM64 ===
go build -ldflags="-s -w" -o "%PROJECT_ROOT%\dist\winalog-arm64.exe" ./cmd/winalog
if errorlevel 1 goto error
echo Build complete: %PROJECT_ROOT%\dist\winalog-arm64.exe
goto end

:clean
echo Cleaning build artifacts...
if exist "%PROJECT_ROOT%\dist" rmdir /s /q "%PROJECT_ROOT%\dist"
if exist "%PROJECT_ROOT%\winalog.exe" del /q "%PROJECT_ROOT%\winalog.exe"
echo Clean complete.
goto end

:error
echo.
echo [ERROR] Build failed!
exit /b 1

:end
endlocal
