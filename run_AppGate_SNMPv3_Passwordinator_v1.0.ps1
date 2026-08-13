# AppGate SNMPv3 Configuration - PowerShell Wrapper
# Usage: .\run_AppGate_SNMPv3_Passwordinator_v1.0.ps1
param(
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonScript = Join-Path $ScriptDir "AppGate_SNMPv3_Passwordinator_v1.0.py"

if (-not (Test-Path $PythonScript)) {
    Write-Error "Python script not found at: $PythonScript"
    exit 1
}

Write-Host "Launching AppGate SNMPv3 Configuration Script..." -ForegroundColor Cyan
Write-Host ""

try {
    & $PythonExe $PythonScript
    exit $LASTEXITCODE
} catch {
    Write-Error "Failed to execute Python script: $_"
    exit 1
}
