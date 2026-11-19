# ==============================================================================
# MedTrust - Isolated Demo Frontend Runner
# Safety: Binds strictly to Port 5174, connects to Backend on Port 8001
# ==============================================================================
[CmdletBinding()]
param (
    [switch]$Foreground = $false
)

$ErrorActionPreference = "Stop"

# 1. Resolve Canonical Absolute Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = [System.IO.Path]::GetFullPath("$ScriptDir\..")
$FrontendDir = [System.IO.Path]::GetFullPath("$ProjectRoot\frontend")
$PidFile = [System.IO.Path]::GetFullPath("$ScriptDir\.demo_frontend.pid")

Write-Host "=== MedTrust Demo Frontend Initialization ===" -ForegroundColor Cyan
Write-Host "Working Directory : $FrontendDir"

# 2. Port Safety Check (Port 5174 strictly)
$PortCheck = cmd /c "netstat -ano | findstr :5174 | findstr LISTENING"
if ($PortCheck) {
    Write-Warning "Port 5174 is already listening:"
    Write-Host $PortCheck
    Write-Error "Cannot start demo frontend: Port 5174 is occupied. Please terminate existing process or run cleanup_demo.ps1."
    exit 1
}

# 3. Check Backend Readiness
try {
    $null = Invoke-RestMethod -Uri "http://localhost:8001/api/v1/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
    Write-Host "[Connectivity] Backend on Port 8001 is reachable." -ForegroundColor Green
} catch {
    Write-Warning "Backend on Port 8001 does not appear to be running. Launch run_demo_backend.ps1 first."
}

# 4. Launch Vite Dev Server on Port 5174
if ($Foreground) {
    Write-Host "Starting Vite development server in foreground on http://localhost:5174..." -ForegroundColor Cyan
    Set-Location $FrontendDir
    npx vite --port 5174
} else {
    Write-Host "Spawning background Vite process on http://localhost:5174..." -ForegroundColor Cyan
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "cmd.exe"
    $pinfo.Arguments = "/c npx vite --port 5174"
    $pinfo.WorkingDirectory = $FrontendDir
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($pinfo)
    $process.Id | Out-File -FilePath $PidFile -Encoding ascii -Force
    Write-Host "Demo Frontend process started (PID: $($process.Id))." -ForegroundColor Green

    # Wait for frontend port
    Write-Host "Waiting for Vite dev server on http://localhost:5174..." -NoNewline
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 800
        $listening = cmd /c "netstat -ano | findstr :5174"
        if ($listening) {
            $ready = $true
            break
        }
        Write-Host "." -NoNewline
    }

    if ($ready) {
        Write-Host " OK!" -ForegroundColor Green
        Write-Host "MedTrust Sovereign Portal is ready at http://localhost:5174" -ForegroundColor Green
    } else {
        Write-Warning " Frontend launched, listening verification timed out. Check PID $($process.Id)."
    }
}
