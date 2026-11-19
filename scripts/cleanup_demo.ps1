# ==============================================================================
# MedTrust - Safe Demo Cleanup & Invariant Verification Script
# Safety: Removes demo_medtrust.db, .demo_kek.secret, .demo_offline_cache.
#         GUARANTEES NEVER TO TOUCH medtrust.db OR fast_cache_* CONTAINERS.
# ==============================================================================
[CmdletBinding()]
param (
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

# 1. Resolve Canonical Absolute Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = [System.IO.Path]::GetFullPath("$ScriptDir\..")
$BackendDir = [System.IO.Path]::GetFullPath("$ProjectRoot\backend")
$ProdDb = [System.IO.Path]::GetFullPath("$BackendDir\medtrust.db")
$DemoDb = [System.IO.Path]::GetFullPath("$BackendDir\demo_medtrust.db")
$DemoDbWal = [System.IO.Path]::GetFullPath("$BackendDir\demo_medtrust.db-wal")
$DemoDbShm = [System.IO.Path]::GetFullPath("$BackendDir\demo_medtrust.db-shm")
$DemoKekFile = [System.IO.Path]::GetFullPath("$BackendDir\.demo_kek.secret")
$DemoOfflineCache = [System.IO.Path]::GetFullPath("$BackendDir\.demo_offline_cache")
$BackendPidFile = [System.IO.Path]::GetFullPath("$ScriptDir\.demo_backend.pid")
$FrontendPidFile = [System.IO.Path]::GetFullPath("$ScriptDir\.demo_frontend.pid")

Write-Host "=== MedTrust Demo Teardown & Safety Cleanup ===" -ForegroundColor Cyan

# 2. Confirmation Prompt (if not -Force)
if (-not $Force) {
    Write-Warning "WARNING: This will terminate running demo processes on Ports 8001/5174."
    Write-Warning "Deleting .demo_kek.secret makes existing wrapped DEKs in demo_medtrust.db permanently undecryptable."
    $confirm = Read-Host "Proceed with demo cleanup? [y/N]"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Cleanup aborted by user." -ForegroundColor Yellow
        exit 0
    }
}

# 3. Terminate Tracked Demo Processes (Strictly by PID)
if (Test-Path $BackendPidFile) {
    $rawPid = (Get-Content $BackendPidFile -Raw).Trim()
    if ($rawPid -match '^\d+$') {
        $procId = [int]$rawPid
        try {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($p) {
                Write-Host "Stopping demo backend process tree (PID: $procId)..." -ForegroundColor Yellow
                cmd /c "taskkill /F /T /PID $procId 2>nul" | Out-Null
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800
            }
        } catch {
            Write-Warning "Could not stop PID $procId : $_"
        }
    }
    Remove-Item -Path $BackendPidFile -Force -ErrorAction SilentlyContinue
}

if (Test-Path $FrontendPidFile) {
    $rawPid = (Get-Content $FrontendPidFile -Raw).Trim()
    if ($rawPid -match '^\d+$') {
        $procId = [int]$rawPid
        try {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($p) {
                Write-Host "Stopping demo frontend process (PID: $procId)..." -ForegroundColor Yellow
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500
            }
        } catch {
            Write-Warning "Could not stop PID $procId : $_"
        }
    }
    Remove-Item -Path $FrontendPidFile -Force -ErrorAction SilentlyContinue
}

# 4. Safe Removal of Demo Database and Transient Keys
# Absolute Hardcoded Invariant Guard: NEVER DELETE medtrust.db
$DemoLogFile = [System.IO.Path]::GetFullPath("$BackendDir\.demo_uvicorn.log")
$DemoErrLogFile = [System.IO.Path]::GetFullPath("$BackendDir\.demo_uvicorn.err.log")
$targets = @($DemoDb, $DemoDbWal, $DemoDbShm, $DemoKekFile, $DemoLogFile, $DemoErrLogFile)
foreach ($target in $targets) {
    if (Test-Path $target) {
        $leaf = Split-Path -Leaf $target
        if ($leaf -eq "medtrust.db") {
            Write-Error "FATAL SAFETY VIOLATION: Attempted to delete production medtrust.db! Aborting immediately."
            exit 1
        }
        Remove-Item -Path $target -Force -ErrorAction SilentlyContinue
        Write-Host "[Cleanup] Removed: $leaf" -ForegroundColor Green
    }
}

if (Test-Path $DemoOfflineCache) {
    Remove-Item -Path $DemoOfflineCache -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[Cleanup] Removed: .demo_offline_cache directory" -ForegroundColor Green
}

# 5. Production Database Invariant Verification
if (Test-Path $ProdDb) {
    $PostHash = (Get-FileHash -Algorithm SHA256 $ProdDb).Hash
    $ExpectedHash = "B7B9447C13F4FA5D4B9979072C4849BA0049B9E1A073D07AF3A8466BD28190AD"
    if ($PostHash -eq $ExpectedHash) {
        Write-Host "[Verified] Production database SHA-256 intact: $PostHash" -ForegroundColor Green
    } else {
        Write-Error "CRITICAL INTEGRITY FAILURE: Production database hash changed! Expected: $ExpectedHash, Actual: $PostHash"
        exit 1
    }
} else {
    Write-Error "CRITICAL: Production database missing at $ProdDb!"
    exit 1
}

Write-Host "=== Demo cleanup complete. Workspace restored to clean idle state. ===" -ForegroundColor Cyan
