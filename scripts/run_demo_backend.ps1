# ==============================================================================
# MedTrust - Isolated Demo Backend Runner
# Safety: Binds strictly to Port 8001, uses demo_medtrust.db, never medtrust.db
# ==============================================================================
[CmdletBinding()]
param (
    [switch]$Foreground = $false,
    [switch]$RealFabric = $false
)

$ErrorActionPreference = "Stop"

# 1. Resolve Canonical Absolute Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = [System.IO.Path]::GetFullPath("$ScriptDir\..")
$BackendDir = [System.IO.Path]::GetFullPath("$ProjectRoot\backend")
$ProdDb = [System.IO.Path]::GetFullPath("$BackendDir\medtrust.db")
$DemoDb = [System.IO.Path]::GetFullPath("$BackendDir\demo_medtrust.db")
$DemoKekFile = [System.IO.Path]::GetFullPath("$BackendDir\.demo_kek.secret")
$DemoOfflineCache = [System.IO.Path]::GetFullPath("$BackendDir\.demo_offline_cache")
$PidFile = [System.IO.Path]::GetFullPath("$ScriptDir\.demo_backend.pid")

Write-Host "=== MedTrust Demo Backend Initialization ===" -ForegroundColor Cyan
Write-Host "Working Directory : $BackendDir"

# 2. Production Database Baseline Verification & Fail-Closed Guard
if (Test-Path $ProdDb) {
    $PreHash = (Get-FileHash -Algorithm SHA256 $ProdDb).Hash
    Write-Host "[Safety Guard] Production medtrust.db verified (SHA-256: $PreHash)" -ForegroundColor Green
} else {
    Write-Error "Production database not found at $ProdDb"
    exit 1
}

if ($DemoDb.ToLower() -eq $ProdDb.ToLower()) {
    Write-Error "CRITICAL SAFETY VIOLATION: Demo database path matches production database path!"
    exit 1
}

# 3. Port Safety Check (Port 8001 strictly)
$PortCheck = cmd /c "netstat -ano | findstr :8001 | findstr LISTENING"
if ($PortCheck) {
    Write-Warning "Port 8001 is already listening:"
    Write-Host $PortCheck
    Write-Error "Cannot start demo backend: Port 8001 is occupied. Please terminate existing process or run cleanup_demo.ps1."
    exit 1
}

# 4. Cryptographic Master KEK Provisioning (Zero-Disclosure, 32 bytes)
$kekHex = $null
if (Test-Path $DemoKekFile) {
    $loadedHex = (Get-Content $DemoKekFile -Raw).Trim()
    if ($loadedHex -match "^[0-9a-fA-F]{64}$") {
        $kekHex = $loadedHex
        Write-Host "[Security] Master KEK loaded from existing session file (32 bytes AES-256)." -ForegroundColor Green
    } else {
        Write-Error "Corrupted session key file at $DemoKekFile. Please remove with cleanup_demo.ps1."
        exit 1
    }
} else {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $kekHex = [System.BitConverter]::ToString($bytes) -replace '-'
    [System.IO.File]::WriteAllText($DemoKekFile, $kekHex)
    
    # Restrict NTFS permissions strictly to current user (Full control for owner)
    cmd /c "icacls `"$DemoKekFile`" /inheritance:r /grant:r `"$($env:USERNAME):(F)`"" | Out-Null
    Write-Host "[Security] Master KEK provisioned (32 bytes AES-256) into .demo_kek.secret with restricted permissions." -ForegroundColor Green
}

# 5. Persistent Offline Cache Directory
if (-not (Test-Path $DemoOfflineCache)) {
    New-Item -ItemType Directory -Path $DemoOfflineCache -Force | Out-Null
}
Write-Host "[Storage] Offline ciphertext cache directory: $DemoOfflineCache" -ForegroundColor Green

# 6. Inject Environment Variables into Process Context
$env:DATABASE_URL = "sqlite:///$DemoDb"
$env:MEDTRUST_MASTER_KEK = $kekHex
$env:MEDTRUST_OFFLINE_STORAGE_DIR = $DemoOfflineCache

# 6b. Ensure Docker Desktop CLI Directory is in PATH
$DockerBin = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin"
if (Test-Path "$DockerBin\docker.exe") {
    if ($env:PATH -notlike "*$DockerBin*") {
        $env:PATH = "$DockerBin;$env:PATH"
        Write-Host "[Environment] Docker Desktop CLI prepended to PATH: $DockerBin" -ForegroundColor Green
    }
}

if ($RealFabric) {
    $env:FABRIC_USE_REAL_GATEWAY = "True"
    Write-Host "[Fabric Gateway] FABRIC_USE_REAL_GATEWAY=True (isolated demo process)" -ForegroundColor Green
} else {
    $env:FABRIC_USE_REAL_GATEWAY = "False"
    Write-Host "[Fabric Gateway] FABRIC_USE_REAL_GATEWAY=False (standby mode)" -ForegroundColor Yellow
}

# Double check DATABASE_URL
if ($env:DATABASE_URL -match "medtrust\.db$" -and $env:DATABASE_URL -notmatch "demo_medtrust\.db$") {
    Write-Error "CRITICAL SAFETY ABORT: DATABASE_URL points to production medtrust.db!"
    exit 1
}

Write-Host "[Database] Isolated demo database URL: $env:DATABASE_URL" -ForegroundColor Green

# 7. Launch Uvicorn Server
if ($Foreground) {
    Write-Host "Starting Uvicorn in foreground on http://localhost:8001..." -ForegroundColor Cyan
    Set-Location $BackendDir
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
} else {
    Write-Host "Spawning background Uvicorn process on http://localhost:8001..." -ForegroundColor Cyan
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "python"
    $pinfo.Arguments = "-m uvicorn app.main:app --host 0.0.0.0 --port 8001"
    $pinfo.WorkingDirectory = $BackendDir
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    $pinfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $process = [System.Diagnostics.Process]::Start($pinfo)
    $process.Id | Out-File -FilePath $PidFile -Encoding ascii -Force
    Write-Host "Demo Backend process started (PID: $($process.Id))." -ForegroundColor Green

    # Wait for health endpoint
    Write-Host "Verifying backend health on http://127.0.0.1:8001/api/v1/health..." -NoNewline
    $healthy = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 800
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/v1/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
            if ($resp.status -eq "ok" -or $resp.status -eq "healthy" -or $resp.online -eq $true) {
                $healthy = $true
                break
            }
        } catch {
            Write-Host "." -NoNewline
        }
    }

    if ($healthy) {
        Write-Host " OK!" -ForegroundColor Green
        Write-Host "Backend API is ready at http://127.0.0.1:8001" -ForegroundColor Green
        Write-Host "Swagger Docs: http://127.0.0.1:8001/docs"
    } else {
        Write-Warning " Backend started but did not respond on /health within 12s. Check PID $($process.Id)."
    }
}
