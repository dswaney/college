# ─────────────────────────────────────────────────────────────────────────────
# Ensure script runs as Administrator
# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile = Join-Path $scriptDir "ScriptLog.txt"
Start-Transcript -Path $logFile -Append

<# # Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    Stop-Transcript
    exit 1 
}
#>

# ─────────────────────────────────────────────────────────────────────────────
# Set Execution Policy AFTER verifying admin rights
# ─────────────────────────────────────────────────────────────────────────────
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

$ErrorActionPreference = "Stop"
trap { Write-Error "Unhandled Error: $_"; exit 1 }

# ─────────────────────────────────────────────────────────────────────────────
# Enable UAC
# ─────────────────────────────────────────────────────────────────────────────
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

# ─────────────────────────────────────────────────────────────────────────────
# Prep: TLS + connection limits
# ─────────────────────────────────────────────────────────────────────────────
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13
[Net.ServicePointManager]::DefaultConnectionLimit = 64

# ─────────────────────────────────────────────────────────────────────────────
# Winget source configuration
# ─────────────────────────────────────────────────────────────────────────────
$sourceList = winget source list
if ($sourceList -notmatch "msstore") {
    winget source add --name msstore --arg https://storeedgefd.dsx.mp.microsoft.com/v9.0 --accept-source-agreements
}
winget source update

# ─────────────────────────────────────────────────────────────────────────────
# Perform Winget Upgrades
# ─────────────────────────────────────────────────────────────────────────────
winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --verbose-logs --include-unknown --include-pinned --force --scope machine
winget upgrade --all --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --verbose-logs --include-unknown --include-pinned --force --scope user

# ─────────────────────────────────────────────────────────────────────────────
# Update Office if Installed
# ─────────────────────────────────────────────────────────────────────────────
$officePath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
if (Test-Path $officePath) {
    Start-Process $officePath -ArgumentList "/update USER", "displaylevel=True"
}
Stop-Transcript
