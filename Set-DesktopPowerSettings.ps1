# Ensure script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Error "❌ This script must be run as Administrator."
    exit 1
}

# Set High Performance power plan
powercfg.exe -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Write-Host "✅ Set power plan to High Performance."

# Set monitor timeout (AC and DC) to 60 minutes
powercfg.exe -X -monitor-timeout-ac 60
Write-Host "✅ Set monitor timeout on AC power to 60 minutes."

powercfg.exe -X -monitor-timeout-dc 60
Write-Host "✅ Set monitor timeout on battery to 60 minutes."

# Disable hibernation
powercfg.exe /hibernate off
Write-Host "✅ Hibernation disabled."
