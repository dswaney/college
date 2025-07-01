# ─────────────────────────────────────────────────────────────────────────────
# Ensure script runs as Administrator
# ─────────────────────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    exit
}

$ErrorActionPreference = "Stop"
trap { Write-Error "Unhandled Error: $_"; exit 1 }

# ─────────────────────────────────────────────────────────────────────────────
# Enable UAC
# ─────────────────────────────────────────────────────────────────────────────
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

# ─────────────────────────────────────────────────────────────────────────────
# Verify or create MISAdmin account
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Verifying MISAdmin Account"
function Ensure-MISAdminAccount {
    $accountName = "MISAdmin"

    try {
        $misAdmin = Get-LocalUser -Name $accountName -ErrorAction Stop
        Write-Host "'$accountName' account already exists." -ForegroundColor Green
        if (-not $misAdmin.PasswordNeverExpires) {
            Write-Warning "'$accountName' account does NOT have 'Password Never Expires' enabled. Updating..."
            Set-LocalUser -Name $accountName -PasswordNeverExpires $true
            Write-Host "'Password Never Expires' enabled for '$accountName'." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "'$accountName' account does not exist. Creating account..."
        do {
            $password = Read-Host "Enter password for '$accountName'" -AsSecureString
            $confirmPassword = Read-Host "Confirm password for '$accountName'" -AsSecureString

            $pwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
            $pwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))

            if ($pwd1 -ne $pwd2) {
                Write-Warning "Passwords do not match. Please try again."
            }
        } while ($pwd1 -ne $pwd2)

        try {
            New-LocalUser -Name $accountName -Password $password -FullName "MIS Admin" -Description "Local MIS Administrator Account" -PasswordNeverExpires -AccountNeverExpires
            Add-LocalGroupMember -Group "Administrators" -Member $accountName
            Write-Host "'$accountName' account created successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create the '$accountName' account. Error: $_"
            exit 1
        }
    }
}
Ensure-MISAdminAccount

$ErrorActionPreference = 'SilentlyContinue'

# Disable IPv6
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# Enable WinRM and firewall rules
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
Enable-PSRemoting -SkipNetworkProfileCheck -Force

if (Get-NetFirewallRule -DisplayGroup 'Windows Remote Management') {
    Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'
}

# Enable local admin impersonation over WinRM
$lafpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if (-not (Test-Path "$lafpKey\\LocalAccountTokenFilterPolicy")) {
    New-ItemProperty -Path $lafpKey -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Value 1 -Force
} else {
    Set-ItemProperty -Path $lafpKey -Name 'LocalAccountTokenFilterPolicy' -Value 1
}

# Configure PowerShell remoting permissions
$cs     = Get-CimInstance Win32_ComputerSystem
$sdSddl = 'D:(A;;GA;;;BA)'
if ($cs.PartOfDomain) {
    $sdSddl += '(A;;GA;;;DA)'
    Write-Host "Domain‑joined; including Domain Admins in SDDL." -ForegroundColor Cyan
} else {
    Write-Host "Workgroup machine; only Local Admins will be granted access." -ForegroundColor Cyan
}

Get-PSSessionConfiguration | ForEach-Object {
    $endpoint = $_.Name
    Write-Host "Securing endpoint '$endpoint' with SDDL: $sdSddl" -ForegroundColor Cyan
    try {
        Set-PSSessionConfiguration -Name $endpoint -SecurityDescriptorSddl $sdSddl -Force -ErrorAction Stop
        Write-Host "✔ '$endpoint' secured." -ForegroundColor Green
    } catch {
        Write-Warning "⚠ Failed to secure '$endpoint': $_"
    }
}

Restart-Service -Name WinRM
Write-Host "✅ WinRM is enabled and locked down." -ForegroundColor Green

# Trust PSGallery and install NuGet
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Install Windows Update module
if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false -Scope CurrentUser
}
Import-Module PSWindowsUpdate -ErrorAction Stop

# Enable Microsoft Update
function Enable-MicrosoftUpdate {
    Add-WUServiceManager -ServiceID '7971f918-a847-4430-9279-4a52d1efe18d' -Confirm:$false
    Set-WUSettings -NotificationLevel 'Notify before download' -Confirm:$false
    Write-Host "✔ Microsoft Update enabled." -ForegroundColor Green
}
Enable-MicrosoftUpdate

# Install HP Driver Module
if (-not (Get-Module HPDrivers -ListAvailable)) {
    Install-Module -Name HPDrivers -Force -Confirm:$false -Scope CurrentUser
}

# Configure NTP
$ntpServers = "ntp1.sp.se ntp2.sp.se"
Write-Host "Configuring NTP peers: $ntpServers"
w32tm /config /manualpeerlist:$ntpServers /syncfromflags:MANUAL /reliable:yes /update
Restart-Service w32time -Force
w32tm /resync
Write-Host "Initial sync complete." -ForegroundColor Green

# Schedule recurring sync
$taskName = 'Sync Time'
try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
} catch {
    $task = $null
}
if (-not $task) {
    $action = New-ScheduledTaskAction -Execute 'w32tm.exe' -Argument '/resync'
    $triggerMidnight = New-ScheduledTaskTrigger -Daily -At '00:00'
    $triggerNoon = New-ScheduledTaskTrigger -Daily -At '12:00'
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($triggerMidnight, $triggerNoon) `
        -Description 'Resync system time at midnight and noon every day' -User 'SYSTEM' -RunLevel Highest
    Write-Host "✔ Scheduled task '$taskName' created with midnight and noon triggers." -ForegroundColor Green
} else {
    if (-not (Get-ScheduledTaskInfo -TaskName $taskName).Enabled) {
        Enable-ScheduledTask -TaskName $taskName
        Write-Host "✔ Scheduled task '$taskName' enabled." -ForegroundColor Green
    } else {
        Write-Host "✔ Scheduled task '$taskName' already exists and is enabled." -ForegroundColor Green
    }
}

# Reset Group Policy
$gpPath = Join-Path $env:Windir 'System32\\GroupPolicy'
if (Test-Path -Path $gpPath -PathType Container) {
    Write-Host "Found GroupPolicy folder at `$gpPath`. Removing…" -ForegroundColor Cyan
    try {
        Remove-Item -Path $gpPath -Recurse -Force -ErrorAction Stop
        Write-Host "✔ Successfully removed GroupPolicy folder." -ForegroundColor Green
    } catch {
        Write-Warning "⚠ Failed to remove GroupPolicy folder: $_"
    }
} else {
    Write-Host "ℹ GroupPolicy folder not found. Skipping removal." -ForegroundColor Yellow
}
gpupdate /force | Out-Null
Write-Host "✔ gpupdate completed." -ForegroundColor Green

# Perform Updates
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
