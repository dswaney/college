# ─────────────────────────────────────────────────────────────────────────────
# Ensure script runs as Administrator
# ─────────────────────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator."
    exit
}

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
# Verify MISAdmin or if not there to create it
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
    } catch {
        Write-Warning "'$accountName' account does not exist. Creating account..."

        # ─────────────────────────────────────────────────────────────────────────────
		# Prompt for Password and Confirm
		# ─────────────────────────────────────────────────────────────────────────────
        do {
            $password = Read-Host "Enter password for '$accountName'" -AsSecureString
            $confirmPassword = Read-Host "Confirm password for '$accountName'" -AsSecureString

            $pwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
            )
            $pwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
            )

            if ($pwd1 -ne $pwd2) {
                Write-Warning "Passwords do not match. Please try again."
            }
        } while ($pwd1 -ne $pwd2)

        # ─────────────────────────────────────────────────────────────────────────────
		# Create the Account
		# ─────────────────────────────────────────────────────────────────────────────
        try {
            New-LocalUser -Name $accountName -Password $password -FullName "MIS Admin" -Description "Local MIS Administrator Account" -PasswordNeverExpires -AccountNeverExpires
            Add-LocalGroupMember -Group "Administrators" -Member $accountName
            Write-Host "'$accountName' account created successfully with admin rights and password set to never expire." -ForegroundColor Green
        } catch {
            Write-Error "Failed to create the '$accountName' account. Error: $_"
            exit 1
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Execute the function
# ─────────────────────────────────────────────────────────────────────────────
Ensure-MISAdminAccount

# ─────────────────────────────────────────────────────────────────────────────
# Restore your error preference
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'SilentlyContinue'

# ─────────────────────────────────────────────────────────────────────────────
# Disable IPv6 on all adapters
# ─────────────────────────────────────────────────────────────────────────────
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# ─────────────────────────────────────────────────────────────────────────────
# Enable & start the WinRM service
# ─────────────────────────────────────────────────────────────────────────────
Set-Service   -Name WinRM -StartupType Automatic -ErrorAction Stop
Start-Service -Name WinRM                     -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# Enable PS remoting (listener + firewall rules)
# ─────────────────────────────────────────────────────────────────────────────
Enable-PSRemoting -SkipNetworkProfileCheck -Force

# ─────────────────────────────────────────────────────────────────────────────
# Ensure the WinRM firewall rules are enabled
# ─────────────────────────────────────────────────────────────────────────────
if (Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue) {
    Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'
}

# ─────────────────────────────────────────────────────────────────────────────
# Allow local administrators to use remote UAC elevation
# This lets local Admins fully impersonate over WinRM
# ─────────────────────────────────────────────────────────────────────────────
$lafpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if (-not (Test-Path "$lafpKey\LocalAccountTokenFilterPolicy")) {
    New-ItemProperty -Path $lafpKey `
                     -Name 'LocalAccountTokenFilterPolicy' `
                     -PropertyType DWord `
                     -Value 1 `
                     -Force | Out-Null
} else {
    Set-ItemProperty -Path $lafpKey `
                     -Name 'LocalAccountTokenFilterPolicy' `
                     -Value 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Build an SDDL granting GenericAll to:
#   BA = Built‑in Administrators
#   DA = Domain Administrators (only if domain‑joined)
# ─────────────────────────────────────────────────────────────────────────────
$cs        = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$sdSddl    = 'D:(A;;GA;;;BA)'                           # always local Admins
if ($cs.PartOfDomain) {
    $sdSddl += '(A;;GA;;;DA)'                           # add Domain Admins if joined
    Write-Host "Domain‑joined; including Domain Admins in SDDL." -ForegroundColor Cyan
} else {
    Write-Host "Workgroup machine; only Local Admins will be granted access." -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
# Apply the SDDL to every PowerShell endpoint
# ─────────────────────────────────────────────────────────────────────────────
Get-PSSessionConfiguration | ForEach-Object {
    $endpoint = $_.Name
    Write-Host "Securing endpoint '$endpoint' with SDDL: $sdSddl" -ForegroundColor Cyan

    try {
        Set-PSSessionConfiguration `
            -Name                  $endpoint `
            -SecurityDescriptorSddl $sdSddl `
            -Force `
            -ErrorAction Stop

        Write-Host "✔ '$endpoint' secured." -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠ Failed to secure '$endpoint': $_"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Restart WinRM so new ACLs take effect
# ─────────────────────────────────────────────────────────────────────────────
Restart-Service -Name WinRM -ErrorAction Stop

Write-Host "✅ WinRM is enabled and locked down to Local Admins" `
           "and Domain Admins (if domain‑joined)." -ForegroundColor Green


# ─────────────────────────────────────────────────────────────────────────────
# Prep: TLS + connection limits
# ─────────────────────────────────────────────────────────────────────────────
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13
[Net.ServicePointManager]::DefaultConnectionLimit = 64

# ─────────────────────────────────────────────────────────────────────────────
# Helper: synchronous download
# ─────────────────────────────────────────────────────────────────────────────
if (Get-Module -ListAvailable -Name BitsTransfer) {
    Import-Module BitsTransfer -ErrorAction Stop

    function Download-File {
        param(
            [Parameter(Mandatory)][string] $Url,
            [Parameter(Mandatory)][string] $Destination
        )
        if (Test-Path $Destination) { Remove-Item $Destination -Force }
        Write-Host "⏬ Downloading (BITS) $Url → $Destination" -ForegroundColor Cyan
        try {
            Start-BitsTransfer -Source $Url -Destination $Destination -Priority High -ErrorAction Stop
            Write-Host "✔ Download successful: $Destination" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "⚠ Download failed (BITS): $Url – $_"
            return $false
        }
    }
}
else {
    Write-Warning "BITS module not found; using Invoke-WebRequest fallback"
    function Download-File {
        param(
            [Parameter(Mandatory)][string] $Url,
            [Parameter(Mandatory)][string] $Destination
        )
        if (Test-Path $Destination) { Remove-Item $Destination -Force }
        Write-Host "⏬ Downloading (HTTP) $Url → $Destination" -ForegroundColor Cyan
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
            Write-Host "✔ Download successful: $Destination" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "⚠ Download failed (HTTP): $Url – $_"
            return $false
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Files to fetch and install
# ─────────────────────────────────────────────────────────────────────────────
$downloads = @(
    [pscustomobject]@{
        Url  = 'https://raw.githubusercontent.com/QuangVNMC/LTSC-Add-Microsoft-Store/master/Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64__8wekyb3d8bbwe.Appx'
        Path = "$env:TEMP\Microsoft.VCLibs.appx"
        Install = { Add-AppxPackage -Path $($this.Path) -ErrorAction Stop }
    },
    [pscustomobject]@{
        Url  = 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx'
        Path = "$env:TEMP\Microsoft.UI.Xaml.appx"
        Install = { Add-AppxPackage -Path $($this.Path) -ErrorAction Stop }
    },
    [pscustomobject]@{
        Url  = 'https://aka.ms/getwinget'
        Path = "$env:TEMP\AppInstaller.msixbundle"
        Install = {
            Add-AppxPackage -Path $($this.Path) -ForceApplicationShutdown -ErrorAction Stop
            Start-Sleep -Seconds 5
        }
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# 1) Download + report
# ─────────────────────────────────────────────────────────────────────────────
foreach ($dl in $downloads) {
    if (-not (Download-File -Url $dl.Url -Destination $dl.Path)) {
        Write-Warning "Skipping install of $($dl.Path) because the download failed."
        continue
    }
}
# ─────────────────────────────────────────────────────────────────────────────
# 📦 Install & clean up
# ─────────────────────────────────────────────────────────────────────────────
foreach ($dl in $downloads) {
    if (-not (Test-Path $dl.Path)) {
        Write-Warning "❗ File missing, skipping install: $($dl.Path)"
        continue
    }

    try {
        if ($dl.Path -like '*.msixbundle') {
            Write-Host "⚙ Installing MSIX bundle: $($dl.Path)" -ForegroundColor Cyan
            Add-AppxPackage -Path $dl.Path -ForceApplicationShutdown -ErrorAction Stop
        }
        else {
            Write-Host "⚙ Installing APPX package: $($dl.Path)" -ForegroundColor Cyan
            Add-AppxPackage -Path $dl.Path -ErrorAction Stop
        }
        Write-Host "✔ Successfully installed: $($dl.Path)" -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠ Failed to install from $($dl.Path): $_"
    }
    finally {
        # ─────────────────────────────────────────────────────────────────────────────
		# remove temp file
		# ─────────────────────────────────────────────────────────────────────────────
        Remove-Item $dl.Path -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "🎉 All done—packages installed and temporary files cleaned up." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# Winget source configuration
# ─────────────────────────────────────────────────────────────────────────────
$sourceList = winget source list
if ($sourceList -notmatch "msstore") {
    winget source add --name msstore --arg https://storeedgefd.dsx.mp.microsoft.com/v9.0 --accept-source-agreements
}
winget source update

# ─────────────────────────────────────────────────────────────────────────────
# Trust the PSGallery feed so Install-PackageProvider won’t prompt
# ─────────────────────────────────────────────────────────────────────────────
if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
    Write-Output "Trusting the PSGallery repository..."
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
}

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# ─────────────────────────────────────────────────────────────────────────────
# Install Update Modules and Tools silently
# ─────────────────────────────────────────────────────────────────────────────
Write-Output "Installing PSWindowsUpdate module..."
if (-not (Get-Module PSWindowsUpdate -ListAvailable)) {
    Install-Module PSWindowsUpdate -Force -Confirm:$false -Scope CurrentUser
}
Import-Module PSWindowsUpdate -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# Configure Windows Update settings:
# 1) Receive updates for other Microsoft products via Microsoft Update
# 2) Get the latest updates as soon as they're available (automatic download)
# ─────────────────────────────────────────────────────────────────────────────
function Enable-MicrosoftUpdate {
    [CmdletBinding()]
    param()

    Write-Output "Enabling Microsoft Update and configuring update behavior…"

    # ─────────────────────────────────────────────────────────────────────────────
	# 1) Add the Microsoft Update service without prompting
	# ─────────────────────────────────────────────────────────────────────────────
    Add-WUServiceManager `
        -ServiceID   '7971f918-a847-4430-9279-4a52d1efe18d' `
        -Confirm:$false `
        -ErrorAction Stop

    # ─────────────────────────────────────────────────────────────────────────────
	# 2) Configure how updates behave (will notify before download)
	# ─────────────────────────────────────────────────────────────────────────────
    Set-WUSettings `
        -NotificationLevel 'Notify before download' `
        -Confirm:$false `
        -ErrorAction Stop

    Write-Host "✔ Microsoft Update enabled; will notify before download." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Run it
# ─────────────────────────────────────────────────────────────────────────────
Enable-MicrosoftUpdate

# ─────────────────────────────────────────────────────────────────────────────
# Install HP Driver Management Module silently
# ─────────────────────────────────────────────────────────────────────────────
Write-Output "Installing HPDrivers module..."
if (-not (Get-Module HPDrivers -ListAvailable)) {
    Install-Module -Name HPDrivers -Force -Confirm:$false -Scope CurrentUser
}

# ─────────────────────────────────────────────────────────────────────────────
# Configure NTP peers, force sync, and schedule a recurring sync every 12 hours
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# 1) Configure Windows Time to use your NTP servers
# ─────────────────────────────────────────────────────────────────────────────
$ntpServers = "ntp1.sp.se ntp2.sp.se"
Write-Host "Configuring NTP peers: $ntpServers" -ForegroundColor Cyan
w32tm /config `
    /manualpeerlist:$ntpServers `
    /syncfromflags:MANUAL `
    /reliable:yes `
    /update

# ─────────────────────────────────────────────────────────────────────────────
# 2) Restart the Windows Time service so settings take effect
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Restarting w32time service..." -ForegroundColor Cyan
Restart-Service w32time -Force

# ─────────────────────────────────────────────────────────────────────────────
# 3) Perform an immediate time sync
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Performing initial time resynchronization..." -ForegroundColor Cyan
w32tm /resync
Write-Host "Initial sync complete." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# 4) Create or verify a Scheduled Task named "Sync Time"
#    that runs w32tm /resync at 00:00 and 12:00 every day
# ─────────────────────────────────────────────────────────────────────────────

$taskName = 'Sync Time'
try {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
} catch {
    $task = $null
}

if (-not $task) {
    Write-Host "Creating scheduled task '$taskName'…" -ForegroundColor Cyan

    # ─────────────────────────────────────────────────────────────────────────────
	# Action: call w32tm.exe /resync
	# ─────────────────────────────────────────────────────────────────────────────
    $action = New-ScheduledTaskAction -Execute 'w32tm.exe' -Argument '/resync'

    # ─────────────────────────────────────────────────────────────────────────────
	# Two daily triggers: midnight and noon
	# ─────────────────────────────────────────────────────────────────────────────
    $triggerMidnight = New-ScheduledTaskTrigger -Daily -At '00:00'
    $triggerNoon     = New-ScheduledTaskTrigger -Daily -At '12:00'

    Register-ScheduledTask `
        -TaskName    $taskName `
        -Action      $action `
        -Trigger     @($triggerMidnight, $triggerNoon) `
        -Description 'Resync system time at midnight and noon every day' `
        -User        'SYSTEM' `
        -RunLevel    Highest

    Write-Host "✔ Scheduled task '$taskName' created with midnight & noon triggers." -ForegroundColor Green
}
else {
    # ─────────────────────────────────────────────────────────────────────────────
	# Ensure it’s enabled
	# ─────────────────────────────────────────────────────────────────────────────
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if (-not $info.Enabled) {
        Write-Host "Enabling scheduled task '$taskName'…" -ForegroundColor Yellow
        Enable-ScheduledTask -TaskName $taskName
        Write-Host "✔ Scheduled task '$taskName' enabled." -ForegroundColor Green
    }
    else {
        Write-Host "✔ Scheduled task '$taskName' already exists and is enabled." -ForegroundColor Green
    }
}

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

# ─────────────────────────────────────────────────────────────────────────────
# Reset Local Group Policy Settings silently
# ─────────────────────────────────────────────────────────────────────────────
$gpPath = Join-Path $env:Windir 'System32\GroupPolicy'

if ( Test-Path -Path $gpPath -PathType Container ) {
    Write-Host "Found GroupPolicy folder at `$gpPath`. Removing…" -ForegroundColor Cyan
    try {
        Remove-Item -Path $gpPath -Recurse -Force -ErrorAction Stop
        Write-Host "✔ Successfully removed GroupPolicy folder." -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠ Failed to remove GroupPolicy folder: $_"
    }
}
else {
    Write-Host "ℹ GroupPolicy folder not found at `$gpPath`. Skipping removal." -ForegroundColor Yellow
}

Write-Host "Updating Group Policy (gpupdate /force)…" -ForegroundColor Cyan
gpupdate /force | Out-Null
Write-Host "✔ gpupdate completed." -ForegroundColor Green

<# # Detect whether we’re on a 64‑bit Dell system
$cs     = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$isDell = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -and $cs.Manufacturer -like '*Dell*')

if (-not $isDell) {
    Write-Warning "Non‑Dell hardware detected ($($cs.Manufacturer)); skipping Dell management steps."
}
else {
    Write-Host "Dell hardware detected; running Dell management steps…" -ForegroundColor Cyan

    # ——————————————————————————————————————————————
    # 1) Install & import the DellBIOSProvider module
    # ——————————————————————————————————————————————
    if (-not (Get-Module -ListAvailable -Name DellBIOSProvider)) {
        Write-Host "Installing DellBIOSProvider module…" -ForegroundColor Cyan
        Install-Module -Name DellBIOSProvider -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop
    }

    try {
        Import-Module DellBIOSProvider -ErrorAction Stop
        Write-Host "✔ DellBIOSProvider module loaded." -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠ Failed to import DellBIOSProvider: $_"
        Write-Warning "    Skipping DellBIOSProvider functionality."
        # You could return or set a flag here if you want to skip DCU as well
    }

    # ——————————————————————————————————————————————
    # 2) Download & install Dell Command | Update (DCU)
    # ——————————————————————————————————————————————
	function Install-DellManagementStack {
		Write-Host "Downloading and installing Dell Command | Update…" -ForegroundColor Cyan

		$url = 'https://downloads.dell.com/serviceable/FOLDER/DCU_Setup_3_0_0.exe'
		$tmp = Join-Path $env:TEMP 'DCU_Setup.exe'

		Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -ErrorAction Stop

		# ─────────────────────────────────────────────────────────────────────────────
		# silently install the MSI with NORESTART
		# ─────────────────────────────────────────────────────────────────────────────
		Start-Process -FilePath 'msiexec.exe' `
			-ArgumentList @(
				'/i', "`"$tmp`"",
				'/qn',
				'/norestart'
			) `
			-Wait

    Write-Host "✔ Dell Command | Update installed (no auto‑reboot)." -ForegroundColor Green
}

    function Update-DellDrivers {
        Write-Host "Running Dell Command | Update to scan and apply updates…" -ForegroundColor Cyan

        $cli = 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe'
        & $cli /scan         -silent -outputLog
        & $cli /applyUpdates -silent -reboot=disable -forceUpdate=enable

        Write-Host "✔ Dell drivers updated." -ForegroundColor Green
    }

    # ─────────────────────────────────────────────────────────────────────────────
	# Execute the Dell routines
	# ─────────────────────────────────────────────────────────────────────────────
    Install-DellManagementStack
    Update-DellDrivers
}
 #>
# ——————————————————————————————————————————————
# Install HP Drivers and clean up install files (runs on all hardware)
# ——————————————————————————————————————————————
Write-Host "Installing HP drivers and cleaning up…" -ForegroundColor Cyan
Get-HPDrivers -NoPrompt -BIOS -DeleteInstallationFiles

# ─────────────────────────────────────────────────────────────────────────────
# Reset Windows Update Components with timeout and retry
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-WithTimeoutAndRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 300,
        [int]$MaxRetries = 2
    )
    for ($i = 1; $i -le $MaxRetries; $i++) {
        Write-Output "Starting attempt $i of $MaxRetries..."
        $job = Start-Job -ScriptBlock $ScriptBlock
        if (Wait-Job $job -Timeout $TimeoutSeconds) {
            Receive-Job $job | Write-Output
            Remove-Job $job | Out-Null
            return
        } else {
            Write-Warning "Attempt $i timed out after $TimeoutSeconds seconds."
            Stop-Job $job | Out-Null; Remove-Job $job | Out-Null
        }
        catch { Write-Warning "Unexpected error: $_" }
    }
    Write-Error "Operation exceeded $MaxRetries retries and timed out."
    catch { Write-Warning "Unexpected error: $_" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Execute Reset-WUComponents with automated timeout and retry
# ─────────────────────────────────────────────────────────────────────────────
Invoke-WithTimeoutAndRetry -ScriptBlock { Reset-WUComponents -Verbose } -TimeoutSeconds 300 -MaxRetries 2

# ─────────────────────────────────────────────────────────────────────────────
# Install Windows Updates
# ─────────────────────────────────────────────────────────────────────────────
Get-WindowsUpdate -AcceptAll -Install -AutoReboot


