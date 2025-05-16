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
# Bloatware removal
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Removing known bloatware applications"
function Remove-AppxPackageSafe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $packages = Get-AppxPackage -AllUsers -Name $AppName

    if (-not $packages) {
        Write-Host "No packages found for '$AppName'." -ForegroundColor Yellow
        return
    }

    foreach ($package in $packages) {
        try {
            Remove-AppxPackage -Package $package.PackageFullName
            Write-Host "✅ Successfully removed '$AppName' for User SID: $($package.UserSID)" -ForegroundColor Green
        } catch {
            Write-Warning "⚠️ Failed to remove '$AppName' for User SID: $($package.UserSID). Error: $_"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Predefined Bloatware List
# ─────────────────────────────────────────────────────────────────────────────
$appList = @(
    "Microsoft.ZuneMusic",
    "Microsoft.Music.Preview",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxGameOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.BingTravel",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.People",
    "Microsoft.BingFinance",
    "Microsoft.3DBuilder",
    "Microsoft.BingNews",
    "Microsoft.XboxApp",
    "Microsoft.BingSports",
    "Microsoft.Getstarted",
    "Microsoft.WindowsMaps",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.BingWeather",
    "Microsoft.WindowsPhone",
    "Microsoft.SkypeApp",
    "Microsoft.YourPhone"
)


# ─────────────────────────────────────────────────────────────────────────────
# Remove Each App in the List
# ─────────────────────────────────────────────────────────────────────────────
foreach ($app in $appList) {
    Remove-AppxPackageSafe -AppName $app
}

# ─────────────────────────────────────────────────────────────────────────────
# Function to Set Registry Value Safely
# ─────────────────────────────────────────────────────────────────────────────
function Set-RegistryValue {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [object] $Value,

        [ValidateSet('String','DWORD','QWORD','Binary','ExpandString')]
        [string] $Type = 'DWORD'
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty `
            -Path         $Path `
            -Name         $Name `
            -Value        $Value `
            -PropertyType $Type `
            -Force        | Out-Null

        Write-Host "✔️  Set $Path\$Name to $Value" -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠️  Failed to set $Path\$Name. Error: $_"
    }
}

# ————————————————————————
# 🔧 List of Registry Settings
# ————————————————————————
$registrySettings = @(
    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
       Name  = 'AllowTelemetry'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
       Name  = 'AllowTelemetry'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'ContentDeliveryAllowed'
       Value = 0
       Type  = 'DWORD' },
	   
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'OemPreInstalledAppsEnabled'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
	   Name  = 'PreInstalledAppsEnabled'
	   Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'PreInstalledAppsEverEnabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SilentInstalledAppsEnabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SubscribedContent-338387Enabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SubscribedContent-338388Enabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SubscribedContent-338389Enabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SubscribedContent-353698Enabled'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       Name  = 'SystemPaneSuggestionsEnabled'
       Value = 0
       Type  = 'DWORD' },
	   
    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'
       Name  = 'NumberOfSIUFInPeriod'
       Value = 0
       Type  = 'DWORD' },
	
    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
       Name  = 'DoNotShowFeedbackNotifications'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
       Name  = 'DisableTailoredExperiencesWithDiagnosticData'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
       Name  = 'DisabledByGroupPolicy'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
       Name  = 'Disabled'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
       Name  = 'DODownloadMode'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
       Name  = 'fAllowToGetHelp'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager'
       Name  = 'EnthusiastMode'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       Name  = 'ShowTaskViewButton'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
       Name  = 'PeopleBand'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       Name  = 'LaunchTo'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
       Name  = 'LongPathsEnabled'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
       Name  = 'SearchOrderConfig'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
       Name  = 'SystemResponsiveness'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
       Name  = 'NetworkThrottlingIndex'
       Value = 4294967295
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Control Panel\Desktop'
       Name  = 'MenuShowDelay'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Control Panel\Desktop'
       Name  = 'AutoEndTasks'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
       Name  = 'ClearPageFileAtShutdown'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\ControlSet001\Services\Ndu'
       Name  = 'Start'
       Value = 2
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Control Panel\Mouse'
       Name  = 'MouseHoverTime'
       Value = 400
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
       Name  = 'IRPStackSize'
       Value = 30
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'
       Name  = 'EnableFeeds'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds'
       Name  = 'ShellFeedsTaskbarViewMode'
       Value = 2
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
       Name  = 'HideSCAMeetNow'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
       Name  = 'ScoobeSystemSettingEnabled'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
       Name  = 'EnableActivityFeed'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
       Name  = 'PublishUserActivities'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
       Name  = 'UploadUserActivities'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
       Name  = 'Value'
       Value = 'Deny'
       Type  = 'STRING' },

    @{ Path  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
       Name  = 'SensorPermissionState'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
       Name  = 'Status'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\Maps'
       Name  = 'AutoUpdateEnabled'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
       Name  = 'SearchboxTaskbarMode'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       Name  = 'TaskbarAl'
       Value = 0
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
       Name  = 'DisplayParameters'
       Value = 1
       Type  = 'DWORD' },

    @{ Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
       Name  = 'DisableEmoticon'
       Value = 1
       Type  = 'DWORD' }
)

# ─────────────────────────────────────────────────────────────────────────────
# Apply All Registry Settings
# ─────────────────────────────────────────────────────────────────────────────
foreach ($entry in $registrySettings) {
    Set-RegistryValue `
        -Path  $entry.Path `
        -Name  $entry.Name `
        -Value $entry.Value `
        -Type  $entry.Type
}

Write-Host "All registry settings have been successfully applied!" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# Restore your error preference
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'SilentlyContinue'

# ─────────────────────────────────────────────────────────────────────────────
# Function to Safely Set Service Startup Type
# ─────────────────────────────────────────────────────────────────────────────
function Set-ServiceStartup {
    param (
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [ValidateSet("Automatic", "Manual", "Disabled", "AutomaticDelayedStart")]
        [string]$StartupType
    )

    try {
        # ─────────────────────────────────────────────────────────────────────────────
		# Try to set; if service doesn't exist or is already at that startup type,
        # Set-Service will either throw or do nothing.
		# ─────────────────────────────────────────────────────────────────────────────
        Set-Service -Name $ServiceName -StartupType $StartupType -ErrorAction Stop
        Write-Host "✔️ Set $ServiceName to $StartupType" -ForegroundColor Green
    } catch {
		# ─────────────────────────────────────────────────────────────────────────────
        # Only show a warning if it really failed (e.g. permission issue);
        # ignore “service not found” or “already configured” errors.
		# ─────────────────────────────────────────────────────────────────────────────
        if ($_.Exception.Message -notmatch 'Cannot find any service with service name') {
            Write-Warning "⚠️ Failed to set $ServiceName. Error: $_"
        }
    }
}

function Set-ServiceStartupStates {
    [CmdletBinding()]
    param ()

    # ─────────────────────────────────────────────────────────────────────────────
	# Define services and their desired startup types
	# ─────────────────────────────────────────────────────────────────────────────
    $serviceConfigs = @{
		"AJRouter"                      = "Disabled"
        "ALG"                           = "Manual"
        "AppIDSvc"                      = "Manual"
        "AppMgmt"                       = "Manual"
        "AppReadiness"                  = "Manual"
        "AppVClient"                    = "Disabled"
        "AppXSvc"                       = "Manual"
		"Appino"						= "Manual"
        "AssignedAccessManagerSvc"      = "Disabled"
        "AudioEndpointBuilder"          = "Automatic"
		"AudioSrv" 						= "Automatic"
		"AxInstSV" 						= "Manual"
		"BDESVC" 						= "Manual"
		"BFE" 							= "Automatic"
		"BITS" 							= "Automatic"
		"BTAGService" 					= "Manual"
		"BcastDVRUserService_*" 		= "Manual"
		"BluetoothUserService_*" 		= "Manual"
		"Browser" 						= "Manual"
		"BthAvctpSvc" 					= "Automatic"
		"BthHFSrv" 						= "Automatic"
		"CDPSvc" 						= "Manual"
		"CDPUserSvc_*" 					= "Automatic"
		"COMSysApp" 					= "Manual"
		"CaptureService_*" 				= "Manual"
		"CertPropSvc" 					= "Manual"
		"ClipSVC" 						= "Manual"
		"ConsentUxUserSvc_*" 			= "Manual"
		"CoreMessagingRegistrar" 		= "Automatic"
		"CredentialEnrollmentManagerUserSvc_*" = "Manual"
		"CryptSvc" 						= "Automatic"
		"CscService" 					= "Manual"
		"DPS" 							= "Automatic"
		"DcomLaunch" 					= "Automatic"
		"DcpSvc" 						= "Manual"
		"DevQueryBroker" 				= "Manual"
		"DeviceAssociationBrokerSvc_*" 	= "Manual"
		"DeviceAssociationService" 		= "Manual"
		"DeviceInstall" 				= "Manual"
		"DevicePickerUserSvc_*" 		= "Manual"
		"DevicesFlowUserSvc_*" 			= "Manual"
		"Dhcp" 							= "Automatic"
		"DiagTrack" 					= "Manual"
		"DialogBlockingService" 		= "Disabled"
		"DispBrokerDesktopSvc" 			= "Automatic"
		"DisplayEnhancementService" 	= "Manual"
		"DmEnrollmentSvc" 				= "Manual"
		"Dnscache" 						= "Automatic"
		"DoSvc" 						= "Automatic"
		"DsSvc" 						= "Manual"
		"DsmSvc" 						= "Manual"
		"DusmSvc" 						= "Automatic"
		"EFS" 							= "Manual"
		"EapHost" 						= "Manual"
		"EntAppSvc" 					= "Manual"
		"EventLog" 						= "Automatic"
		"FDResPub" 						= "Manual"
		"Fax" 							= "Manual"
		"FontCache" 					= "Automatic"
		"FrameServer" 					= "Manual"
		"FrameServerMonitor" 			= "Manual"
		"GraphicsPerfSvc"				= "Manual"
		"HomeGroupListener" 			= "Manual"
		"HomeGroupProvider" 			= "Manual"
		"HvHost" 						= "Manual"
		"IEEtwCollectorService" 		= "Manual"
		"IKEEXT" 						= "Manual"
		"InstallService" 				= "Manual"
		"InventorySvc" 					= "Manual"
		"IpxlatCfgSvc" 					= "Manual"
		"Keylso" 						= "Automatic"
		"KtmRm"							= "Manual"
		"LSM" 							= "Automatic"
		"LanmanServer" 					= "Automatic"
		"LanmanWorkstation" 			= "Automatic"
		"LicenseManager" 				= "Manual"
		"LxpSvc" 						= "Manual"
		"MSDTC" 						= "Manual"
		"MSiSCSI" 						= "Manual"
		"MapsBroker" 					= "Automatic"
		"McpManagementService" 			= "Manual"
		"MessagingService_*" 			= "Manual"
		"MicrosoftEdgeElevationService" = "Manual"
		"MixedRealityOpenXRSvc" 		= "Manual"
		"MpsSvc" 						= "Automatic"
		"MsKeyboardFilter" 				= "Manual"
		"NPSMSvc_*" 					= "Manual"
		"NaturalAuthentication" 		= "Manual"
		"NcaSvc" 						= "Manual"
		"NcbService" 					= "Manual"
		"NcdAutoSetup" 					= "Manual"
		"NetSetupSvc" 					= "Manual"
		"NetTcpPortSharing" 			= "Disabled"
		"Netlogon" 						= "Automatic"
		"Netman" 						= "Manual"
		"NgcCtnrSvc" 					= "Manual"
		"NgcSvc" 						= "Manual"
		"NlaSvc" 						= "Manual"
		"OneSyncSrv_*" 					= "Automatic"
		"P9RdrService_*" 				= "Manual"
		"PNRPAutoReg" 					= "Manual"
		"PNRPsvc" 						= "Manual"
		"PcaSvc" 						= "Manual"
		"PeerDistSvc"					= "Manual"
		"PenService_*" 					= "Manual"
		"PerfHost"						= "Manual"
		"PhoneSvc" 						= "Manual"
		"PimIndexMaintenanceSvc_*" 		= "Manual"
		"PlugPlay" 						= "Manual"
		"PolicyAgent" 					= "Manual"
		"Power" 						= "Automatic"
		"PrintNotify" 					= "Manual"
		"PrintWorkflowUserSvc_*" 		= "Manual"
		"ProfSvc" 						= "Automatic"
		"PushToInstall" 				= "Manual"
		"QWAVE" 						= "Manual"
		"RasAuto" 						= "Manual"
		"RasMan" 						= "Manual"
		"RemoteAccess" 					= "Automatic"
		"RemoteRegistry" 				= "Disabled"
		"RetailDemo" 					= "Manual"
		"RmSvc" 						= "Manual"
		"RpcEptMapper" 					= "Automatic"
		"RpcLocator" 					= "Manual"
		"RpcSs" 						= "Automatic"
		"SCPolicySvc" 					= "Manual"
		"SCardSvr" 						= "Manual"
		"SDRSVC" 						= "Manual"
		"SEMgrSvc" 						= "Manual"
		"SENS" 							= "Automatic"
		"SNMPTrap"						= "Manual"
		"SSDPSRV" 						= "Manual"
		"SamSs" 						= "Automatic"
		"ScDeviceEnum" 					= "Manual"
		"Schedule" 						= "Automatic"
		"SecurityHealthService" 		= "Manual"
		"Sense"							= "Manual"
		"SensorDataService" 			= "Manual"
		"SensorService" 				= "Manual"
		"SensrSvc" 						= "Manual"
		"SessionEnv"					= "Manual"
		"SgrmBroker" 					= "Automatic"
		"SharedAccess" 					= "Manual"
		"SharedRealitySvc" 				= "Manual"
		"ShellHWDetection" 				= "Automatic"
		"SmsRouter" 					= "Manual"
		"Spooler" 						= "Automatic"
		"SstpSvc" 						= "Manual"
		"StateRepository" 				= "Manual"
		"StiSvc" 						= "Manual"
		"StorSvc" 						= "Manual"
		"SysMain" 						= "Automatic"
		"SystemEventsBroker" 			= "Automatic"
		"TabletInputService" 			= "Manual"
		"TapiSrv" 						= "Manual"
		"TermService" 					= "Automatic"
		"TextInputManagementService" 	= "Manual"
		"Themes" 						= "Automatic"
		"TieringEngineService" 			= "Manual"
		"TimeBroker" 					= "Manual"
		"TimeBrokerSvc" 				= "Manual"
		"TokenBroker" 					= "Manual"
		"TrkWks" 						= "Automatic"
		"TroubleshootingSvc" 			= "Manual"
		"TrustedInstaller" 				= "Manual"
		"UI0Detect"						= "Manual"
		"UdkUserSvc_*" 					= "Manual"
		"UevAgentService" 				= "Disabled"
		"UmRdpService"					= "Manual"
		"UnistoreSvc_*" 				= "Manual"
		"UserDataSvc_*" 				= "Manual"
		"UserManager" 					= "Automatic"
		"UsoSvc" 						= "Manual"
		"VGAuthService" 				= "Automatic"
		"VMTools" 						= "Automatic"
		"VSS" 							= "Manual"
		"VacSvc" 						= "Manual"
		"VaultSvc" 						= "Automatic"
		"W32Time" 						= "Manual"
		"WEPHOSTSVC" 					= "Manual"
		"WFDSConMgrSvc" 				= "Manual"
		"WMPNetworkSvc" 				= "Manual"
		"WManSvc" 						= "Manual"
		"WPDBusEnum" 					= "Manual"
		"WSService" 					= "Manual"
		"WSearch" 						= "Automatic"
		"WaaSMedicSvc" 					= "Manual"
		"WalletService" 				= "Manual"
		"WarpJITSvc" 					= "Manual"
		"WbioSrvc" 						= "Manual"
		"Wcmsvc" 						= "Automatic"
		"WcsPlugInService" 				= "Manual"
		"WdNisSvc" 						= "Manual"
		"WdiServiceHost" 				= "Manual"
		"WdiSystemHost" 				= "Manual"
		"WebClient" 					= "Manual"
		"Wecsvc" 						= "Manual"
		"WerSvc" 						= "Manual"
		"WiaRpc" 						= "Manual"
		"WinDefend" 					= "Automatic"
		"WinHttpAutoProxySvc" 			= "Manual"
		"WinRM" 						= "Manual"
		"Winmgmt" 						= "Automatic"
		"WlanSvc" 						= "Automatic"
		"WpcMonSvc" 					= "Manual"
		"WpnService" 					= "Manual"
		"WpnUserService_*" 				= "Automatic"
		"XblAuthManager" 				= "Manual"
		"XblGameSave" 					= "Manual"
		"XbocGipSvc" 					= "Manual"
		"XboxNetApiSvc"					= "Manual"
		"autotimesvc" 					= "Manual"
		"bthserv" 						= "Manual"
		"camsvc" 						= "Manual"
		"cbdhsvc_*" 					= "Manual"
		"cloudidsvc" 					= "Manual"
		"dcsvc" 						= "Manual"
		"defragsvc" 					= "Manual"
		"diagnostichub.standardcollector.service" 	= "Manual"
		"diagsvc" 						= "Manual"
		"dmwappushservice" 				= "Manual"
		"dot3svc" 						= "Manual"
		"edgeupdate" 					= "Manual"
		"edgeupatem" 					= "Manual"
		"embeddedmode" 					= "Manual"
		"fdPHost" 						= "Manual"
		"fhsvc" 						= "Manual"
		"gpsvc" 						= "Automatic"
		"hidserv" 						= "Manual"
		"icssvc" 						= "Manual"
		"iphlpsvc" 						= "Automatic"
		"ifsvc" 						= "Manual"
		"lltdsvc" 						= "Manual"
		"lmhosts" 						= "Manual"
		"msiserver" 					= "Manual"
		"netprofm" 						= "Manual"
		"nsi" 							= "Manual"
		"p2pimsvc" 						= "Manual"
		"p2psvc" 						= "Manual"
		"perceptionsimulation" 			= "Manual"
		"pla" 							= "Manual"
		"seclogon" 						= "Manual"
		"shpamsvc" 						= "Disabled"
		"smphost" 						= "Manual"
		"spectrum" 						= "Manual"
		"sppsvc" 						= "Automatic"
		"ssh-agent" 					= "Disabled"
		"svsvc" 						= "Manual"
		"swprv" 						= "Manual"
		"tiledatamodelsvc" 				= "Automatic" 
		"tzautoupdate" 					= "Disabled"
		"uhssvc" 						= "Disabled"
		"upnphost" 						= "Manual"
		"vds"							= "Manual"
		"vm3dservice" 					= "Manual"
		"vmicguestinterface" 			= "Manual"
		"vmicheartbeat" 				= "Manual"
		"vmickvpexchange" 				= "Manual"
		"vmicrdv" 						= "Manual"
		"vmicshutdown"					= "Manual"
		"vmictimesync" 					= "Manual"
		"vmicvmsession" 				= "Manual"
		"vmicvss" 						= "Manual"
		"vmvss" 						= "Manual"
		"wbengine"						= "Manual"
		"wcncsvc" 						= "Manual"
		"webthreatdefsvc" 				= "Manual"
		"webthreatdefusersvc_*"			= "Automatic"
		"wercplsupport" 				= "Manual"
		"wisvc" 						= "Manual"
		"wlidsvc" 						= "Manual"
		"wlpasvc" 						= "Manual"
		"wmiApSrv"						= "Manual"
		"workfolderssvc" 				= "Manual"
		"wscsvc" 						= "Automatic"
		"wuauserv" 						= "Manual"
		"wudfsvc" 						= "Manual"
        # ─────────────────────────────────────────────────────────────────────────────
		# Add more services as needed...
		# ─────────────────────────────────────────────────────────────────────────────
    }

    foreach ($svc in $serviceConfigs.GetEnumerator()) {
        try {
			# ─────────────────────────────────────────────────────────────────────────────
            # Grab the service object (or $null if not found)
			# ─────────────────────────────────────────────────────────────────────────────
            $svcObj = Get-Service -Name $svc.Key -ErrorAction SilentlyContinue
            if (-not $svcObj) {
				# ─────────────────────────────────────────────────────────────────────────────
                # service not installed — skip silently
				# ─────────────────────────────────────────────────────────────────────────────
                continue
            }

            # ─────────────────────────────────────────────────────────────────────────────
			# Only act if the StartType is different
			# ─────────────────────────────────────────────────────────────────────────────
            if ($svcObj.StartType -ne $svc.Value) {
                Set-Service -Name $svc.Key -StartupType $svc.Value -ErrorAction Stop
                Write-Host "✔️ Set '$($svc.Key)' to '$($svc.Value)'" -ForegroundColor Green
            }
			# ─────────────────────────────────────────────────────────────────────────────
            # else already correct — do nothing
			# ─────────────────────────────────────────────────────────────────────────────
        } catch {
            Write-Warning "⚠️ Failed to update service '$($svc.Key)'. Error: $_"
        }
    }
}
# ─────────────────────────────────────────────────────────────────────────────
# Run the function
# ─────────────────────────────────────────────────────────────────────────────
Set-ServiceStartupStates

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
#Install all updates except any in the "Feature Update" category (which includes 24H2)
# ─────────────────────────────────────────────────────────────────────────────
<# Get-WindowsUpdate `
  -NotTitle    'Feature update to Windows 11, version 24H2' `
  -AcceptAll `
  -Install `
  -AutoReboot #>

# ─────────────────────────────────────────────────────────────────────────────
# Install Windows Updates
# ─────────────────────────────────────────────────────────────────────────────
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
