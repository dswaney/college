# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Define domain user credentials
$userName = "CC-Student"
$password = "CC`tud3nt!"  # Note: escape the `$` for PowerShell
$displayPassword = "CC$tud3nt!" # For registry (no escape)

$domainName = "Compton.edu"
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Configure registry for domain autologin
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1" -Type String
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $userName -Type String
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $displayPassword -Type String
Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value $domainName -Type String

Write-Host "✅ Auto-login configured for domain user '$domainName\\$userName'." -ForegroundColor Green
