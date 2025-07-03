# Define a reusable function
function Register-WeeklyTask {
    param (
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Time
    )

    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $Time
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "MISAdmin" -LogonType Password -RunLevel Highest

    # Create a secure password
    $securePassword = ConvertTo-SecureString " " -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("MISAdmin", $securePassword)

    Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Principal $principal -Description "Weekly task to run $ScriptPath" -User "MISAdmin" -Password "" -Force

    Write-Host "✅ Scheduled task '$TaskName' has been created for $Time." -ForegroundColor Green
}

# Define script paths and schedule
Register-WeeklyTask -TaskName "Remove User Profiles Weekly"         -ScriptPath "C:\Windows\Scripts\Remove-UserProfiles.ps1"        -Time "01:30AM"
Register-WeeklyTask -TaskName "Weekend Apps Updates"                -ScriptPath "C:\Windows\Scripts\Weekend_Apps_Updates.ps1"       -Time "02:00AM"
Register-WeeklyTask -TaskName "Weekend HP Drivers Update"           -ScriptPath "C:\Windows\Scripts\Weekend_HP_Drivers_Update.ps1"  -Time "02:45AM"
Register-WeeklyTask -TaskName "Weekend Windows Updates"             -ScriptPath "C:\Windows\Scripts\Weekend_Windows_Updates.ps1"    -Time "04:00AM"
Register-WeeklyTask -TaskName "System Repair"         			    -ScriptPath "C:\Windows\Scripts\SystemRepair.ps1" 			    -Time "08:00AM"
