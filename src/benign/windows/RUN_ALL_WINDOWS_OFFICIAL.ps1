[CmdletBinding()]
param(
    [string]$CampaignRoot='C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs',
    [ValidateRange(0,30)][int]$MaxRuns=0
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
function A([bool]$C,[string]$M){if(-not$C){throw ('WINDOWS_ORCHESTRATOR_FAILURE:'+$M)}}
$P=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());A ($P.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
$Manifest=Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv';$Launcher=Join-Path $PSScriptRoot 'RUN_NEXT_WINDOWS_OFFICIAL.ps1';A (Test-Path $Launcher -PathType Leaf) 'NEXT_RUN_LAUNCHER_MISSING'
$Completed=0
while($true){
    $Rows=@(Import-Csv $Manifest);$Platform=@($Rows|Where-Object platform -ceq 'Windows')
    A (@($Platform|Where-Object status -ceq 'RUNNING').Count -eq 0) 'AMBIGUOUS_RUNNING_ROW'
    A (@($Platform|Where-Object status -ceq 'FAIL').Count -eq 0) 'FAILED_ROW_REQUIRES_REPAIR'
    $Pending=@($Platform|Where-Object status -ceq 'PENDING')
    if($Pending.Count -eq 0){break}
    if($MaxRuns -gt 0 -and $Completed -ge $MaxRuns){break}
    Write-Host ('WINDOWS ORCHESTRATOR: launching '+$Pending[0].run_id+'; pending='+$Pending.Count) -ForegroundColor Cyan
    & $Launcher -CampaignRoot $CampaignRoot
    $Completed++
}
$Final=@(Import-Csv $Manifest|Where-Object platform -ceq 'Windows');$Pass=@($Final|Where-Object status -ceq 'PASS').Count;$Pending=@($Final|Where-Object status -ceq 'PENDING').Count
Write-Host ('WINDOWS ONE-CLICK ORCHESTRATOR COMPLETE: newly_completed='+$Completed+' total_pass='+$Pass+'/30 pending='+$Pending) -ForegroundColor Green
