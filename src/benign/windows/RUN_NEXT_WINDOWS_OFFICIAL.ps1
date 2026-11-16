[CmdletBinding()]
param(
    [string]$CampaignRoot='C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw ('OFFICIAL_RUN_PRECHECK_FAILURE:'+$Message)}}
function Set-ManifestStatus([string]$Path,[string]$RunID,[string]$Expected,[string]$NewStatus){
    $Rows=@(Import-Csv -LiteralPath $Path)
    $Matches=@($Rows|Where-Object run_id -ceq $RunID)
    Assert-True ($Matches.Count -eq 1) ('RUN_ID_NOT_UNIQUE:'+$RunID)
    Assert-True ([string]$Matches[0].status -ceq $Expected) ('STATUS_RACE:'+ $RunID+':expected='+$Expected+':actual='+$Matches[0].status)
    foreach($Row in $Rows){if([string]$Row.run_id -ceq $RunID){$Row.status=$NewStatus}}
    $Temp=$Path+'.atomic.'+[guid]::NewGuid().ToString('N')
    $Rows|Export-Csv -LiteralPath $Temp -NoTypeInformation -Encoding UTF8
    Assert-True (@(Import-Csv -LiteralPath $Temp).Count -eq 60) 'ATOMIC_MANIFEST_ROW_COUNT_CHANGED'
    Move-Item -LiteralPath $Temp -Destination $Path -Force
}

$Principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
$PackageRoot=$PSScriptRoot
$Manifest=Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv'
$OfficialRoot=Join-Path $CampaignRoot '02_WINDOWS\BENIGN\official_runs'
$Readiness=Join-Path (Split-Path -Parent $PackageRoot) 'VERIFY_OFFICIAL_CAMPAIGN_READINESS.ps1'
foreach($Path in @($CampaignRoot,$Manifest,$OfficialRoot,$Readiness,(Join-Path $PackageRoot 'BENIGN_Official_Run_Controller.ps1'))){Assert-True (Test-Path -LiteralPath $Path) ('REQUIRED_PATH_MISSING:'+$Path)}
& $Readiness -CampaignRoot $CampaignRoot -AllowExistingOfficialRuns

$All=@(Import-Csv -LiteralPath $Manifest)
Assert-True (@($All|Where-Object status -ceq 'RUNNING').Count -eq 0) 'AMBIGUOUS_RUNNING_ROW_EXISTS'
$Windows=@($All|Where-Object platform -ceq 'Windows')
$Row=@($Windows|Where-Object status -ceq 'PENDING'|Select-Object -First 1)
Assert-True ($Row.Count -eq 1) 'NO_SINGLE_PENDING_WINDOWS_RUN'
$Row=$Row[0]
$GlobalOrder=[array]::IndexOf([object[]]$Windows,$Row)+1
Assert-True ($GlobalOrder -ge 1 -and $GlobalOrder -le 30) 'GLOBAL_ORDER_OUT_OF_RANGE'
Assert-True (@(Get-ChildItem -LiteralPath $OfficialRoot -Directory -Filter ($Row.run_id+'_*')).Count -eq 0) ('OFFICIAL_EVIDENCE_ALREADY_EXISTS:'+$Row.run_id)
Assert-True ([string]$Row.snapshot_baseline -ceq 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013') 'WINDOWS_SNAPSHOT_MANIFEST_DRIFT'
Assert-True ([int]$Row.expected_duration_seconds -eq 60) 'DURATION_MANIFEST_DRIFT'

$LogDir=Join-Path $CampaignRoot '01_SHARED\logs'
New-Item -ItemType Directory -Path $LogDir -Force|Out-Null
$Log=Join-Path $LogDir ('OFFICIAL_'+$Row.run_id+'_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.log')
Write-Host ('NEXT_OFFICIAL_RUN='+$Row.run_id) -ForegroundColor Yellow
Write-Host ('SCENARIO='+$Row.scenario_id+' REPETITION='+$Row.repetition+' GLOBAL_ORDER='+$GlobalOrder) -ForegroundColor Yellow
Write-Host ('LIVE_LOG='+$Log) -ForegroundColor Cyan

Set-ManifestStatus $Manifest $Row.run_id 'PENDING' 'RUNNING'
Start-Transcript -LiteralPath $Log -Force|Out-Null
try{
    $Output=@(& (Join-Path $PackageRoot 'BENIGN_Official_Run_Controller.ps1') `
        -CampaignRoot $CampaignRoot `
        -VmrunPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
        -VMwareGuiPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe' `
        -WindowsVmxPath 'D:\Windows 11\Windows 11.vmx' `
        -UbuntuVmxPath 'D:\Ubuntu 24.04\Ubuntu.vmx' `
        -WindowsSnapshot ([string]$Row.snapshot_baseline) `
        -UbuntuSnapshot 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013' `
        -PreRollSeconds 5 -PostTailSeconds 10 -ActiveWorkloadSeconds ([int]$Row.expected_duration_seconds) `
        -RunID ([string]$Row.run_id) -GlobalOrder $GlobalOrder -ScenarioID ([string]$Row.scenario_id) `
        -Repetition ([string]$Row.repetition) -ScenarioRunID ([string]$Row.scenario_run_id) `
        -FixtureSeed ([string]$Row.fixture_seed) -Split ([string]$Row.split) `
        -ScenarioName ([string]$Row.scenario_name) -LeadApplication ([string]$Row.lead_application))
    $RunRoot=[string]($Output|Select-Object -Last 1)
    Assert-True (Test-Path -LiteralPath $RunRoot -PathType Container) 'CONTROLLER_DID_NOT_RETURN_RUN_ROOT'
    $Result=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_RESULT.json') -Raw|ConvertFrom-Json
    $Verify=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_FULL_VERIFICATION.json') -Raw|ConvertFrom-Json
    Assert-True ([string]$Result.status -ceq 'PASS' -and [string]$Result.run_id -ceq [string]$Row.run_id) 'RUN_RESULT_NOT_PASS'
    Assert-True ([string]$Verify.status -ceq 'PASS' -and [int]$Verify.fail -eq 0) 'RUN_HASH_VERIFICATION_NOT_PASS'
    Set-ManifestStatus $Manifest $Row.run_id 'RUNNING' 'PASS'
    Write-Host ('FINAL OFFICIAL WINDOWS RUN PASS: '+$Row.run_id) -ForegroundColor Green
    Write-Host ('EVIDENCE='+$RunRoot) -ForegroundColor Green
}catch{
    try{Set-ManifestStatus $Manifest $Row.run_id 'RUNNING' 'FAIL'}catch{Write-Host ('MANIFEST_FAILURE_UPDATE_ERROR: '+$_.Exception.Message) -ForegroundColor Red}
    Write-Host ('FINAL OFFICIAL WINDOWS RUN FAIL: '+$Row.run_id+' '+$_.Exception.Message) -ForegroundColor Red
    throw
}finally{
    try{Stop-Transcript|Out-Null}catch{}
}
