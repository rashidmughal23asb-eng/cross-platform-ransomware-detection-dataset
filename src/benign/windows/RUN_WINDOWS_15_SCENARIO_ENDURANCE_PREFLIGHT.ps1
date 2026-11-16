[CmdletBinding()]
param([string]$CampaignRoot='C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs')
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
function A([bool]$C,[string]$M){if(-not$C){throw ('ENDURANCE_PREFLIGHT_FAILURE:'+$M)}}
$P=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());A ($P.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
$Manifest=Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv';$Official=Join-Path $CampaignRoot '02_WINDOWS\BENIGN\official_runs';$Root=Join-Path $CampaignRoot '02_WINDOWS\BENIGN\qualification\endurance_v28';$Controller=Join-Path $PSScriptRoot 'BENIGN_Endurance_Preflight_Controller.ps1'
foreach($Path in @($Manifest,$Official,$Controller)){A (Test-Path $Path) ('REQUIRED_PATH_MISSING:'+$Path)}
A (@(Get-ChildItem $Official -Force).Count -eq 0) 'OFFICIAL_WINDOWS_DIRECTORY_NOT_EMPTY'
$All=@(Import-Csv $Manifest);A (@($All|Where-Object status -cne 'PENDING').Count -eq 0) 'MANIFEST_NOT_ALL_PENDING'
A (-not(Test-Path $Root)) 'ENDURANCE_PREFLIGHT_ROOT_ALREADY_EXISTS'
New-Item -ItemType Directory -Path $Root|Out-Null
$Rows=@($All|Where-Object{$_.platform-ceq'Windows'-and$_.repetition-ceq'A'}|Sort-Object scenario_id);A ($Rows.Count -eq 15) 'EXPECTED_15_WINDOWS_A_ROWS'
$Summary=@()
foreach($Row in $Rows){
    $GlobalOrder=[array]::IndexOf([object[]]@($All|Where-Object platform -ceq 'Windows'),$Row)+1
    Write-Host ('ENDURANCE PREFLIGHT: '+$Row.run_id+' '+$Row.scenario_id+' '+$Row.scenario_name) -ForegroundColor Cyan
    $Output=@(& $Controller -CampaignRoot $CampaignRoot -VmrunPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' -VMwareGuiPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe' -WindowsVmxPath 'D:\Windows 11\Windows 11.vmx' -UbuntuVmxPath 'D:\Ubuntu 24.04\Ubuntu.vmx' -WindowsSnapshot ([string]$Row.snapshot_baseline) -UbuntuSnapshot 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013' -PreRollSeconds 5 -PostTailSeconds 10 -ActiveWorkloadSeconds ([int]$Row.expected_duration_seconds) -RunID ([string]$Row.run_id) -GlobalOrder $GlobalOrder -ScenarioID ([string]$Row.scenario_id) -Repetition ([string]$Row.repetition) -ScenarioRunID ([string]$Row.scenario_run_id) -FixtureSeed ([string]$Row.fixture_seed) -Split ([string]$Row.split) -ScenarioName ([string]$Row.scenario_name) -LeadApplication ([string]$Row.lead_application))
    $RunRoot=[string]($Output|Select-Object -Last 1);A (Test-Path $RunRoot -PathType Container) ('RUN_ROOT_MISSING:'+$Row.run_id)
    $Result=Get-Content (Join-Path $RunRoot 'RUN_RESULT.json') -Raw|ConvertFrom-Json;$Verify=Get-Content (Join-Path $RunRoot 'RUN_FULL_VERIFICATION.json') -Raw|ConvertFrom-Json
    A ([string]$Result.status -ceq 'PASS' -and [int]$Result.official_campaign_slots_consumed -eq 0) ('RESULT_NOT_PASS_ZERO_SLOT:'+$Row.run_id)
    A ([string]$Verify.status -ceq 'PASS' -and [int]$Verify.fail -eq 0) ('HASH_NOT_PASS:'+$Row.run_id)
    $Summary+=[pscustomobject]@{run_id=$Row.run_id;scenario_id=$Row.scenario_id;status='PASS';evidence=$RunRoot;active_duration_seconds=$Result.workload_duration_seconds;root_lifecycle_seconds=$Result.workload_root_lifecycle_seconds}
}
$SummaryPath=Join-Path $Root 'ENDURANCE_PREFLIGHT_SUMMARY.json';[IO.File]::WriteAllText($SummaryPath,(($Summary|ConvertTo-Json -Depth 5)+"`r`n"),(New-Object Text.UTF8Encoding($false)))
A (@(Import-Csv $Manifest|Where-Object status -cne 'PENDING').Count -eq 0) 'PREFLIGHT_CHANGED_OFFICIAL_MANIFEST'
Write-Host 'WINDOWS 15-SCENARIO ENDURANCE PREFLIGHT: PASS; OFFICIAL SLOTS=0' -ForegroundColor Green
