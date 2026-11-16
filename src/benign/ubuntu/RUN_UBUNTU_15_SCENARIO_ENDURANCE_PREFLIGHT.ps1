[CmdletBinding()]
param(
    [string]$CampaignRoot='C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw ('UBUNTU_ENDURANCE_PREFLIGHT_PRECHECK_FAILURE:'+$Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}

$Principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
$PackageRoot=$PSScriptRoot
$Manifest=Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv'
$OfficialRoot=Join-Path $CampaignRoot '03_UBUNTU\BENIGN\official_runs'
$QualificationRoot=Join-Path $CampaignRoot '03_UBUNTU\BENIGN\qualification\endurance_v28'
$Controller=Join-Path $PackageRoot 'Ubuntu_Benign_Endurance_Preflight_Controller.ps1'
$Readiness=Join-Path (Split-Path -Parent $PackageRoot) 'VERIFY_OFFICIAL_CAMPAIGN_READINESS.ps1'
foreach($Path in @($CampaignRoot,$Manifest,$OfficialRoot,$Controller,$Readiness)){Assert-True (Test-Path -LiteralPath $Path) ('REQUIRED_PATH_MISSING:'+$Path)}
Assert-True (@(Get-ChildItem -LiteralPath $OfficialRoot -Force).Count -eq 0) 'UBUNTU_OFFICIAL_DIRECTORY_MUST_BE_EMPTY'
Assert-True (-not(Test-Path -LiteralPath $QualificationRoot)) 'ENDURANCE_QUALIFICATION_ROOT_ALREADY_EXISTS'

& $Readiness -CampaignRoot $CampaignRoot -AllowExistingOfficialRuns
$ManifestHashBefore=SHA $Manifest
$All=@(Import-Csv -LiteralPath $Manifest)
Assert-True ($All.Count -eq 60) 'MANIFEST_ROW_COUNT_NOT_60'
Assert-True (@($All|Where-Object platform -ceq 'Windows').Count -eq 30) 'WINDOWS_ROW_COUNT_NOT_30'
Assert-True (@($All|Where-Object platform -ceq 'Windows'|Where-Object status -ceq 'PASS').Count -eq 30) 'WINDOWS_OFFICIAL_CAMPAIGN_NOT_COMPLETE'
$Rows=@($All|Where-Object platform -ceq 'Ubuntu'|Where-Object repetition -ceq 'A'|Sort-Object scenario_id)
Assert-True ($Rows.Count -eq 15) 'UBUNTU_REPETITION_A_SCENARIO_COUNT_NOT_15'
Assert-True (@($All|Where-Object platform -ceq 'Ubuntu'|Where-Object status -ceq 'PENDING').Count -eq 30) 'UBUNTU_ROWS_NOT_ALL_PENDING'
Assert-True (@($Rows|Select-Object -ExpandProperty scenario_id -Unique).Count -eq 15) 'UBUNTU_SCENARIOS_NOT_UNIQUE'
Assert-True (@($Rows|Where-Object{[int]$_.expected_duration_seconds -ne 60}).Count -eq 0) 'UBUNTU_DURATION_MANIFEST_DRIFT'
Assert-True (@($Rows|Where-Object{[string]$_.snapshot_baseline -cne 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013'}).Count -eq 0) 'UBUNTU_SNAPSHOT_MANIFEST_DRIFT'

New-Item -ItemType Directory -Path $QualificationRoot -Force|Out-Null
$Completed=0
foreach($Row in $Rows){
    $GlobalOrder=[array]::IndexOf([object[]]@($All|Where-Object platform -ceq 'Ubuntu'),$Row)+1
    Write-Host ('UBUNTU ENDURANCE PREFLIGHT: '+$Row.run_id+' '+$Row.scenario_id+' '+$Row.scenario_name) -ForegroundColor Cyan
    $Output=@(& $Controller `
        -CampaignRoot $CampaignRoot `
        -VmrunPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
        -VMwareGuiPath 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe' `
        -WindowsVmxPath 'D:\Windows 11\Windows 11.vmx' `
        -UbuntuVmxPath 'D:\Ubuntu 24.04\Ubuntu.vmx' `
        -WindowsSnapshot 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013' `
        -UbuntuSnapshot ([string]$Row.snapshot_baseline) `
        -PreRollSeconds 5 -PostTailSeconds 10 -ActiveWorkloadSeconds ([int]$Row.expected_duration_seconds) `
        -RunID ([string]$Row.run_id) -GlobalOrder $GlobalOrder -ScenarioID ([string]$Row.scenario_id) `
        -Repetition ([string]$Row.repetition) -ScenarioRunID ([string]$Row.scenario_run_id) `
        -FixtureSeed ([string]$Row.fixture_seed) -Split ([string]$Row.split) `
        -ScenarioName ([string]$Row.scenario_name) -LeadApplication ([string]$Row.lead_application))
    $RunRoot=[string]($Output|Select-Object -Last 1)
    Assert-True (Test-Path -LiteralPath $RunRoot -PathType Container) ('CONTROLLER_DID_NOT_RETURN_RUN_ROOT:'+$Row.run_id)
    Assert-True ($RunRoot.StartsWith($QualificationRoot,[StringComparison]::OrdinalIgnoreCase)) ('RUN_ROOT_OUTSIDE_QUALIFICATION:'+$RunRoot)
    $Result=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_RESULT.json') -Raw|ConvertFrom-Json
    $Verify=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_FULL_VERIFICATION.json') -Raw|ConvertFrom-Json
    Assert-True ([string]$Result.status -ceq 'PASS') ('RUN_RESULT_NOT_PASS:'+$Row.run_id)
    Assert-True ([bool]$Result.qualification_only -and -not[bool]$Result.official_run -and [bool]$Result.endurance_preflight) ('RUN_NOT_QUALIFICATION_ONLY:'+$Row.run_id)
    Assert-True ([int]$Result.official_campaign_slots_consumed -eq 0) ('OFFICIAL_SLOT_CONSUMED:'+$Row.run_id)
    Assert-True ([string]$Verify.status -ceq 'PASS' -and [int]$Verify.fail -eq 0) ('RUN_HASH_VERIFICATION_NOT_PASS:'+$Row.run_id)
    Assert-True ((SHA $Manifest) -ceq $ManifestHashBefore) ('MANIFEST_CHANGED_DURING_PREFLIGHT:'+$Row.run_id)
    $Completed++
}

Assert-True ($Completed -eq 15) 'NOT_ALL_15_SCENARIOS_COMPLETED'
Assert-True ((SHA $Manifest) -ceq $ManifestHashBefore) 'MANIFEST_CHANGED_BY_PREFLIGHT'
Assert-True (@(Get-ChildItem -LiteralPath $OfficialRoot -Force).Count -eq 0) 'UBUNTU_OFFICIAL_DIRECTORY_CHANGED_BY_PREFLIGHT'
$Summary=[ordered]@{status='PASS';qualification_only=$true;official_campaign_slots_consumed=0;scenario_count=15;manifest_sha256_before=$ManifestHashBefore;manifest_sha256_after=(SHA $Manifest);qualification_root=$QualificationRoot;timestamp=[DateTime]::UtcNow.ToString('o')}
[IO.File]::WriteAllText((Join-Path $QualificationRoot 'UBUNTU_15_SCENARIO_ENDURANCE_PREFLIGHT_SUMMARY.json'),(($Summary|ConvertTo-Json -Depth 5)+"`r`n"),(New-Object Text.UTF8Encoding($false)))
Write-Host 'UBUNTU 15-SCENARIO ENDURANCE PREFLIGHT: PASS; OFFICIAL SLOTS=0' -ForegroundColor Green
Write-Host ('QUALIFICATION_ROOT='+$QualificationRoot) -ForegroundColor Green
