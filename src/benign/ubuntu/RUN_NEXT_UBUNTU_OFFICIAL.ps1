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
$OfficialRoot=Join-Path $CampaignRoot '03_UBUNTU\BENIGN\official_runs'
$Readiness=Join-Path (Split-Path -Parent $PackageRoot) 'VERIFY_OFFICIAL_CAMPAIGN_READINESS.ps1'
foreach($Path in @($CampaignRoot,$Manifest,$OfficialRoot,$Readiness,(Join-Path $PackageRoot 'Ubuntu_Benign_Official_Run_Controller.ps1'))){Assert-True (Test-Path -LiteralPath $Path) ('REQUIRED_PATH_MISSING:'+$Path)}
& $Readiness -CampaignRoot $CampaignRoot -AllowExistingOfficialRuns

# --- Campaign spec item 9: the frozen instrument must match its recorded hashes every run.
$PackageManifest=Join-Path (Split-Path -Parent $PackageRoot) 'PACKAGE_SHA256.csv'
Assert-True (Test-Path -LiteralPath $PackageManifest -PathType Leaf) 'PACKAGE_CHECKSUM_FILE_MISSING'
$PackageRows=@(Import-Csv -LiteralPath $PackageManifest)
Assert-True ($PackageRows.Count -eq 26) 'PACKAGE_CHECKSUM_ROW_COUNT_NOT_26'
$PackageFailures=@()
foreach($PackageRow in $PackageRows){
    $PackageFile=Join-Path (Split-Path -Parent $PackageRoot) ([string]$PackageRow.relative_path)
    if(-not (Test-Path -LiteralPath $PackageFile -PathType Leaf)){$PackageFailures+=[string]('MISSING:'+$PackageRow.relative_path);continue}
    if((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne ([string]$PackageRow.sha256).ToLowerInvariant()){$PackageFailures+=[string]('SHA256_MISMATCH:'+$PackageRow.relative_path)}
}
Assert-True ($PackageFailures.Count -eq 0) ('PACKAGE_INTEGRITY_FAILED:'+(@($PackageFailures) -join ';'))
Write-Host ('PACKAGE_INTEGRITY: PASS rows='+$PackageRows.Count) -ForegroundColor Green

# --- Campaign spec item 9: the Ubuntu endurance preflight must remain PASS and zero-slot.
$EnduranceRoot=Join-Path $CampaignRoot '03_UBUNTU\BENIGN\qualification\endurance_v28'
$EnduranceSummary=Join-Path $EnduranceRoot 'UBUNTU_15_SCENARIO_ENDURANCE_PREFLIGHT_SUMMARY.json'
Assert-True (Test-Path -LiteralPath $EnduranceSummary -PathType Leaf) 'UBUNTU_ENDURANCE_PREFLIGHT_SUMMARY_MISSING'
$Endurance=Get-Content -LiteralPath $EnduranceSummary -Raw|ConvertFrom-Json
Assert-True ([string]$Endurance.status -ceq 'PASS') 'UBUNTU_ENDURANCE_PREFLIGHT_NOT_PASS'
Assert-True ([int]$Endurance.scenario_count -eq 15) 'UBUNTU_ENDURANCE_PREFLIGHT_SCENARIO_COUNT_NOT_15'
Assert-True ([int]$Endurance.official_campaign_slots_consumed -eq 0) 'UBUNTU_ENDURANCE_PREFLIGHT_CONSUMED_SLOTS'
Assert-True (@(Get-ChildItem -LiteralPath $EnduranceRoot -Directory -ErrorAction SilentlyContinue).Count -eq 15) 'UBUNTU_ENDURANCE_PREFLIGHT_DIRECTORY_COUNT_NOT_15'

$All=@(Import-Csv -LiteralPath $Manifest)
Assert-True (@($All|Where-Object status -ceq 'RUNNING').Count -eq 0) 'AMBIGUOUS_RUNNING_ROW_EXISTS'
# --- Campaign spec item 9: the Windows official block must remain 30/30 PASS.
Assert-True (@($All|Where-Object platform -ceq 'Windows'|Where-Object status -ceq 'PASS').Count -eq 30) 'WINDOWS_OFFICIAL_NOT_30_PASS'
Assert-True (@($All|Where-Object platform -ceq 'Windows'|Where-Object status -cne 'PASS').Count -eq 0) 'WINDOWS_OFFICIAL_NON_PASS_ROW'
$Ubuntu=@($All|Where-Object platform -ceq 'Ubuntu')
$Row=@($Ubuntu|Where-Object status -ceq 'PENDING'|Select-Object -First 1)
Assert-True ($Row.Count -eq 1) 'NO_SINGLE_PENDING_UBUNTU_RUN'
$Row=$Row[0]
$GlobalOrder=[array]::IndexOf([object[]]$Ubuntu,$Row)+1
Assert-True ($GlobalOrder -ge 1 -and $GlobalOrder -le 30) 'GLOBAL_ORDER_OUT_OF_RANGE'
Assert-True (@(Get-ChildItem -LiteralPath $OfficialRoot -Directory -Filter ($Row.run_id+'_*')).Count -eq 0) ('OFFICIAL_EVIDENCE_ALREADY_EXISTS:'+$Row.run_id)
Assert-True ([string]$Row.snapshot_baseline -ceq 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013') 'UBUNTU_SNAPSHOT_MANIFEST_DRIFT'
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
    $Output=@(& (Join-Path $PackageRoot 'Ubuntu_Benign_Official_Run_Controller.ps1') `
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
    Assert-True (Test-Path -LiteralPath $RunRoot -PathType Container) 'CONTROLLER_DID_NOT_RETURN_RUN_ROOT'
    $Result=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_RESULT.json') -Raw|ConvertFrom-Json
    $Verify=Get-Content -LiteralPath (Join-Path $RunRoot 'RUN_FULL_VERIFICATION.json') -Raw|ConvertFrom-Json
    Assert-True ([string]$Result.status -ceq 'PASS' -and [string]$Result.run_id -ceq [string]$Row.run_id) 'RUN_RESULT_NOT_PASS'
    Assert-True ([string]$Verify.status -ceq 'PASS' -and [int]$Verify.fail -eq 0) 'RUN_HASH_VERIFICATION_NOT_PASS'
    # --- Campaign spec item 10: recovery receipt must prove the post-run host/VM state.
    $RecoveryReceipt=Join-Path $RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json'
    Assert-True (Test-Path -LiteralPath $RecoveryReceipt -PathType Leaf) 'RECOVERY_RECEIPT_MISSING'
    $Recovery=Get-Content -LiteralPath $RecoveryReceipt -Raw|ConvertFrom-Json
    Assert-True ([string]$Recovery.status -ceq 'PASS') 'RECOVERY_RECEIPT_NOT_PASS'
    Assert-True ([bool]$Recovery.ubuntu_off) 'RECOVERY_UBUNTU_NOT_OFF'
    Assert-True ([bool]$Recovery.windows_off) 'RECOVERY_WINDOWS_NOT_OFF'
    Assert-True ([string]$Recovery.ubuntu_snapshot -ceq [string]$Row.snapshot_baseline) 'RECOVERY_UBUNTU_SNAPSHOT_MISMATCH'
    Assert-True ([string]$Recovery.windows_snapshot -ceq 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013') 'RECOVERY_WINDOWS_SNAPSHOT_MISMATCH'
    Assert-True ([bool]$Recovery.network_restored) 'RECOVERY_NETWORK_RESTORE_NOT_CONFIRMED'
    Assert-True ([bool]$Recovery.gui_entries_restored) 'RECOVERY_GUI_ENTRIES_NOT_RESTORED'
    Set-ManifestStatus $Manifest $Row.run_id 'RUNNING' 'PASS'
    Write-Host ('FINAL OFFICIAL UBUNTU RUN PASS: '+$Row.run_id) -ForegroundColor Green
    Write-Host ('EVIDENCE='+$RunRoot) -ForegroundColor Green
}catch{
    $FailureMessage=$_.Exception.Message
    try{Set-ManifestStatus $Manifest $Row.run_id 'RUNNING' 'FAIL'}catch{Write-Host ('MANIFEST_FAILURE_UPDATE_ERROR: '+$_.Exception.Message) -ForegroundColor Red}
    # --- Campaign spec item 7: print failed run ID, stage, evidence path and manifest status.
    $FailedDirectories=@(Get-ChildItem -LiteralPath $OfficialRoot -Directory -Filter ($Row.run_id+'_*') -ErrorAction SilentlyContinue)
    $FailedRoot=''
    if($FailedDirectories.Count -eq 1){$FailedRoot=$FailedDirectories[0].FullName}
    $FailedStage='NOT_RECORDED'
    if($FailedRoot -ne ''){
        $ControllerLog=Join-Path $FailedRoot 'UBUNTU_BENIGN_OFFICIAL_CONTROLLER.log'
        if(Test-Path -LiteralPath $ControllerLog -PathType Leaf){
            $StageLines=@(Get-Content -LiteralPath $ControllerLog|Where-Object{$_ -match '^\S+ \[[A-Za-z]+\] \[[A-Z_]+\] '})
            if($StageLines.Count -gt 0){
                $StageMatch=[regex]::Match([string]$StageLines[$StageLines.Count-1],'^\S+ \[[A-Za-z]+\] \[([A-Z_]+)\] ')
                if($StageMatch.Success){$FailedStage=$StageMatch.Groups[1].Value}
            }
        }
    }
    $FailedResult=$null
    if($FailedRoot -ne ''){
        $FailedResultPath=Join-Path $FailedRoot 'RUN_RESULT.json'
        if(Test-Path -LiteralPath $FailedResultPath -PathType Leaf){
            try{$FailedResult=Get-Content -LiteralPath $FailedResultPath -Raw|ConvertFrom-Json}catch{$FailedResult=$null}
        }
    }
    Write-Host ''
    Write-Host '=== OFFICIAL UBUNTU RUN FAILURE (FAIL-CLOSED, NO RETRY) ===' -ForegroundColor Red
    Write-Host ('FAILED_RUN_ID='+[string]$Row.run_id) -ForegroundColor Red
    Write-Host ('FAILED_STAGE='+$FailedStage) -ForegroundColor Red
    Write-Host ('FAILED_EVIDENCE_PATH='+$(if($FailedRoot -ne ''){$FailedRoot}else{'NOT_FOUND'})) -ForegroundColor Red
    Write-Host 'MANIFEST_STATUS=FAIL' -ForegroundColor Red
    Write-Host ('ERROR='+$FailureMessage) -ForegroundColor Red
    if($null -ne $FailedResult){
        $FailedProperties=@($FailedResult.PSObject.Properties.Name)
        if($FailedProperties -contains 'execution_error'){
            if(-not [string]::IsNullOrEmpty([string]$FailedResult.execution_error)){Write-Host ('EXECUTION_ERROR='+[string]$FailedResult.execution_error) -ForegroundColor Red}
        }
        if($FailedProperties -contains 'recovery_error'){
            if(-not [string]::IsNullOrEmpty([string]$FailedResult.recovery_error)){Write-Host ('RECOVERY_ERROR='+[string]$FailedResult.recovery_error) -ForegroundColor Red}
        }
    }
    Write-Host 'CAMPAIGN_HALTED=TRUE NEXT_ACTION=REPAIR_FAILED_ROW_THEN_RELAUNCH' -ForegroundColor Red
    throw
}finally{
    try{Stop-Transcript|Out-Null}catch{}
}
