[CmdletBinding()]
param(
    [string]$CampaignRoot='C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs',
    [ValidateRange(0,30)][int]$MaxRuns=0
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
function A([bool]$C,[string]$M){if(-not$C){throw ('UBUNTU_ORCHESTRATOR_FAILURE:'+$M)}}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};[IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 20)+"`r`n"),(New-Object Text.UTF8Encoding($false)))}

# --- Campaign spec item 8: refuse PASS rows without exactly one valid package, orphan or duplicate packages.
function Assert-EvidenceIntegrity([object[]]$Rows,[string]$Root){
    $Known=@($Rows|Where-Object platform -ceq 'Ubuntu'|ForEach-Object {[string]$_.run_id})
    foreach($Trusted in @($Rows|Where-Object platform -ceq 'Ubuntu'|Where-Object status -ceq 'PASS')){
        $Id=[string]$Trusted.run_id
        $Dirs=@(Get-ChildItem -LiteralPath $Root -Directory -Filter ($Id+'_*') -ErrorAction SilentlyContinue)
        A ($Dirs.Count -eq 1) ('PASS_ROW_EVIDENCE_PACKAGE_COUNT_NOT_ONE:'+$Id+':count='+$Dirs.Count)
        $RunResult=Join-Path $Dirs[0].FullName 'RUN_RESULT.json'
        $FullVerify=Join-Path $Dirs[0].FullName 'RUN_FULL_VERIFICATION.json'
        A (Test-Path -LiteralPath $RunResult -PathType Leaf) ('PASS_ROW_RUN_RESULT_MISSING:'+$Id)
        A (Test-Path -LiteralPath $FullVerify -PathType Leaf) ('PASS_ROW_FULL_VERIFICATION_MISSING:'+$Id)
        $R=Get-Content -LiteralPath $RunResult -Raw|ConvertFrom-Json
        $V=Get-Content -LiteralPath $FullVerify -Raw|ConvertFrom-Json
        A ([string]$R.status -ceq 'PASS') ('PASS_ROW_RUN_RESULT_NOT_PASS:'+$Id)
        A ([string]$R.run_id -ceq $Id) ('PASS_ROW_RUN_ID_MISMATCH:'+$Id)
        A ([int]$R.official_campaign_slots_consumed -eq 1) ('PASS_ROW_SLOT_COUNT_NOT_ONE:'+$Id)
        A ([string]$V.status -ceq 'PASS' -and [int]$V.fail -eq 0) ('PASS_ROW_FULL_VERIFICATION_NOT_PASS:'+$Id)
    }
    foreach($Dir in @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue)){
        $M=[regex]::Match($Dir.Name,'^(BEN_UBU_[0-9]{2})_')
        A $M.Success ('UNRECOGNIZED_EVIDENCE_DIRECTORY:'+$Dir.Name)
        A ($Known -contains $M.Groups[1].Value) ('EVIDENCE_DIRECTORY_NOT_IN_MANIFEST:'+$Dir.Name)
    }
}

$P=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());A ($P.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
$Manifest=Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv';$Launcher=Join-Path $PSScriptRoot 'RUN_NEXT_UBUNTU_OFFICIAL.ps1';A (Test-Path $Launcher -PathType Leaf) 'NEXT_RUN_LAUNCHER_MISSING'
$OfficialRoot=Join-Path $CampaignRoot '03_UBUNTU\BENIGN\official_runs'
$Completed=0
while($true){
    $Rows=@(Import-Csv $Manifest);$Platform=@($Rows|Where-Object platform -ceq 'Ubuntu')
    A (@($Platform|Where-Object status -ceq 'RUNNING').Count -eq 0) 'AMBIGUOUS_RUNNING_ROW'
    A (@($Platform|Where-Object status -ceq 'FAIL').Count -eq 0) 'FAILED_ROW_REQUIRES_REPAIR'
    Assert-EvidenceIntegrity $Rows $OfficialRoot
    $Pending=@($Platform|Where-Object status -ceq 'PENDING')
    if($Pending.Count -eq 0){break}
    if($MaxRuns -gt 0 -and $Completed -ge $MaxRuns){break}
    Write-Host ('UBUNTU ORCHESTRATOR: launching '+$Pending[0].run_id+'; pending='+$Pending.Count) -ForegroundColor Cyan
    & $Launcher -CampaignRoot $CampaignRoot
    $Completed++
}
$Final=@(Import-Csv $Manifest|Where-Object platform -ceq 'Ubuntu')
$Pass=@($Final|Where-Object status -ceq 'PASS').Count
$Pending=@($Final|Where-Object status -ceq 'PENDING').Count
$Running=@($Final|Where-Object status -ceq 'RUNNING').Count
$Fail=@($Final|Where-Object status -ceq 'FAIL').Count
if($Pending -eq 0 -and $Running -eq 0 -and $Fail -eq 0 -and $Pass -eq 30){
    # --- Campaign spec item 11: final Ubuntu campaign verification receipt.
    $AllFinal=@(Import-Csv $Manifest)
    A ($AllFinal.Count -eq 60) 'FINAL_MANIFEST_ROW_COUNT_NOT_60'
    A ($Pass -eq 30) 'FINAL_UBUNTU_PASS_COUNT_NOT_30'
    A (@($AllFinal|Where-Object platform -ceq 'Windows'|Where-Object status -ceq 'PASS').Count -eq 30) 'FINAL_WINDOWS_OFFICIAL_NOT_30_PASS'
    A (@(Get-ChildItem -LiteralPath (Join-Path $CampaignRoot '02_WINDOWS\BENIGN\official_runs') -Directory -Force -ErrorAction SilentlyContinue).Count -eq 30) 'FINAL_WINDOWS_EVIDENCE_DIRECTORY_COUNT_NOT_30'
    foreach($Number in 1..15){
        $Scenario='S{0:D2}' -f $Number
        $ScenarioRows=@($Final|Where-Object scenario_id -ceq $Scenario)
        A ($ScenarioRows.Count -eq 2) ('FINAL_SCENARIO_ROW_COUNT_NOT_TWO:'+$Scenario)
        A ((@($ScenarioRows.repetition|Sort-Object -Unique) -join ',') -ceq 'A,B') ('FINAL_SCENARIO_REPETITIONS_NOT_A_B:'+$Scenario)
    }
    $Dirs=@(Get-ChildItem -LiteralPath $OfficialRoot -Directory -Force|Sort-Object Name)
    A ($Dirs.Count -eq 30) ('FINAL_EVIDENCE_DIRECTORY_COUNT_NOT_30:'+$Dirs.Count)
    $Slots=0
    $Details=@()
    foreach($Dir in $Dirs){
        $RunResult=Join-Path $Dir.FullName 'RUN_RESULT.json'
        $FullVerify=Join-Path $Dir.FullName 'RUN_FULL_VERIFICATION.json'
        A (Test-Path -LiteralPath $RunResult -PathType Leaf) ('FINAL_RUN_RESULT_MISSING:'+$Dir.Name)
        A (Test-Path -LiteralPath $FullVerify -PathType Leaf) ('FINAL_FULL_VERIFICATION_MISSING:'+$Dir.Name)
        $R=Get-Content -LiteralPath $RunResult -Raw|ConvertFrom-Json
        $V=Get-Content -LiteralPath $FullVerify -Raw|ConvertFrom-Json
        A ([string]$R.status -ceq 'PASS') ('FINAL_RUN_RESULT_NOT_PASS:'+$Dir.Name)
        A ([string]$V.status -ceq 'PASS' -and [int]$V.fail -eq 0) ('FINAL_FULL_VERIFICATION_NOT_PASS:'+$Dir.Name)
        A ([int]$R.official_campaign_slots_consumed -eq 1) ('FINAL_SLOT_COUNT_NOT_ONE:'+$Dir.Name)
        $Slots+=[int]$R.official_campaign_slots_consumed
        $Details+=[pscustomobject][ordered]@{run_id=[string]$R.run_id;scenario_id=[string]$R.scenario_id;repetition=[string]$R.repetition;scenario_run_id=[string]$R.scenario_run_id;evidence_directory=$Dir.Name;official_campaign_slots_consumed=[int]$R.official_campaign_slots_consumed}
    }
    A ($Slots -eq 30) ('FINAL_AGGREGATE_SLOTS_NOT_30:'+$Slots)
    $PackageManifest=Join-Path (Split-Path -Parent $PSScriptRoot) 'PACKAGE_SHA256.csv'
    A (Test-Path -LiteralPath $PackageManifest -PathType Leaf) 'FINAL_PACKAGE_CHECKSUM_FILE_MISSING'
    $PackageRows=@(Import-Csv -LiteralPath $PackageManifest)
    A ($PackageRows.Count -eq 26) 'FINAL_PACKAGE_CHECKSUM_ROW_COUNT_NOT_26'
    $PackageFailures=0
    foreach($PackageRow in $PackageRows){
        $PackageFile=Join-Path (Split-Path -Parent $PSScriptRoot) ([string]$PackageRow.relative_path)
        if((-not (Test-Path -LiteralPath $PackageFile -PathType Leaf)) -or ((Get-FileHash -LiteralPath $PackageFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne ([string]$PackageRow.sha256).ToLowerInvariant())){$PackageFailures++}
    }
    A ($PackageFailures -eq 0) ('FINAL_PACKAGE_INTEGRITY_FAILED:'+$PackageFailures)
    $Receipt=Join-Path $OfficialRoot 'UBUNTU_OFFICIAL_CAMPAIGN_VERIFICATION.json'
    Write-Json $Receipt ([ordered]@{
        schema_version='1.0'
        gate='UBUNTU_OFFICIAL_CAMPAIGN'
        status='PASS'
        platform='Ubuntu'
        official_campaign_slots_consumed=$Slots
        ubuntu_pass_rows=$Pass
        ubuntu_pending_rows=$Pending
        ubuntu_running_rows=$Running
        ubuntu_fail_rows=$Fail
        windows_official_pass_rows=30
        windows_evidence_directory_count=30
        evidence_directory_count=@($Dirs).Count
        unique_evidence_directories=@($Dirs.Name|Sort-Object -Unique).Count
        scenarios_s01_s15_ab_complete=$true
        package_checksum_rows=$PackageRows.Count
        package_checksum_file_sha256=(Get-FileHash -LiteralPath $PackageManifest -Algorithm SHA256).Hash.ToLowerInvariant()
        package_integrity='PASS'
        windows_results_unchanged=$true
        runs=$Details
        timestamp=[DateTime]::UtcNow.ToString('o')
    })
    Write-Host ('UBUNTU ONE-CLICK ORCHESTRATOR COMPLETE: newly_completed='+$Completed+' total_pass='+$Pass+'/30 pending=0') -ForegroundColor Green
    Write-Host 'FINAL UBUNTU CAMPAIGN VERIFICATION: PASS' -ForegroundColor Green
    Write-Host ('RECEIPT='+$Receipt) -ForegroundColor Green
}
else{
    Write-Host ('UBUNTU ORCHESTRATOR STOPPED: newly_completed='+$Completed+' total_pass='+$Pass+'/30 pending='+$Pending+' running='+$Running+' fail='+$Fail) -ForegroundColor Yellow
}
