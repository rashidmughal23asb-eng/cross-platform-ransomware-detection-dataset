[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_90Runs',
    [switch]$AllowExistingOfficialRuns
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function A([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw ('READINESS_FAILURE:' + $Message) }
    Write-Host ('PASS  ' + $Message) -ForegroundColor Green
}

$ManifestPath = Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_MANIFEST.csv'
$MatrixPath = Join-Path $CampaignRoot '01_SHARED\manifests\BENIGN_60_RUN_SCENARIO_MATRIX.csv'
$WindowsQual = Join-Path $CampaignRoot '02_WINDOWS\BENIGN\qualification\BENIGN_QUAL_d4096cdd7ca246e2_20261106_234511'
$UbuntuQual = Join-Path $CampaignRoot '03_UBUNTU\BENIGN\qualification\UBUNTU_BENIGN_QUAL_24e07f274fff4554_20261107_102820'
$WindowsOfficial = Join-Path $CampaignRoot '02_WINDOWS\BENIGN\official_runs'
$UbuntuOfficial = Join-Path $CampaignRoot '03_UBUNTU\BENIGN\official_runs'

foreach ($Path in @($ManifestPath, $MatrixPath, $WindowsQual, $UbuntuQual, $WindowsOfficial, $UbuntuOfficial)) {
    A (Test-Path -LiteralPath $Path) ('required path exists: ' + $Path)
}

$Rows = @(Import-Csv -LiteralPath $ManifestPath)
A ($Rows.Count -eq 60) 'manifest contains exactly 60 benign runs'
A (@($Rows | Where-Object platform -ceq 'Windows').Count -eq 30) 'manifest contains exactly 30 Windows benign runs'
A (@($Rows | Where-Object platform -ceq 'Ubuntu').Count -eq 30) 'manifest contains exactly 30 Ubuntu benign runs'
A (@($Rows.run_id | Sort-Object -Unique).Count -eq 60) 'run_id values are unique'
A (@($Rows.scenario_run_id | Sort-Object -Unique).Count -eq 60) 'scenario_run_id values are unique'
if ($AllowExistingOfficialRuns) {
    A (@($Rows | Where-Object { $_.status -cnotin @('PENDING','PASS','FAIL','RUNNING') }).Count -eq 0) 'all benign manifest statuses are recognized'
} else {
    A (@($Rows | Where-Object status -cne 'PENDING').Count -eq 0) 'all benign manifest rows remain PENDING'
}

foreach ($Platform in @('Windows', 'Ubuntu')) {
    $PlatformRows = @($Rows | Where-Object platform -ceq $Platform)
    foreach ($Number in 1..15) {
        $Scenario = 'S{0:D2}' -f $Number
        $ScenarioRows = @($PlatformRows | Where-Object scenario_id -ceq $Scenario)
        A ($ScenarioRows.Count -eq 2) ($Platform + ' ' + $Scenario + ' has exactly two repetitions')
        A ((@($ScenarioRows.repetition | Sort-Object -Unique) -join ',') -ceq 'A,B') ($Platform + ' ' + $Scenario + ' repetitions are A and B')
    }
}

$WinResult = Get-Content -LiteralPath (Join-Path $WindowsQual 'QUAL_RESULT.json') -Raw | ConvertFrom-Json
$WinVerify = Get-Content -LiteralPath (Join-Path $WindowsQual 'QUAL_FULL_VERIFICATION.json') -Raw | ConvertFrom-Json
$UbuResult = Get-Content -LiteralPath (Join-Path $UbuntuQual 'QUAL_RESULT.json') -Raw | ConvertFrom-Json
$UbuVerify = Get-Content -LiteralPath (Join-Path $UbuntuQual 'QUAL_FULL_VERIFICATION.json') -Raw | ConvertFrom-Json
A ([string]$WinResult.status -ceq 'PASS') 'authoritative Windows qualification is PASS'
A ([string]$WinVerify.status -ceq 'PASS' -and [int]$WinVerify.fail -eq 0) 'authoritative Windows qualification hashes pass'
A ([string]$UbuResult.status -ceq 'PASS') 'authoritative Ubuntu qualification is PASS'
A ([string]$UbuVerify.status -ceq 'PASS' -and [int]$UbuVerify.fail -eq 0) 'authoritative Ubuntu qualification hashes pass'
A ([int]$WinResult.official_campaign_slots_consumed -eq 0) 'Windows qualification consumed zero official slots'
A ([int]$UbuResult.official_campaign_slots_consumed -eq 0) 'Ubuntu qualification consumed zero official slots'

$WindowsExisting = @(Get-ChildItem -LiteralPath $WindowsOfficial -Force)
$UbuntuExisting = @(Get-ChildItem -LiteralPath $UbuntuOfficial -Force)
if (-not $AllowExistingOfficialRuns) {
    A ($WindowsExisting.Count -eq 0) 'Windows official_runs is empty before campaign start'
    A ($UbuntuExisting.Count -eq 0) 'Ubuntu official_runs is empty before campaign start'
}

Write-Host ''
Write-Host 'OFFICIAL BENIGN CAMPAIGN READINESS: PASS' -ForegroundColor Green
Write-Host 'VM_EXECUTION_PERFORMED=NO' -ForegroundColor Yellow
Write-Host 'OFFICIAL_SLOTS_CONSUMED=0' -ForegroundColor Yellow
Write-Host 'CONTROLLER_RELEASE_STATUS=RELEASED_STATIC_GATE_PASS' -ForegroundColor Green
