<#
    DIAGNOSE_UBUNTU_SAMPLE_PREPARE.ps1
    ==================================
    D-122: read-only host-side diagnostic for the SAMPLE_PREPARE failure.

    It reproduces the EXACT conditions of the failed preflight stage - same V11 snapshot,
    same host isolation, same native-VIX boot, same sudo credential transport, same helper
    argument vector - and then:

      1. runs the FROZEN helper's own sample_prepare. That stage only STAGES the sample
         (copies it, chmod 500, builds the 25-file canary corpus) and verifies the guest
         isolation; it NEVER EXECUTES the sample and never starts telemetry;
      2. runs a companion read-only diagnostic script as root, which reports the staged
         sample's metadata, the guest's network state, the toolchain and the helper's mode
         arithmetic;
      3. copies the helper log and the diagnostic report back to the host - the failed run
         lost both, because the bridge's Invoke-UbuntuGuestProgram returns only the exit
         code and the copy of the helper log failed silently;
      4. powers the guest off, REVERTS TO THE V11 BASELINE, verifies the revert, restores
         the host network.

    IT CONSUMES NO OFFICIAL SLOT, IT EXECUTES NO RANSOMWARE SAMPLE, IT TOUCHES NO MANIFEST,
    AND IT LEAVES THE GUEST ON THE SAME BASELINE IT FOUND.
#>
[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs',
    [string]$RunID = 'RAN_UBU_01_A',
    [string]$SampleRunId = 'L-R-01',
    [string]$FamilyStratum = 'Conti',
    [string]$SampleSha256 = '8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201',
    [string]$SampleBytes = '36344',
    [string]$SampleGuestPath = '/opt/RansomLab/MalwareStaging/P5G/V10/Samples/8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201.sample',
    [string]$ModeOctal = '0000',
    [switch]$SkipHelperRun
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageRoot = $PSScriptRoot
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'UbuntuNativeBridge.ps1')

$VmrunPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$VMwareGuiPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe'
$UbuntuVmxPath = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$UbuntuSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112'
$WindowsSnapshot = 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013'
$Script:AttemptID = [guid]::NewGuid().ToString('N').Substring(0, 16)
$AttemptID = $Script:AttemptID
$OutDir = Join-Path $CampaignRoot ('01_SHARED\audit\UBUNTU_SAMPLE_PREPARE_DIAGNOSTIC_' + $AttemptID)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ---- the three helpers the CONTROLLER owns; the diagnostic defines its own copies (the
# ---- controller is frozen and must not be modified, and the preflight driver pins its hash)
function Get-UniqueVmsd([string]$Vmx) {
    $a = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    if ($a.Count -ne 1) { throw ('VMSD_NOT_UNIQUE:' + $Vmx) }
    return $a[0].FullName
}
function Get-CurrentSnapshotName([string]$Vmx, [string]$Label) {
    $lines = [IO.File]::ReadAllLines((Get-UniqueVmsd $Vmx))
    $cur = ''; $uidToIndex = @{}; $indexToName = @{}
    foreach ($l in $lines) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"'); if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.uid\s*=\s*"([^"]*)"'); if ($m.Success) { $uidToIndex[$m.Groups[2].Value] = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.displayName\s*=\s*"([^"]*)"'); if ($m.Success) { $indexToName[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    if ($uidToIndex.ContainsKey($cur) -and $indexToName.ContainsKey($uidToIndex[$cur])) { return $indexToName[$uidToIndex[$cur]] }
    return ''
}
function Ensure-GuiEntries {
    $procs = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
    Write-Host ('[DIAG] VMware GUI windows present: ' + $procs.Count)
}
function Restore-HostNetwork([object]$Baseline) {
    foreach ($a in @($Baseline.PhysicalAdapters)) { if ([string]$a.InitialStatus -ceq 'Up') { Enable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop } }
    $deadline = [DateTime]::UtcNow.AddSeconds(300); $attempt = 0; $consecutiveRestored = 0; $last = 'NOT_TESTED'
    do {
        Start-Sleep -Seconds 2; $attempt++
        $cur = Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID 'DIAG'
        $check = Test-P5GNetworkRestored $Baseline $cur.PhysicalAdapters $cur.Routes ([pscustomobject]@{ vms_safe = $true })
        if ([bool]$check.restored) {
            $consecutiveRestored++
            if ($consecutiveRestored -ge 3) { Write-Host ('[DIAG] host network restored after ' + $attempt + ' checks'); return $cur }
        } else { $consecutiveRestored = 0; $last = [string]$check.reason }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw ('NETWORK_ADAPTER_RESTORE_NOT_CONFIRMED:attempts=' + $attempt + ':last_reason=' + $last)
}
function Write-Json([string]$Path, [object]$Object) {
    [IO.File]::WriteAllText($Path, (($Object | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Get-VmOn([string]$Vmrun, [string]$Vmx) {
    $out = & $Vmrun list 2>$null
    return (@($out | Where-Object { $_ -and ([string]$_).Trim().ToLowerInvariant() -eq $Vmx.ToLowerInvariant() }).Count -gt 0)
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_POWERSHELL_REQUIRED' }

$guestRunRoot = '/tmp/ransomware_diag/' + $AttemptID
$guestHelper = '/tmp/RANSOMWARE_Guest_Official_diag_' + $AttemptID + '.sh'
$guestDiag = '/tmp/diag_' + $AttemptID + '.sh'
$guestCred = '/tmp/RANSOMWARE_DIAG_' + $AttemptID + '.sudo'
$guestReport = '/tmp/diag_report_' + $AttemptID + '.txt'

$baseline = $null
$isolationStarted = $false
$report = [ordered]@{
    schema_version = '1.0'
    gate = 'UBUNTU_SAMPLE_PREPARE_DIAGNOSTIC'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    mode = 'READ_ONLY_DIAGNOSTIC'
    ransomware_sample_executed = $false
    official_run_slot_consumed = $false
    helper_sample_prepare_ran = (-not $SkipHelperRun)
    helper_exit_code = $null
    helper_log_retrieved = $false
    diagnostic_report_retrieved = $false
    diagnostic_log_retrieved = $false
    baseline_reverted = $false
    guest_snapshot_before = ''
    guest_snapshot_after = ''
}

try {
    $report.guest_snapshot_before = (Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu')
    Write-Host ('[DIAG] the Ubuntu guest is currently on: ' + $report.guest_snapshot_before)

    Write-Host '[DIAG] capturing the network baseline and disabling the host adapters (as the controller does)'
    $baseline = Get-P5GNetworkBaseline -AttemptID $AttemptID -RunID 'DIAG'
    $ups = @($baseline.PhysicalAdapters | Where-Object { $_.InitialStatus -ceq 'Up' })
    foreach ($a in $ups) { Disable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop }
    Start-Sleep -Seconds 3
    $isolationStarted = $true

    Write-Host '[DIAG] starting the Ubuntu guest by native VIX'
    Start-UbuntuVM $VmrunPath $UbuntuVmxPath
    Ensure-GuiEntries

    Write-Host '[DIAG] transferring the frozen helper, the diagnostic script and the sudo credential'
    Copy-ToUbuntuGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Official.sh') $guestHelper
    Copy-ToUbuntuGuest (Join-Path $PackageRoot 'diagnose_ubuntu_sample_prepare.sh') $guestDiag
    $null = New-UbuntuSudoCredentialFile $guestCred

    if (-not $SkipHelperRun) {
        Write-Host '[DIAG] running the FROZEN helper sample_prepare (staging only - it does NOT execute the sample)'
        $rc = Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper sample_prepare $AttemptID $guestRunRoot $SampleSha256 $SampleBytes $SampleGuestPath $ModeOctal $guestCred ubuntu $SampleRunId $FamilyStratum TEST A $SampleRunId-A R01-UBU-A RANSOMWARE MALICIOUS_PRIMARY_SUBJECT bpftrace+auditd tar.gz $RunID 21" 300
        $report.helper_exit_code = $rc
        Write-Host ('[DIAG] helper sample_prepare exit code = ' + $rc)
    }

    Write-Host '[DIAG] running the read-only diagnostic as root'
    $diagRc = Invoke-UbuntuGuestProgram '/bin/bash' "$guestDiag diagnostic $guestCred $guestRunRoot $guestReport $guestHelper $SampleGuestPath $SampleSha256 $SampleBytes $ModeOctal" 300
    $report.diagnostic_exit_code = $diagRc
    Write-Host ('[DIAG] diagnostic exit code = ' + $diagRc)

    Write-Host '[DIAG] retrieving the guest-side artefacts'
    $helperLog = Join-Path $OutDir 'guest_helper_sample_prepare.log'
    try {
        Copy-FromUbuntuGuest ($guestRunRoot + '/work/guest_helper_sample_prepare.log') $helperLog
        $report.helper_log_retrieved = (Test-Path -LiteralPath $helperLog -PathType Leaf)
        if ($report.helper_log_retrieved) { Write-Host ('[DIAG] retrieved the helper log: ' + $helperLog) }
    } catch { Write-Host ('[DIAG] the helper log could NOT be retrieved: ' + $_.Exception.Message) }
    $diagLog = Join-Path $OutDir 'diagnostic.log'
    try {
        Copy-FromUbuntuGuest ($guestRunRoot + '/work/diagnostic.log') $diagLog
        $report.diagnostic_log_retrieved = (Test-Path -LiteralPath $diagLog -PathType Leaf)
    } catch { Write-Host ('[DIAG] the diagnostic log could not be retrieved: ' + $_.Exception.Message) }
    $diagReport = Join-Path $OutDir 'diagnostic_report.txt'
    try {
        Copy-FromUbuntuGuest $guestReport $diagReport
        $report.diagnostic_report_retrieved = (Test-Path -LiteralPath $diagReport -PathType Leaf)
        if ($report.diagnostic_report_retrieved) { Write-Host ('[DIAG] retrieved the diagnostic report: ' + $diagReport) }
    } catch { Write-Host ('[DIAG] the diagnostic report could NOT be retrieved: ' + $_.Exception.Message) }
    try { Copy-FromUbuntuGuest ($guestRunRoot + '/evidence/sample_prepare_receipt.json') (Join-Path $OutDir 'sample_prepare_receipt.json') } catch {}
}
catch {
    $report.error = $_.Exception.Message
    Write-Host ('[DIAG] ERROR: ' + $_.Exception.Message) -ForegroundColor Red
}
finally {
    Write-Host '[DIAG] recovery: powering off, reverting to V11, restoring the host network'
    try { try { Stop-UbuntuVM $VmrunPath $UbuntuVmxPath } catch {} } catch {}
    try {
        Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $UbuntuSnapshot
        $report.guest_snapshot_after = (Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu')
        $report.baseline_reverted = ($report.guest_snapshot_after -ceq $UbuntuSnapshot)
    } catch { $report.revert_error = $_.Exception.Message }
    if ($isolationStarted) { try { $null = Restore-HostNetwork $baseline } catch { $report.restore_error = $_.Exception.Message } }
    try { Ensure-GuiEntries } catch {}
    try { Close-UbuntuVix } catch {}
    $report.ubuntu_off = (-not (Get-VmOn $VmrunPath $UbuntuVmxPath))
    $report.windows_off = (-not (Get-VmOn $VmrunPath $WindowsVmxPath))
    Write-Json (Join-Path $OutDir 'DIAGNOSTIC_RESULT.json') $report
    Write-Host ('[DIAG] output: ' + $OutDir)
    if ($report.diagnostic_report_retrieved) {
        Write-Host '--------------------- DIAGNOSTIC REPORT ---------------------'
        Get-Content (Join-Path $OutDir 'diagnostic_report.txt') | ForEach-Object { Write-Host $_ }
        Write-Host '-------------------------------------------------------'
    }
    if ($report.helper_log_retrieved) {
        Write-Host '--------------------- HELPER LOG ---------------------------'
        Get-Content (Join-Path $OutDir 'guest_helper_sample_prepare.log') | ForEach-Object { Write-Host $_ }
        Write-Host '-----------------------------------------------------------'
    }
}
