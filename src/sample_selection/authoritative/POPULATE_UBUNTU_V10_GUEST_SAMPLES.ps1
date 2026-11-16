<#
.SYNOPSIS
  Populate the Ubuntu V10 guest sample root with the 19 frozen artifacts.

.DESCRIPTION
  Prerequisite for FINALIZE_UBUNTU_V10_AFTER_19_MATERIALIZED.ps1.
  The finalizer assumes the samples are already inside Ubuntu; this step puts them there.

  Intended to run immediately after REVERT_UBUNTU_TO_R4_BASELINE.ps1, i.e. on a
  freshly reverted R4 baseline, so the materialization is a single clean pass
  with no repair history in the evidence trail.

  Frozen-set integrity is checked on the host (19/19 exact SHA-256), the guest
  TSV carries sha/family/role/rank/size so every file is verified by hash AND
  byte count before and after placement, the guest is fsync'd, and all 19 are
  re-verified once more after the flush. Zero-byte files must be 0.

  Sequence, fail-closed at every gate:
    1. host: frozen manifest + host intake re-verified (19/19 exact SHA-256)
    2. host: Ubuntu powered off, current snapshot == old frozen R4 snapshot
    3. guest: OLD R4 BASELINE COUNT == 10 (read-only, before any write)
    4. guest: create /opt/RansomLab/MalwareStaging/P5G/V10/Samples (root:root 700)
    5. guest: 19 files staged over Native VIX to /tmp, hash-verified, then moved in
    6. guest: re-verify 19/19 hashes in place, count 19, unexpected 0, unique 19
    7. guest: confirm old R4 baseline still 10 samples
    8. guest: clean removal of staging + credential file
    9. host: clean power-off
   10. host: receipt + evidence hashes

  Does NOT freeze final 000 permissions (the finalizer does that after its own verify).
  Does NOT create any snapshot. Does NOT execute any sample. Consumes no run slots.

.PARAMETER SkipHostAudit
  Skip the extra frozen-audit invocation and rely on the existing PASS receipt.

.EXAMPLE
  .\POPULATE_UBUNTU_V10_GUEST_SAMPLES.ps1
#>

[CmdletBinding()]
param(
    [string]$CampaignRoot = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs",
    [string]$VmrunPath = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    [string]$UbuntuVmxPath = "D:\Ubuntu 24.04\Ubuntu.vmx",
    [string]$OldSnapshot = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013",
    [switch]$SkipHostAudit
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptDir       = Join-Path $CampaignRoot "01_SHARED\scripts\host\sample_selection"
$Bridge          = Join-Path $CampaignRoot "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$FrozenManifest  = Join-Path $CampaignRoot "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110\UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"
$IntakeRoot      = Join-Path $CampaignRoot "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110\host_archive_intake_all19"
$AuditScript     = Join-Path $ScriptDir "AUDIT_UBUNTU_V10_HOST_INTAKE_19_SHA256_V1_1.ps1"
$AuditReceipt    = Join-Path $CampaignRoot "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110\evidence\UBUNTU_V10_HOST_INTAKE_19_SHA256_AUDIT_RECEIPT_V1_1.json"
$GuestHelperHost = Join-Path $ScriptDir "UBUNTU_V10_POPULATE_GUEST.sh"
$OutRoot         = Join-Path $CampaignRoot "01_SHARED\sample_selection\UBUNTU_V10_GUEST_POPULATION_20261110"

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function SHA([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Json([string]$Path, [object]$Object) {
    $d = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (($Object | ConvertTo-Json -Depth 20) + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Write-Step([string]$m) { Write-Host ""; Write-Host ("=== " + $m) -ForegroundColor Cyan }

function Get-CurrentSnapshotName([string]$Vmx) {
    $vmsd = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    Assert-True ($vmsd.Count -eq 1) "VMSD_NOT_UNIQUE"
    $cur = ''; $map = @{}
    foreach ($l in [IO.File]::ReadAllLines($vmsd[0].FullName)) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"')
        if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"')
        if ($m.Success) {
            $i = [int]$m.Groups[1].Value
            if (-not $map.ContainsKey($i)) { $map[$i] = @{} }
            $map[$i][$m.Groups[2].Value] = $m.Groups[3].Value
        }
    }
    Assert-True (-not [string]::IsNullOrWhiteSpace($cur)) "NO_CURRENT_SNAPSHOT"
    foreach ($i in $map.Keys) { if ([string]$map[$i]['uid'] -ceq $cur) { return [string]$map[$i]['displayName'] } }
    throw "SNAPSHOT_UID_UNMAPPED"
}

function Start-UbuntuVMWithRetry {
    param([string]$VmrunPath, [string]$UbuntuVmxPath, [int]$MaxAttempts = 3)
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try { Start-UbuntuVM $VmrunPath $UbuntuVmxPath; return }
        catch {
            $m = $_.Exception.Message
            if ($i -lt $MaxAttempts -and $m -match 'VIX ERROR CODE:\s*15') {
                Write-Host ("  start attempt {0} hit VIX 15 (VM file locked) - re-clearing the Workstation lock" -f $i) -ForegroundColor Yellow
                try { Close-UbuntuVix } catch { }
                try { Clear-UbuntuWorkstationLock -VmrunPath $VmrunPath -Vmx $UbuntuVmxPath | Out-Null } catch { }
                Start-Sleep -Seconds 10
                continue
            }
            throw
        }
    }
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'

foreach ($p in @($VmrunPath, $UbuntuVmxPath, $Bridge, $FrozenManifest, $GuestHelperHost, $IntakeRoot, $AuditScript)) {
    Assert-True (Test-Path -LiteralPath $p) ("REQUIRED_PATH_MISSING: " + $p)
}
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

Write-Step "1/9 Host frozen-set re-verification"
$manifestSha = SHA $FrozenManifest
$rows = @(Import-Csv -LiteralPath $FrozenManifest)
Assert-True ($rows.Count -eq 19) "FROZEN_MANIFEST_NOT_19"
$primary = @($rows | Where-Object { $_.role -ceq 'PRIMARY' })
$reserve = @($rows | Where-Object { $_.role -ceq 'RESERVE' })
Assert-True ($primary.Count -eq 10) "FROZEN_PRIMARY_NOT_10"
Assert-True ($reserve.Count -eq 9) "FROZEN_RESERVE_NOT_9"
Write-Host ("frozen manifest : {0}" -f $manifestSha)
Write-Host ("rows            : 19 (10 PRIMARY / 9 RESERVE)")

# Every expected hash must exist on the host with the exact bytes
$intakeHashes = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $IntakeRoot -File -Recurse)) { $intakeHashes[(SHA $f.FullName)] = $f.FullName }
$missing = 0
foreach ($r in $rows) {
    $h = ([string]$r.sha256).Trim().ToLowerInvariant()
    if (-not $intakeHashes.ContainsKey($h)) { Write-Host ("MISSING ON HOST: rank {0} {1}" -f $r.frozen_rank, $r.family) -ForegroundColor Red; $missing++ }
}
Assert-True ($missing -eq 0) ("HOST_INTAKE_INCOMPLETE: missing=" + $missing)
Write-Host ("host intake     : 19/19 exact present, 0 missing")

if (-not $SkipHostAudit) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $AuditScript | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) "FROZEN_HOST_AUDIT_NOT_PASS_EXACT_19_READY"
    Write-Host "frozen host audit: PASS_EXACT_19_READY"
}
elseif (Test-Path -LiteralPath $AuditReceipt) {
    $rc = Get-Content -LiteralPath $AuditReceipt -Raw | ConvertFrom-Json
    Assert-True ([string]$rc.status -ceq 'PASS_EXACT_19_READY') "EXISTING_AUDIT_RECEIPT_NOT_PASS"
    Write-Host ("frozen host audit: {0} (existing receipt {1})" -f $rc.status, $rc.timestamp_utc)
}

Write-Step "2/9 VM power state + snapshot binding"
& $VmrunPath -T ws list | Out-Null
$running = @(& $VmrunPath -T ws list 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' })
Assert-True ($running.Count -eq 0) ("OTHER_VM_RUNNING: " + ($running -join '; '))
$current = Get-CurrentSnapshotName $UbuntuVmxPath
Assert-True ($current -ceq $OldSnapshot) ("SNAPSHOT_DRIFT expected=" + $OldSnapshot + " actual=" + $current)
$snapBefore = @(& $VmrunPath -T ws listSnapshots $UbuntuVmxPath 2>&1 | ForEach-Object { ([string]$_).Trim() })
$snapNamesBefore = @($snapBefore | Where-Object { $_ -notmatch '^Total snapshots:' -and -not [string]::IsNullOrWhiteSpace($_) })
# vmrun prints "Total snapshots: N" then one line per snapshot. A snapshot
# genuinely named "list" exists on this host (uid 13) and must be counted.
$snapHeader = @($snapBefore | Where-Object { $_ -match '^Total snapshots:\s*\d+' })
Assert-True ($snapHeader.Count -eq 1) ("SNAPSHOT_HEADER_UNEXPECTED: " + ($snapBefore -join ' | '))
Assert-True ($snapNamesBefore.Count -eq [int]([regex]::Match($snapHeader[0], '\d+').Value)) "SNAPSHOT_LIST_INCONSISTENT"
Assert-True ($snapNamesBefore.Count -eq 7) ("SNAPSHOT_COUNT_NOT_7: " + $snapNamesBefore.Count)
Assert-True (@($snapNamesBefore | Where-Object { $_ -ceq $OldSnapshot }).Count -eq 1) "OLD_R4_SNAPSHOT_MISSING"
Write-Host ("ubuntu powered  : OFF")
Write-Host ("current snapshot: " + $current)
Write-Host ("snapshots       : " + $snapNamesBefore.Count + " entries (old R4 present)")

# Expected-hash TSV for the guest: sha \t family \t role \t rank \t size
# The size column lets the guest verify hash AND byte count, which is what
# catches the ext4 delayed-allocation zero-byte failure (a 0-byte file keeps
# its name but not its length, and a stale sha entry would otherwise be the
# only evidence).
# LF-only: the guest reads this with IFS=$'\t' read; CRLF would leave a \r on
# the size field and break the numeric comparison.
$expectHost = Join-Path $OutRoot "UBUNTU_V10_EXPECTED_SHA256.tsv"
$lines = New-Object System.Collections.Generic.List[string]
$expectedSizeTotal = [int64]0
foreach ($r in ($rows | Sort-Object { [int]$_.frozen_rank })) {
    $sha = ([string]$r.sha256).Trim().ToLowerInvariant()
    $family = ([string]$r.family).Trim()
    Assert-True ($sha -match '^[0-9a-f]{64}$') ("INVALID_SHA: " + $sha)
    Assert-True ($family -notmatch "`t|`r|`n") "UNSAFE_FAMILY_TEXT"
    $sizeText = ([string]$r.file_size_bytes).Trim()
    Assert-True ($sizeText -match '^\d+$') ("INVALID_FILE_SIZE: " + $sizeText + " rank " + $r.frozen_rank)
    $size = [int64]$sizeText
    Assert-True ($size -gt 0) ("NON_POSITIVE_FILE_SIZE: " + $sizeText + " rank " + $r.frozen_rank)
    $expectedSizeTotal += $size
    $lines.Add(("{0}`t{1}`t{2}`t{3}`t{4}" -f $sha, $family, ([string]$r.role).Trim(), ([string]$r.frozen_rank).Trim(), $sizeText))
}
Assert-True ($lines.Count -eq 19) ("EXPECTED_TSV_NOT_19_ROWS: " + $lines.Count)
[IO.File]::WriteAllText($expectHost, (($lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Assert-True (((Get-Content -LiteralPath $expectHost -Raw) -match "`r") -eq $false) "EXPECTED_TSV_IS_NOT_LF_ONLY"
Write-Host ("expected bytes  : " + $expectedSizeTotal.ToString("N0") + " across 19 rows (5-column LF-only TSV)")

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$attempt = [guid]::NewGuid().ToString('N').Substring(0, 12)
$guestStage   = "/tmp/V10_POP_$attempt"
$guestHelper  = "/tmp/UBUNTU_V10_POPULATE_GUEST_$attempt.sh"
$guestExpect  = "/tmp/UBUNTU_V10_EXPECTED_SHA256_$attempt.tsv"
$guestCred    = "/tmp/UBUNTU_V10_POPULATE_$attempt.sudo"
$guestResult  = "/tmp/UBUNTU_V10_POPULATE_RESULT_$attempt.txt"
$hostResult   = Join-Path $OutRoot ("UBUNTU_V10_POPULATION_RESULT_{0}.txt" -f $stamp)

# Workstation GUI + stale-lock guard (shared with the repair and finalize steps).
. (Join-Path $ScriptDir 'UbuntuWorkstationLockGuard.ps1')
$lockInfo = Clear-UbuntuWorkstationLock -VmrunPath $VmrunPath -Vmx $UbuntuVmxPath

. $Bridge

try {
    Write-Step "3/9 Boot Ubuntu via Native-VIX (no other VM running)"
    Start-UbuntuVMWithRetry $VmrunPath $UbuntuVmxPath
    Write-Host "ubuntu          : powered ON, guest tools ready, logged in"

    Write-Step "4/9 Stage 19 artifacts + helper + manifest + credential in /tmp"
    $mk = Invoke-UbuntuGuestProgram "/bin/mkdir" ("-p -m 700 " + $guestStage) 120
    Assert-True ($mk -eq 0) ("GUEST_STAGE_DIR_CREATE_FAILED: exit " + $mk)

    $copied = 0
    foreach ($r in ($rows | Sort-Object { [int]$_.frozen_rank })) {
        $sha = ([string]$r.sha256).Trim().ToLowerInvariant()
        $src = $intakeHashes[$sha]
        Assert-True (-not [string]::IsNullOrWhiteSpace($src)) ("HOST_SOURCE_MISSING: " + $sha)
        Copy-ToUbuntuGuest $src ($guestStage + "/" + $sha + ".sample")
        $copied++
        Write-Host ("  copied {0,2}/19  {1}  {2}" -f $copied, $r.family, $sha.Substring(0, 16))
    }
    Assert-True ($copied -eq 19) "HOST_TO_GUEST_COPY_INCOMPLETE"

    Copy-ToUbuntuGuest $GuestHelperHost $guestHelper
    Copy-ToUbuntuGuest $expectHost $guestExpect
    New-UbuntuSudoCredentialFile $guestCred | Out-Null
    Write-Host "helper/manifest/credential transferred"

    Write-Step "5/9 Guest: preserve R4, create V10 root, place and verify 19 files"
    $args = "$guestHelper --cred=$guestCred --manifest=$guestExpect --stage=$guestStage --out=$guestResult"
    Write-Host ("  guest command: /bin/bash " + $args)
    $exit = Invoke-UbuntuGuestProgram "/bin/bash" $args 900
    Write-Host ("  guest helper exit code: " + $exit)
    $haveResult = $false
    try { Copy-FromUbuntuGuest $guestResult $hostResult 180; $haveResult = $true } catch { }
    if (-not $haveResult) { throw ("GUEST_HELPER_PRODUCED_NO_RESULT: exit=" + $exit + " missing=" + $guestResult) }
    $text = Get-Content -LiteralPath $hostResult -Raw
    Write-Host ""
    $text.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Host ("  " + $_) }

    Assert-True ($exit -eq 0) ("GUEST_POPULATION_EXIT_" + $exit)
    Assert-True ($text -match 'OLD_R4_SAMPLE_COUNT=10') "OLD_R4_BASELINE_NOT_10"
    Assert-True ($text -match 'STATUS=PASS_19_POPULATED_GUEST_HASH_VERIFIED') "GUEST_POPULATION_NOT_PASS"
    Assert-True ($text -match 'STAGE_PASS_COUNT=19') "GUEST_STAGE_PASS_NOT_19"
    Assert-True ($text -match 'STAGE_FAIL_COUNT=0') "GUEST_STAGE_FAIL_NONZERO"
    Assert-True ($text -match 'STAGE_MISS_COUNT=0') "GUEST_STAGE_MISSING_FILES"
    Assert-True ($text -match 'HASH_PASS=19') "GUEST_HASH_PASS_NOT_19"
    Assert-True ($text -match 'HASH_FAIL=0') "GUEST_HASH_FAIL_NONZERO"
    Assert-True ($text -match 'V10_SAMPLE_COUNT=19') "GUEST_V10_COUNT_NOT_19"
    Assert-True ($text -match 'V10_UNEXPECTED_ENTRIES=0') "GUEST_V10_UNEXPECTED_ENTRIES"
    Assert-True ($text -match 'V10_UNIQUE_HASHES=19') "GUEST_V10_DUPLICATE_HASHES"
    Assert-True ($text -match 'V10_ZERO_BYTE_SAMPLES=0') "GUEST_V10_ZERO_BYTE_SAMPLES"
    Assert-True ($text -match 'GUEST_SYNC=DONE') "GUEST_SYNC_NOT_CONFIRMED"
    Assert-True ($text -match 'POST_SYNC_HASH_PASS=19') "GUEST_POST_SYNC_PASS_NOT_19"
    Assert-True ($text -match 'POST_SYNC_HASH_FAIL=0') "GUEST_POST_SYNC_FAIL_NONZERO"
    Assert-True ($text -match 'OLD_R4_SAMPLE_COUNT_AFTER=10') "OLD_R4_CHANGED_DURING_POPULATION"

    Write-Step "6/9 Cleanup guest staging + credential"
    try {
        $cleanup = "-rf " + $guestStage + " " + $guestCred + " " + $guestExpect + " " + $guestHelper + " " + $guestResult
        Invoke-UbuntuGuestProgram "/bin/rm" $cleanup 120 | Out-Null
    }
    catch { Write-Host ("cleanup warning: " + $_.Exception.Message) -ForegroundColor Yellow }

    Write-Step "7/9 Clean power-off (no snapshot created in this step)"
    # Flush the guest page cache first: a hard power-off can otherwise leave the
    # most recently written files at 0 bytes (ext4 delayed allocation).
    try { Invoke-UbuntuGuestProgram "/bin/sync" "" 120 | Out-Null } catch { }
    Start-Sleep -Seconds 2
    Stop-UbuntuVM $VmrunPath $UbuntuVmxPath
}
catch {
    $err = $_
    Write-Host ""
    Write-Host ("FAILURE: " + $err.Exception.Message) -ForegroundColor Red
    Write-Host "Recovering: power off and revert Ubuntu to the frozen snapshot (no snapshot will be created)..." -ForegroundColor Yellow

    try { Invoke-UbuntuGuestProgram "/bin/sync" "" 120 | Out-Null } catch { }
    try { Stop-UbuntuVM $VmrunPath $UbuntuVmxPath; Write-Host "ubuntu          : OFF (recovered after failure)" -ForegroundColor Yellow }
    catch { Write-Host ("power-off after failure FAILED: " + $_.Exception.Message) -ForegroundColor Red }

    try {
        Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $OldSnapshot
        $curFail = Get-CurrentSnapshotName $UbuntuVmxPath
        Write-Host ("ubuntu          : REVERTED to " + $curFail + " (clean frozen state)") -ForegroundColor Yellow
    }
    catch {
        Write-Host ("REVERT AFTER FAILURE FAILED: " + $_.Exception.Message) -ForegroundColor Red
        Write-Host ("MANUAL ACTION REQUIRED: revert Ubuntu to " + $OldSnapshot) -ForegroundColor Red
    }

    try { Close-UbuntuVix } catch { }
    throw $err
}
finally {
    try { Close-UbuntuVix } catch { }
}

Start-Sleep -Seconds 3
Assert-True (-not ($running = @(& $VmrunPath -T ws list 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' }))) "UBUNTU_STILL_RUNNING"
$snapAfter = @(& $VmrunPath -T ws listSnapshots $UbuntuVmxPath 2>&1 | ForEach-Object { ([string]$_).Trim() })
$snapNamesAfter = @($snapAfter | Where-Object { $_ -notmatch '^Total snapshots:' -and -not [string]::IsNullOrWhiteSpace($_) })
$newSnapName = 'P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110'
$newSnapExists = @($snapNamesAfter | Where-Object { $_ -ceq $newSnapName }).Count -gt 0
Assert-True (-not $newSnapExists) "SNAPSHOT_CREATED_IN_POPULATION_STEP_NOT_EXPECTED"
Assert-True ($snapNamesAfter.Count -eq 7) ("SNAPSHOT_COUNT_CHANGED: " + $snapNamesAfter.Count)
foreach ($n in $snapNamesBefore) {
    Assert-True (@($snapNamesAfter | Where-Object { $_ -ceq $n }).Count -eq 1) ("SNAPSHOT_LOST: " + $n)
}
$currentAfter = Get-CurrentSnapshotName $UbuntuVmxPath
Assert-True ($currentAfter -ceq $OldSnapshot) ("CURRENT_SNAPSHOT_DRIFT_AFTER_POPULATION: " + $currentAfter)
Write-Host ("ubuntu          : OFF")
Write-Host ("current snapshot: " + $currentAfter + " (unchanged)")
Write-Host "new V10 snapshot: NOT created (correct for this step)"

Write-Step "8/9 Receipt + evidence hashes"
$receipt = [ordered]@{
    schema_version = "1.0"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = "PASS_19_POPULATED_IN_UBUNTU_PENDING_PERMISSION_FREEZE"
    frozen_manifest_path = $FrozenManifest
    frozen_manifest_sha256 = $manifestSha
    host_intake_root = $IntakeRoot
    expected_hash_tsv_sha256 = (SHA $expectHost)
    guest_populate_helper_sha256 = (SHA $GuestHelperHost)
    native_vix_bridge_sha256 = (SHA $Bridge)
    guest_v10_root = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    guest_r4_root = "/opt/RansomLab/MalwareStaging/P5G/R4/Samples"
    old_r4_sample_count_before = 10
    old_r4_sample_count_after = 10
    expected_hash_tsv_columns = "sha256,family,role,rank,size"
    expected_bytes_total = $expectedSizeTotal
    guest_hash_pass = 19
    guest_hash_fail = 0
    guest_sample_count = 19
    guest_duplicate_hashes = 0
    guest_unexpected_entries = 0
    guest_zero_byte_samples = 0
    guest_post_sync_hash_pass = 19
    guest_post_sync_hash_fail = 0
    guest_sync_before_power_off = $true
    snapshot_count_before = $snapNamesBefore.Count
    snapshot_count_after = $snapNamesAfter.Count
    permissions_now = "files 600 root:root, dir 700 root:root (000 freeze deferred to finalizer)"
    snapshot_created = $false
    ubuntu_powered_off_after = $true
    current_snapshot_after = $currentAfter
    malware_executed = $false
    official_run_slot_consumed = $false
    guest_result_report = $hostResult
}
$receiptPath = Join-Path $OutRoot ("UBUNTU_V10_GUEST_POPULATION_RECEIPT_{0}_{1}.json" -f $stamp, $attempt)
Write-Json $receiptPath $receipt

$hashRows = foreach ($p in @($FrozenManifest, $expectHost, $GuestHelperHost, $hostResult, $receiptPath)) {
    [pscustomobject]@{ file = $p; bytes = (Get-Item -LiteralPath $p).Length; sha256 = (SHA $p) }
}
$hashCsv = Join-Path $OutRoot ("UBUNTU_V10_GUEST_POPULATION_EVIDENCE_SHA256_{0}.csv" -f $stamp)
$hashRows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8

Write-Step "9/9 Result"
Write-Host "GUEST POPULATION: PASS" -ForegroundColor Green
Write-Host "19/19 frozen artifacts now present in Ubuntu V10 sample root and hash-verified."
Write-Host "Old R4 baseline preserved (10 samples, unchanged)."
Write-Host "Ubuntu powered off; no snapshot created."
Write-Host ""
Write-Host ("Receipt : " + $receiptPath)
Write-Host ("Evidence: " + $hashCsv)
Write-Host ""
Write-Host "NEXT: run FINALIZE_UBUNTU_V10_AFTER_19_MATERIALIZED.ps1 to freeze permissions,"
Write-Host "      power off, create P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110,"
Write-Host "      and measure the actual D: snapshot delta."
exit 0
