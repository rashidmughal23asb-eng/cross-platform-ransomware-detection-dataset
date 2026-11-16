# ERROR: this file is a TEMPLATE written by the host script's own steps; edit the host script instead.
# ---------------------------------------------------------------------------
# UBUNTU V11 FINALIZATION - the host driver (D-109).
#
# The FINAL MATERIALISATION of the frozen family set of ten qualified distinct
# Ubuntu families into the guest, followed by the NEW OFFLINE (powered-off)
# snapshot - the same strategy as the V10 finalisation:
#   1. the guest is brought up, the three new V11 samples are installed at their
#      canonical staging path (root:root, mode 000) and their hashes verified;
#   2. the whole frozen family set (ten families across the V10 and V11 staging
#      roots) is verified inside the guest: SHA-256, byte count, owner and mode,
#      plus the preservation proof of the campaign's original R4 root;
#   3. the guest is CLEANLY POWERED OFF;
#   4. the snapshot is created with the VM OFF, so no guest memory state is
#      stored (hundreds of MB rather than many GB);
#   5. the exact D: storage delta is measured and recorded.
#
# 0 official campaign slots. The snapshot is created offline on purpose.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
$ScriptDir = Join-Path $Root "01_SHARED\scripts\host\sample_selection"
$QualScripts = Join-Path $Root "01_SHARED\scripts\host\qualification"
$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$UbuntuVmx = "D:\Ubuntu 24.04\Ubuntu.vmx"

$Bridge = Join-Path $Root "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$FamilySetManifest = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv"
$GuestHelperHost = Join-Path $ScriptDir "UBUNTU_V11_FINALIZE_GUEST.sh"
$GuestExpectedHost = Join-Path $ScriptDir "UBUNTU_V11_EXPECTED_SHA256.tsv"
$InstallHelperHost = Join-Path $QualScripts "QUAL_UBUNTU_SAMPLE_INSTALL.sh"
$IntakeRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_EXTENSION_INTAKE_20261111\host_archive_intake_all3"

$GuestHelper = "/tmp/UBUNTU_V11_FINALIZE_GUEST.sh"
$GuestExpected = "/tmp/UBUNTU_V11_EXPECTED_SHA256.tsv"
$GuestResult = "/tmp/UBUNTU_V11_FINALIZE_RESULT.txt"
$GuestCred = "/tmp/UBUNTU_V11_FINALIZE.sudo"
$GuestInstallHelper = "/tmp/QUAL_UBUNTU_SAMPLE_INSTALL.sh"

$OldSnapshot = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"
$NewSnapshot = "P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112"

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V11_POST_MATERIALIZATION_FINALIZE_20261112"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

function Get-DriveFreeGiB([string]$DeviceId){
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'"
    if(-not $d){ throw "Drive not found: $DeviceId" }
    return [math]::Round($d.FreeSpace / 1GB, 3)
}

# D-111: Windows MAX_PATH is 260 characters. Every host path this script WRITES is checked
# before it is used, so an over-long path fails fast with a precise message instead of
# surfacing later as a VIX copy error (the 2026-11-12 attempt) or a silent write failure.
function Assert-MaxPath([string]$Path,[string]$Label){
    if($Path.Length -gt 259){ throw ("MAX_PATH_OVERFLOW:{0}: {1} characters (the Windows limit is 260) - {2}" -f $Label,$Path.Length,$Path) }
}

function Get-RunningVmx {
    $out = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
    if($LASTEXITCODE -ne 0){ throw "VMRUN_LIST_FAILED" }
    return @(
        $out |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' }
    )
}

foreach($p in @($Vmrun,$UbuntuVmx,$Bridge,$FamilySetManifest,$GuestHelperHost,$InstallHelperHost)){
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){
        throw "Required file missing: $p"
    }
}

# ---------------------------------------------------------------------------
# 1. The frozen family set: 10 rows, and the expected-hash TSV for the guest.
# ---------------------------------------------------------------------------
$rows = @(Import-Csv -LiteralPath $FamilySetManifest)
if($rows.Count -ne 10){ throw "Frozen family set row count is not 10." }

$lines = New-Object System.Collections.Generic.List[string]
$toInstall = New-Object System.Collections.Generic.List[object]
foreach($r in ($rows | Sort-Object {[int]$_.frozen_rank})){
    $sha = ([string]$r.sha256).Trim().ToLowerInvariant()
    $family = ([string]$r.family).Trim()
    $root = ([string]$r.guest_staging_root).Trim()
    $bytes = ([string]$r.file_size_bytes).Trim()

    if($sha -notmatch '^[0-9a-f]{64}$'){ throw "Invalid frozen SHA-256: $sha" }
    if($family -match "`t|`r|`n"){ throw "Unsafe family text in the frozen family set." }
    if($root -notmatch '^/opt/RansomLab/MalwareStaging/P5G/V1[01]/Samples$'){ throw "Unexpected staging root: $root" }
    if($bytes -notmatch '^[0-9]+$'){ throw "Invalid byte count: $bytes" }
    $lines.Add("$sha`t$family`t$root`t$bytes")

    # the three V11 samples are not in the guest yet and must be materialised
    if($root -like '*/V11/Samples'){
        $hostFile = Join-Path $IntakeRoot ("$sha.sample")
        if(-not(Test-Path -LiteralPath $hostFile -PathType Leaf)){
            throw "Host archive copy missing for the materialisation: $hostFile"
        }
        $hostSha = (Get-FileHash -LiteralPath $hostFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hostSha -ne $sha){ throw "Host archive copy hash mismatch: $hostFile" }
        $toInstall.Add([pscustomobject]@{ sha=$sha; family=$family; bytes=$bytes; host=$hostFile; dest="$root/$sha.sample" })
    }
}
if($toInstall.Count -ne 3){ throw "Expected exactly 3 samples to materialise, found $($toInstall.Count)." }

# D-112: LF endings. WriteAllLines would write CRLF on Windows, and the trailing CR
# would ride on the LAST field of every row in the guest.
[IO.File]::WriteAllText($GuestExpectedHost, (($lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))

$manifestHash = (Get-FileHash $FamilySetManifest -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = (Get-FileHash $GuestExpectedHost -Algorithm SHA256).Hash.ToLowerInvariant()
$bridgeHash = (Get-FileHash $Bridge -Algorithm SHA256).Hash.ToLowerInvariant()
$helperHash = (Get-FileHash $GuestHelperHost -Algorithm SHA256).Hash.ToLowerInvariant()
$installHash = (Get-FileHash $InstallHelperHost -Algorithm SHA256).Hash.ToLowerInvariant()

# ---------------------------------------------------------------------------
# 2. Snapshot pre-state: the old snapshot must exist, the new one must not.
# ---------------------------------------------------------------------------
$snapshotsBefore = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list Ubuntu snapshots." }
$snapTextBefore = ($snapshotsBefore -join "`n")

$oldPresentBefore = $snapTextBefore -match [regex]::Escape($OldSnapshot)
$newPresentBefore = $snapTextBefore -match [regex]::Escape($NewSnapshot)

if(-not $oldPresentBefore){ throw "Old frozen snapshot missing; stop." }
if($newPresentBefore){ throw "New V11 snapshot already exists; refusing duplicate/ambiguous creation." }

# the V10 baseline snapshot is the one the guest currently sits on
$vmsd = @(Get-ChildItem (Split-Path -Parent $UbuntuVmx) -Filter '*.vmsd' -File)
if($vmsd.Count -ne 1){ throw "Expected exactly one .vmsd for the Ubuntu VM." }
$cur = ''
$map = @{}
foreach($l in [IO.File]::ReadAllLines($vmsd[0].FullName)){
    $m = [regex]::Match($l,'^\s*snapshot\.current\s*=\s*"([^"]*)"'); if($m.Success){ $cur = $m.Groups[1].Value }
    $m = [regex]::Match($l,'^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"')
    if($m.Success){ $i = [int]$m.Groups[1].Value; if(-not $map.ContainsKey($i)){ $map[$i] = @{} }; $map[$i][$m.Groups[2].Value] = $m.Groups[3].Value }
}
$currentName = ''
foreach($i in $map.Keys){ if([string]$map[$i]['uid'] -ceq $cur){ $currentName = [string]$map[$i]['displayName'] } }
if($currentName -cne $OldSnapshot){ throw "The guest is not on the frozen V10 baseline (current: $currentName)." }

$dBeforeVerify = Get-DriveFreeGiB "D:"
# The finalisation boots the guest WITHOUT the pilot's memory mode (mainMem.useNamedFile=FALSE),
# so VMware creates an 8 GiB .vmem on D: for the run - it is released at the clean power-off, and
# the offline snapshot then costs only its own delta. The guard therefore requires the room for
# that .vmem plus the pilot's 2.5 GiB disk reserve.
$vmemGiB = 8.0
$requiredGiB = $vmemGiB + 2.5
if($dBeforeVerify -lt $requiredGiB){ throw ("D: free space is {0} GiB; the guest boot needs {1} GiB for its .vmem plus the 2.5 GiB disk reserve, so at least {2} GiB are required. Stop any running VM (its .vmem is released on power-off) and free space, then re-run." -f $dBeforeVerify, $vmemGiB, $requiredGiB) }

# ---------------------------------------------------------------------------
# 3. Ubuntu must be the only running VM.
# ---------------------------------------------------------------------------
$running = @(Get-RunningVmx)
$others = @($running | Where-Object { $_ -cne $UbuntuVmx })
if($others.Count -gt 0){ throw "Another VM is running: $($others -join '; ')" }

. (Join-Path $ScriptDir 'UbuntuWorkstationLockGuard.ps1')
$lockInfo = Clear-UbuntuWorkstationLock -VmrunPath $Vmrun -Vmx $UbuntuVmx

. $Bridge

$HostResult = Join-Path $OutRoot "UBUNTU_V11_FINALIZE_RESULT.txt"
Assert-MaxPath $HostResult "guest verification report"

$finalizeOk = $false
try {
    Write-Host "Stage 1/8: establish qualified Native-VIX Ubuntu session..."
    Start-UbuntuVM $Vmrun $UbuntuVmx

    Write-Host "Stage 2/8: transfer the verification helper, the frozen expected-hash manifest and the install helper..."
    Copy-ToUbuntuGuest $GuestHelperHost $GuestHelper
    Copy-ToUbuntuGuest $GuestExpectedHost $GuestExpected
    Copy-ToUbuntuGuest $InstallHelperHost $GuestInstallHelper
    New-UbuntuSudoCredentialFile $GuestCred | Out-Null

    Write-Host "Stage 3/8: materialise the three new V11 samples at the canonical staging path (root:root, mode 000)..."
    foreach($s in $toInstall){
        $tmp = "/tmp/UBUNTU_V11_MATERIALIZE_$($s.sha).sample"
        $receipt = "/tmp/UBUNTU_V11_INSTALL_$($s.sha).json"
        # D-111: the host-side receipt name is SHORT on purpose. With the full 64-hex SHA-256
        # the path was 262 characters - past the Windows MAX_PATH of 260 - and the copy out of
        # the guest failed with "COPY GUEST TO HOST WAIT VIX ERROR CODE: 22". (The same class
        # of defect was hit once before, in D-054, with the controller-log paths.)
        $receiptName = "INSTALL_R_{0}.json" -f $s.sha.Substring(0,16)
        $receiptPath = Join-Path $OutRoot $receiptName
        Assert-MaxPath $receiptPath ("install receipt:" + $s.family)
        Copy-ToUbuntuGuest $s.host $tmp
        $args = "$GuestInstallHelper $tmp $($s.dest) $($s.sha) $($s.bytes) $GuestCred $receipt"
        $exit = Invoke-UbuntuGuestProgram "/bin/bash" $args 300
        if($exit -ne 0){ throw "Materialisation of $($s.family) failed with exit code $exit." }
        Copy-FromUbuntuGuest $receipt $receiptPath 120
        $ir = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if([string]$ir.status -cne 'PASS'){ throw "Materialisation receipt for $($s.family) is not PASS." }
        if([string]$ir.installed_sha256 -cne $s.sha){ throw "Materialisation receipt hash mismatch for $($s.family)." }
        if([string]$ir.installed_mode -cne '0'){ throw "Materialisation mode for $($s.family) is not 000." }
        if([string]$ir.installed_owner -cne 'root:root'){ throw "Materialisation owner for $($s.family) is not root:root." }
        Write-Host ("  materialised {0} -> {1} (mode 000, root:root, sha verified)" -f $s.family, $s.dest)
    }

    Write-Host "Stage 4/8: verify the ten qualified families and the permission freeze in the guest..."
    $args = "$GuestHelper --cred=$GuestCred --manifest=$GuestExpected"
    $exit = Invoke-UbuntuGuestProgram "/bin/bash" $args 600
    # D-112: copy the guest verification report back BEFORE the exit-code check, so the
    # per-family diagnostic survives a failed verification (the 2026-11-12 attempt lost it).
    try { Copy-FromUbuntuGuest $GuestResult $HostResult 180 } catch { Write-Host ("WARN: the guest verification report could not be copied back: " + $_.Exception.Message) -ForegroundColor Yellow }
    if($exit -ne 0){ throw "V11 finalization guest helper exited with code $exit (the guest report, if copied, is at $HostResult)." }
    $guestText = Get-Content -LiteralPath $HostResult -Raw

    if($guestText -notmatch 'STATUS=PASS_ALL_10_QUALIFIED_FAMILIES_VERIFIED_AND_PERMISSION_FROZEN'){ throw "The ten qualified families did not verify in the guest." }
    if($guestText -notmatch 'FAMILY_COUNT=10'){ throw "Expected FAMILY_COUNT=10 proof missing." }
    if($guestText -notmatch 'FAMILY_PASS=10'){ throw "Expected FAMILY_PASS=10 proof missing." }
    if($guestText -notmatch 'FAMILY_FAIL=0'){ throw "Expected FAMILY_FAIL=0 proof missing." }
    if($guestText -notmatch 'OLD_R4_SAMPLE_COUNT=10'){ throw "Old R4 10-sample preservation proof failed." }

    Write-Host "Stage 5/8: remove the temporary verification artefacts..."
    try {
        Invoke-UbuntuGuestProgram "/bin/rm" "-f $GuestHelper $GuestExpected $GuestResult $GuestCred $GuestInstallHelper" 60 | Out-Null
    } catch {}

    Write-Host "Stage 6/8: clean power-off before the snapshot..."
    try { Invoke-UbuntuGuestProgram "/bin/sync" "" 120 | Out-Null } catch {}
    Start-Sleep -Seconds 2
    Stop-UbuntuVM $Vmrun $UbuntuVmx
    $finalizeOk = $true
}
finally {
    try { Close-UbuntuVix } catch {}
    # D-110: a failed finalisation must NEVER leave the guest running or modified. The
    # 2026-11-12 first attempt failed after the guest was powered on and left it running
    # (with its 8 GiB .vmem on D:, which also consumed the host's disk budget and made the
    # next attempt's disk guard fire). On any failure the guest is stopped and reverted to
    # the frozen baseline here, so the host and the guest are left exactly as they were.
    if(-not $finalizeOk){
        Write-Host "Finalisation did not complete: stopping Ubuntu and reverting to the frozen baseline..." -ForegroundColor Yellow
        try { Stop-UbuntuVM $Vmrun $UbuntuVmx } catch {}
        try { Revert-UbuntuExactSnapshot $Vmrun $UbuntuVmx $OldSnapshot } catch { Write-Host ("REVERT WARNING: " + $_.Exception.Message) -ForegroundColor Yellow }
    }
}

Start-Sleep -Seconds 5

if((Get-RunningVmx) -contains $UbuntuVmx){ throw "Ubuntu still running before the snapshot." }

$dBeforeSnapshot = Get-DriveFreeGiB "D:"

# ---------------------------------------------------------------------------
# 4. The OFFLINE snapshot: the VM is powered off, so no guest RAM state is
#    stored (hundreds of MB rather than many GB).
# ---------------------------------------------------------------------------
Write-Host "Stage 7/8: create the new OFFLINE (powered-off) V11 snapshot..."
& $Vmrun -T ws snapshot $UbuntuVmx $NewSnapshot 2>&1 | ForEach-Object { Write-Host $_ }
if($LASTEXITCODE -ne 0){ throw "V11 snapshot creation failed." }

Start-Sleep -Seconds 3

$snapshotsAfter = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list snapshots after creation." }
$snapTextAfter = ($snapshotsAfter -join "`n")

$oldPresentAfter = $snapTextAfter -match [regex]::Escape($OldSnapshot)
$newPresentAfter = $snapTextAfter -match [regex]::Escape($NewSnapshot)

if(-not $oldPresentAfter){ throw "Old snapshot disappeared after the V11 snapshot creation." }
if(-not $newPresentAfter){ throw "New V11 snapshot not visible after creation." }

$dAfterSnapshot = Get-DriveFreeGiB "D:"
$snapshotDeltaGiB = [math]::Round($dBeforeSnapshot - $dAfterSnapshot,3)
$snapshotDeltaMiB = [math]::Round(($dBeforeSnapshot - $dAfterSnapshot)*1024,1)

# ---------------------------------------------------------------------------
# 5. The receipt.
# ---------------------------------------------------------------------------
Write-Host "Stage 8/8: write the V11 post-materialization snapshot receipt..."

$receipt = [ordered]@{
    schema_version = "1.0"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    status = "PASS_V11_10_QUALIFIED_FAMILIES_MATERIALISED_NEW_OFFLINE_SNAPSHOT_CREATED"

    frozen_family_set_manifest_path = $FamilySetManifest
    frozen_family_set_manifest_sha256 = $manifestHash
    expected_hash_tsv_sha256 = $expectedHash
    native_vix_bridge_sha256 = $bridgeHash
    guest_helper_sha256 = $helperHash
    install_helper_sha256 = $installHash

    frozen_family_set_count = 10
    samples_materialised_this_step = $toInstall.Count
    exact_sha256_verified = 10
    sha256_failures = 0
    materialised_families = @($toInstall | ForEach-Object { $_.family })
    materialised_paths = @($toInstall | ForEach-Object { $_.dest })
    materialisation_mode = "000"
    materialisation_owner = "root:root"

    old_r4_sample_count_preserved = 10
    old_snapshot = $OldSnapshot
    old_snapshot_present_before = $oldPresentBefore
    old_snapshot_present_after = $oldPresentAfter

    v10_guest_root = "/opt/RansomLab/MalwareStaging/P5G/V10/Samples"
    v11_guest_root = "/opt/RansomLab/MalwareStaging/P5G/V11/Samples"

    new_snapshot = $NewSnapshot
    new_snapshot_present_before = $newPresentBefore
    new_snapshot_present_after = $newPresentAfter
    snapshot_created_while_vm_off = $true
    guest_memory_snapshot_requested = $false
    snapshot_strategy = "OFFLINE (powered-off) snapshot - the same strategy as the V10 finalisation, so only the changed disk blocks are stored (hundreds of MB rather than many GB)"

    d_free_gib_before_verification = $dBeforeVerify
    d_free_gib_before_snapshot = $dBeforeSnapshot
    d_free_gib_after_snapshot = $dAfterSnapshot
    observed_snapshot_storage_delta_gib = $snapshotDeltaGiB
    observed_snapshot_storage_delta_mib = $snapshotDeltaMiB

    vmdk_chain_manually_modified = $false
    old_baseline_deleted = $false
    official_run_slot_consumed = $false

    guest_verification_report = $HostResult
}

$receiptPath = Join-Path $OutRoot "UBUNTU_V11_POST_MATERIALIZATION_SNAPSHOT_RECEIPT.json"
Assert-MaxPath $receiptPath "snapshot receipt"
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

$snapshotListPath = Join-Path $OutRoot "UBUNTU_SNAPSHOT_LIST_AFTER.txt"
$snapshotsAfter | Set-Content -LiteralPath $snapshotListPath -Encoding UTF8

$hashFiles = @(
    $FamilySetManifest,
    $GuestExpectedHost,
    $GuestHelperHost,
    $InstallHelperHost,
    $HostResult,
    $snapshotListPath,
    $receiptPath
)
$hashFiles += @($toInstall | ForEach-Object { Join-Path $OutRoot ("INSTALL_R_{0}.json" -f $_.sha.Substring(0,16)) })

$hashRows = foreach($p in $hashFiles){
    [pscustomobject]@{
        file = $p
        bytes = (Get-Item -LiteralPath $p).Length
        sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$hashCsv = Join-Path $OutRoot "UBUNTU_V11_POST_MATERIALIZATION_EVIDENCE_SHA256.csv"
Assert-MaxPath $hashCsv "evidence hash csv"
$hashRows | Export-Csv -LiteralPath $hashCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "UBUNTU V11 POST-MATERIALIZATION FINALIZATION: PASS"
Write-Host "Qualified families verified in the guest: 10/10"
Write-Host ("Samples materialised this step: {0} ({1})" -f $toInstall.Count, (($toInstall | ForEach-Object { $_.family }) -join ', '))
Write-Host "Old R4 samples preserved: 10/10"
Write-Host "Old snapshot preserved: $oldPresentAfter"
Write-Host "New snapshot created: $newPresentAfter"
Write-Host "Snapshot created with Ubuntu OFF: True"
Write-Host "D: free before snapshot: $dBeforeSnapshot GiB"
Write-Host "D: free after snapshot:  $dAfterSnapshot GiB"
Write-Host "Observed new snapshot delta: $snapshotDeltaMiB MiB"
Write-Host "Receipt: $receiptPath"
Write-Host "Evidence hashes: $hashCsv"
