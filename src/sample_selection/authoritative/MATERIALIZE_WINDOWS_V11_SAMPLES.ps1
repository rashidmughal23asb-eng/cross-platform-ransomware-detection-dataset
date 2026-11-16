# MATERIALIZE_WINDOWS_V11_SAMPLES.ps1
# ===================================
# Host-side driver for the D-164 Windows V11 sample-cycle materialisation.
#
# Builds C:\RansomLab\MalwareStaging\P5G\V11\Samples\ in the Windows guest:
#   * nine keepers are COPIED byte-for-byte from the frozen R4 root (which is never modified),
#   * Nefilim is extracted in-guest from the AES archive with 7-Zip,
# then verifies SHA-256 / bytes / path / PE machine for all ten and creates the new offline
# baseline snapshot P5G_V11_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261115 with the VM OFF.
#
# ZERO EXECUTION (D-164 Â§3): no sample is ever started, mapped or scored; no telemetry is
# started; the network stays isolated; the only tools used are Copy-Item, 7z and Get-FileHash.
#
# Modes (run each in an ELEVATED PowerShell, in order):
#   Preflight  - static preconditions, both VMs off. Writes nothing.
#   Stage      - start the Windows guest from the frozen R5 baseline and transfer the helper,
#                the expected-hash TSV and the encrypted archive.
#   RunGuest   - execute the in-guest materializer and retrieve its evidence.
#   Retrieve   - re-copy the guest evidence to the host (idempotent).
#   Finalize   - verify the retrieved evidence, then create the powered-off snapshot and write
#                the V11 materialisation manifest + snapshot receipt.
#
# Exit code 0 = PASS for the requested mode; any failure throws (fail-closed, state preserved).

[CmdletBinding()]
param(
    [ValidateSet('Preflight', 'Stage', 'RunGuest', 'Retrieve', 'Finalize')]
    [string]$Mode = 'Preflight',
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$UbuntuVmxPath  = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$Vmrun          = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$VMwareGuiPath  = 'C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe'

$ScriptDir      = Join-Path $CampaignRoot '01_SHARED\scripts\host\sample_selection'
$Bridge         = Join-Path $CampaignRoot '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\windows\HCQNativeBridge.ps1'
$ExpectedHost   = Join-Path $ScriptDir 'WINDOWS_V11_EXPECTED_SHA256.tsv'
$HelperHost     = Join-Path $ScriptDir 'WINDOWS_V11_GUEST_MATERIALIZER.ps1'
$ArchiveHost    = Join-Path $CampaignRoot '01_SHARED\STAGING_CANDIDATES\SCREEN_20261115\Nefilim_2daa5144081d.zip'

$OldSnapshot    = 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013'
$NewSnapshot    = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261115'

$GuestHelper    = 'C:\Windows\Temp\WINDOWS_V11_GUEST_MATERIALIZER.ps1'
$GuestExpected  = 'C:\Windows\Temp\WINDOWS_V11_EXPECTED_SHA256.tsv'
$GuestArchive   = 'C:\Windows\Temp\WINDOWS_V11_NEFILIM_ARCHIVE.zip'
$GuestEvidence  = 'C:\RansomLab\Evidence\P5G_V11_WINDOWS_MATERIALIZATION'
$GuestManifest  = Join-Path $GuestEvidence 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv'
$GuestAuthority = Join-Path $GuestEvidence 'P5G_V11_WINDOWS_AUTHORITY.json'
$GuestReport    = Join-Path $GuestEvidence 'P5G_V11_WINDOWS_REPORT.txt'

$OutRoot        = Join-Path $CampaignRoot '01_SHARED\sample_selection\WINDOWS_V11_MATERIALIZATION_20261115'
$StageDir       = Join-Path $OutRoot 'STAGE'
$RetrievedDir   = Join-Path $OutRoot 'RETRIEVED'
$FinalDir       = Join-Path $OutRoot 'FINAL'

$ExpectedRows   = 10
$ExpectedBytes  = 44710560

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Utf8NoBom([string]$Path, [string]$Text) { $E = New-Object Text.UTF8Encoding($false); [IO.File]::WriteAllText($Path, $Text, $E) }
function Get-RunningVmx {
    $out = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
    Assert-True ($LASTEXITCODE -eq 0) 'VMRUN LIST FAILED'
    return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' })
}
function Get-SnapshotNames([string]$Vmx) {
    $out = @(& $Vmrun -T ws listSnapshots $Vmx 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -eq 0) {
        return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    }
    # Fallback: `vmrun listSnapshots` needs elevation on this host. The .vmsd is the
    # authoritative snapshot tree and is readable without elevation (D-164 Â§4 proof path).
    $dir = Split-Path -Parent $Vmx
    $vmsd = @(Get-ChildItem -LiteralPath $dir -Filter '*.vmsd' -File -ErrorAction SilentlyContinue)
    Assert-True ($vmsd.Count -eq 1) ('VMRUN LISTSNAPSHOTS FAILED AND VMSD NOT UNIQUE: ' + $Vmx)
    $names = @()
    foreach ($l in [IO.File]::ReadAllLines($vmsd[0].FullName)) {
        $m = [regex]::Match($l, '^\s*snapshot[0-9]+\.displayName\s*=\s*"([^"]*)"\s*$')
        if ($m.Success) { $names += $m.Groups[1].Value }
    }
    return @($names)
}
function Write-Utf8NoBom([string]$Path, [string]$Text) { $E = New-Object Text.UTF8Encoding($false); [IO.File]::WriteAllText($Path, $Text, $E) }
function Write-Json([string]$Path, [object]$Object) { $d = Split-Path -Parent $Path; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; Write-Utf8NoBom $Path (($Object | ConvertTo-Json -Depth 20) + "`r`n") }
function Write-AtomicCreate([string]$Path, [object]$Object) { if (Test-Path -LiteralPath $Path) { throw ('EVIDENCE_ALREADY_EXISTS:' + $Path) }; Write-Json $Path $Object; return $Path }
function Get-DriveFreeGiB([string]$DeviceId) {
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DeviceId'"
    if (-not $d) { throw "Drive not found: $DeviceId" }
    return [math]::Round($d.FreeSpace / 1GB, 3)
}

# Caller-provided symbols the shared native bridge expects in the calling scope
# (the production controller defines the same set).
function Get-RunningVmxSet {
    $h = @{}
    $out = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
    foreach ($l in $out) { $t = $l.Trim(); if ($t -match '^[A-Za-z]:\\.*\.vmx$') { $h[$t.ToLowerInvariant()] = $true } }
    return $h
}
function Get-VmOn([string]$Vmx) { (Get-RunningVmxSet).ContainsKey($Vmx.ToLowerInvariant()) }
function Get-UniqueVmsd([string]$Vmx) {
    $a = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    Assert-True ($a.Count -eq 1) ('VMSD_NOT_UNIQUE: ' + $Vmx)
    return $a[0].FullName
}
function Get-CurrentSnapshotName([string]$Vmx, [string]$Label) {
    $v = Get-UniqueVmsd $Vmx
    $lines = [IO.File]::ReadAllLines($v)
    $cur = ''
    $map = @{}
    foreach ($l in $lines) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"')
        if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"')
        if ($m.Success) {
            $i = [int]$m.Groups[1].Value
            if (-not $map.ContainsKey($i)) { $map[$i] = @{} }
            $map[$i][$m.Groups[2].Value] = $m.Groups[3].Value
        }
    }
    Assert-True (-not [string]::IsNullOrWhiteSpace($cur)) ($Label + '_NO_CURRENT_SNAPSHOT')
    foreach ($i in $map.Keys) { if ([string]$map[$i]['uid'] -ceq $cur) { return [string]$map[$i]['displayName'] } }
    throw ($Label + '_SNAPSHOT_UID_UNMAPPED')
}
function Assert-CurrentSnapshot([string]$Vmx, [string]$Expected, [string]$Label) {
    $a = Get-CurrentSnapshotName $Vmx $Label
    Assert-True ($a -ceq $Expected) ($Label + '_SNAPSHOT_DRIFT expected=' + $Expected + ' actual=' + $a)
}

# -------------------------------------------------------------------------- static binds
foreach ($p in @($Vmrun, $WindowsVmxPath, $UbuntuVmxPath, $Bridge, $ExpectedHost, $HelperHost, $ArchiveHost)) {
    Assert-True (Test-Path -LiteralPath $p -PathType Leaf) ('REQUIRED INPUT MISSING: ' + $p)
}
$ExpectedSha = Get-Sha $ExpectedHost
$HelperSha   = Get-Sha $HelperHost
$ArchiveSha  = Get-Sha $ArchiveHost
$ArchiveBytes = (Get-Item -LiteralPath $ArchiveHost).Length
Assert-True ($ArchiveSha -ceq '30e245557d8b16dbb58fc497699e2350f06f7ca530d7523074dbd112a4b6273d') 'NEFILIM ARCHIVE SHA DRIFT'
Assert-True ($ArchiveBytes -eq 40338) 'NEFILIM ARCHIVE BYTE DRIFT'

$TsvRows = @(Get-Content -LiteralPath $ExpectedHost | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') })
Assert-True ($TsvRows.Count -eq $ExpectedRows) ('EXPECTED TSV ROW COUNT != 10: ' + $TsvRows.Count)
$TsvBytes = 0
foreach ($line in $TsvRows) {
    $f = $line -split "`t"
    Assert-True ($f.Count -ge 6) ('MALFORMED TSV ROW: ' + $line)
    Assert-True ((([string]$f[0]).Trim().ToLowerInvariant()) -match '^[0-9a-f]{64}$') ('INVALID TSV SHA: ' + $line)
    $TsvBytes += [int64](([string]$f[3]).Trim())
}
Assert-True ($TsvBytes -eq $ExpectedBytes) ('EXPECTED TSV TOTAL BYTES != ' + $ExpectedBytes + ': ' + $TsvBytes)

New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null

# -------------------------------------------------------------------------- Preflight
if ($Mode -eq 'Preflight') {
    $running = @(Get-RunningVmx)
    Assert-True ($running.Count -eq 0) ('BOTH VMS MUST BE POWERED OFF; running=' + ($running -join '; '))
    $winSnap = @(Get-SnapshotNames $WindowsVmxPath)
    Assert-True ($winSnap -contains $OldSnapshot) ('FROZEN WINDOWS BASELINE SNAPSHOT MISSING: ' + $OldSnapshot)
    Assert-True (-not ($winSnap -contains $NewSnapshot)) ('V11 SNAPSHOT ALREADY EXISTS - PRESERVE AND STOP: ' + $NewSnapshot)
    $free = Get-DriveFreeGiB 'D:'
    Assert-True ($free -ge 6.0) ('D: FREE BELOW 6.0 GiB: ' + $free)
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $OutRoot 'FINAL'))) 'FINAL EVIDENCE ALREADY EXISTS - PRESERVE AND STOP'
    Write-Host 'WINDOWS V11 MATERIALIZATION PREFLIGHT: PASS' -ForegroundColor Green
    Write-Host ('  expected TSV : ' + $ExpectedHost + '  sha=' + $ExpectedSha)
    Write-Host ('  guest helper : ' + $HelperHost + '  sha=' + $HelperSha)
    Write-Host ('  archive      : ' + $ArchiveHost + '  bytes=' + $ArchiveBytes + '  sha=' + $ArchiveSha)
    Write-Host ('  expected set : 10 samples, ' + $TsvBytes + ' bytes (44,710,560)')
    Write-Host ('  baseline     : ' + $OldSnapshot + '  ->  new snapshot ' + $NewSnapshot)
    Write-Host ('  D: free      : ' + $free + ' GiB   VMs running: 0')
    exit 0
}

# -------------------------------------------------------------------------- Stage
if ($Mode -eq 'Stage') {
    Assert-True (-not (Test-Path -LiteralPath $StageDir)) ('STAGE EVIDENCE ALREADY EXISTS: ' + $StageDir)
    $running = @(Get-RunningVmx)
    Assert-True ($running.Count -eq 0) ('BOTH VMS MUST BE POWERED OFF BEFORE STAGE; running=' + ($running -join '; '))
    $winSnap = @(Get-SnapshotNames $WindowsVmxPath)
    Assert-True ($winSnap -contains $OldSnapshot) ('FROZEN WINDOWS BASELINE SNAPSHOT MISSING: ' + $OldSnapshot)
    Assert-True (-not ($winSnap -contains $NewSnapshot)) 'V11 SNAPSHOT ALREADY EXISTS - PRESERVE AND STOP'
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

    . $Bridge
    $Script:RunRoot = $StageDir
    try {
        Write-Host 'STAGE 1/3: start the Windows guest from the frozen R5 baseline...'
        Start-VM $WindowsVmxPath 'WINDOWS_V11_MATERIALIZE'
        Write-Host 'STAGE 2/3: transfer the helper, the expected-hash TSV and the encrypted archive...'
        Copy-HostToGuest $script:HCQVix.VM $HelperHost   $GuestHelper   $script:HCQVix.None 300
        Copy-HostToGuest $script:HCQVix.VM $ExpectedHost $GuestExpected $script:HCQVix.None 300
        Copy-HostToGuest $script:HCQVix.VM $ArchiveHost  $GuestArchive  $script:HCQVix.None 300
        Write-Host 'STAGE 3/3: verify the transfers by a host round-trip (byte + SHA-256)...'
        $RoundTrip = Join-Path $env:TEMP ('P5G_V11_STAGE_ROUNDTRIP_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $RoundTrip -Force | Out-Null
        try {
            Copy-GuestToHost $script:HCQVix.VM $GuestHelper   (Join-Path $RoundTrip 'helper.ps1')   $script:HCQVix.None 300
            Copy-GuestToHost $script:HCQVix.VM $GuestExpected (Join-Path $RoundTrip 'expected.tsv') $script:HCQVix.None 300
            Copy-GuestToHost $script:HCQVix.VM $GuestArchive  (Join-Path $RoundTrip 'archive.zip')  $script:HCQVix.None 300
            Assert-True ((Get-Sha (Join-Path $RoundTrip 'helper.ps1')) -ceq $HelperSha) 'HELPER ROUND-TRIP SHA MISMATCH'
            Assert-True ((Get-Sha (Join-Path $RoundTrip 'expected.tsv')) -ceq $ExpectedSha) 'EXPECTED-TSV ROUND-TRIP SHA MISMATCH'
            Assert-True ((Get-Sha (Join-Path $RoundTrip 'archive.zip')) -ceq $ArchiveSha) 'ARCHIVE ROUND-TRIP SHA MISMATCH'
            Assert-True ((Get-Item -LiteralPath (Join-Path $RoundTrip 'archive.zip')).Length -eq $ArchiveBytes) 'ARCHIVE ROUND-TRIP BYTE MISMATCH'
        } finally {
            Remove-Item -LiteralPath $RoundTrip -Recurse -Force -ErrorAction SilentlyContinue
        }
    } finally {
        try { Close-HCQVix } catch { }
    }

    $receipt = [ordered]@{
        schema_version = '1.0'; gate = 'P5G_V11_WINDOWS_STAGE'; status = 'PASS'
        created_utc = [DateTime]::UtcNow.ToString('o'); decision_ref = 'D-163/D-164'
        expected_tsv_sha256 = $ExpectedSha; guest_helper_sha256 = $HelperSha
        archive_sha256 = $ArchiveSha; archive_bytes = $ArchiveBytes
        guest_helper_path = $GuestHelper; guest_expected_path = $GuestExpected; guest_archive_path = $GuestArchive
        windows_baseline_snapshot = $OldSnapshot
        next_control = 'MATERIALIZE_WINDOWS_V11_SAMPLES.ps1 -Mode RunGuest'
    }
    Write-Utf8NoBom (Join-Path $StageDir 'P5G_V11_WINDOWS_STAGE_RECEIPT.json') (($receipt | ConvertTo-Json -Depth 8) + "`n")
    Write-Host 'WINDOWS V11 STAGE: PASS - the guest is RUNNING; next run -Mode RunGuest' -ForegroundColor Green
    exit 0
}

# -------------------------------------------------------------------------- RunGuest / Retrieve
if ($Mode -eq 'RunGuest' -or $Mode -eq 'Retrieve') {
    $running = @(Get-RunningVmx)
    Assert-True ($running -contains $WindowsVmxPath) 'WINDOWS GUEST IS NOT RUNNING'
    Assert-True (-not ($running -contains $UbuntuVmxPath)) 'UBUNTU MUST STAY OFF'
    New-Item -ItemType Directory -Path $RetrievedDir -Force | Out-Null

    if ($Mode -eq 'RunGuest') {
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $RetrievedDir 'P5G_V11_WINDOWS_AUTHORITY.json'))) 'RETRIEVED EVIDENCE ALREADY EXISTS - USE -Mode Retrieve OR PRESERVE AND STOP'
        . $Bridge
        try {
            Write-Host 'ESTABLISHING NATIVE VIX SESSION WITH THE RUNNING WINDOWS GUEST...'
            Start-VM $WindowsVmxPath 'WINDOWS_V11_MATERIALIZE_RUN'
            Write-Host 'RUNNING THE IN-GUEST MATERIALIZER (zero execution; the sample is never started)...'
            $cmd = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $GuestHelper + '"'
            $exit = Invoke-HCQEncoded $cmd 900
            Assert-True ($exit -eq 0) ('GUEST MATERIALIZER EXIT CODE != 0: ' + $exit)
        } finally {
            try { Close-HCQVix } catch { }
        }
    }

    . $Bridge
    try {
        Copy-GuestToHost $script:HCQVix.VM $GuestManifest  (Join-Path $RetrievedDir 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv') $script:HCQVix.None 300
        Copy-GuestToHost $script:HCQVix.VM $GuestAuthority (Join-Path $RetrievedDir 'P5G_V11_WINDOWS_AUTHORITY.json') $script:HCQVix.None 300
        Copy-GuestToHost $script:HCQVix.VM $GuestReport    (Join-Path $RetrievedDir 'P5G_V11_WINDOWS_REPORT.txt') $script:HCQVix.None 300
    } finally {
        try { Close-HCQVix } catch { }
    }

    $auth = Get-Content -LiteralPath (Join-Path $RetrievedDir 'P5G_V11_WINDOWS_AUTHORITY.json') -Raw | ConvertFrom-Json
    Assert-True ([string]$auth.status -ceq 'PASS') 'GUEST MATERIALIZATION AUTHORITY NOT PASS'
    Assert-True ([int]$auth.sample_count -eq 10) 'GUEST SAMPLE COUNT != 10'
    Assert-True ([int]$auth.keeper_copy_count -eq 9) 'KEEPER COPY COUNT != 9'
    Assert-True ([int]$auth.archive_materialized_count -eq 1) 'ARCHIVE MATERIALIZED COUNT != 1'
    Assert-True ([bool]$auth.all_exact_sha256_verified -and [bool]$auth.all_bytes_verified -and [bool]$auth.all_paths_verified -and [bool]$auth.all_pe_machines_verified) 'GUEST VERIFICATION FLAG NOT TRUE'
    Assert-True ([bool]$auth.r4_root_preserved_untouched) 'R4 ROOT PRESERVATION NOT RECORDED'
    Assert-True (-not [bool]$auth.malware_executed) 'GUEST AUTHORITY INDICATES MALWARE EXECUTION'
    Assert-True (-not [bool]$auth.telemetry_started) 'GUEST AUTHORITY INDICATES TELEMETRY START'
    $HostManifest = Join-Path $RetrievedDir 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv'
    Assert-True ((Get-Sha $HostManifest) -ceq ([string]$auth.manifest_sha256).ToLowerInvariant()) 'RETRIEVED MANIFEST SHA DRIFT'
    $rows = @(Import-Csv -LiteralPath $HostManifest)
    Assert-True ($rows.Count -eq 10) 'RETRIEVED MANIFEST ROW COUNT != 10'
    $sum = ($rows | Measure-Object -Property materialized_bytes -Sum).Sum
    Assert-True ([int64]$sum -eq $ExpectedBytes) ('RETRIEVED MANIFEST TOTAL BYTES != ' + $ExpectedBytes + ': ' + $sum)
    foreach ($r in $rows) {
        Assert-True (([string]$r.materialized_sha256).ToLowerInvariant() -ceq ([string]$r.sample_sha256).ToLowerInvariant()) ('MANIFEST SELF-HASH MISMATCH: ' + $r.run_id)
        Assert-True ([int64]$r.materialized_bytes -gt 0) ('MANIFEST BYTE COUNT INVALID: ' + $r.run_id)
    }
    Write-Host ('RETRIEVED: 10 samples, ' + $sum + ' bytes; authority PASS; R4 preserved; malware_executed=False') -ForegroundColor Green
    exit 0
}

# -------------------------------------------------------------------------- Finalize
if ($Mode -eq 'Finalize') {
    $retrievedManifest = Join-Path $RetrievedDir 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv'
    $retrievedAuthority = Join-Path $RetrievedDir 'P5G_V11_WINDOWS_AUTHORITY.json'
    $retrievedReport = Join-Path $RetrievedDir 'P5G_V11_WINDOWS_REPORT.txt'
    foreach ($p in @($retrievedManifest, $retrievedAuthority, $retrievedReport)) {
        Assert-True (Test-Path -LiteralPath $p -PathType Leaf) ('RETRIEVED EVIDENCE MISSING (run -Mode RunGuest first): ' + $p)
    }
    Assert-True (-not (Test-Path -LiteralPath $FinalDir)) ('FINAL EVIDENCE ALREADY EXISTS: ' + $FinalDir)
    $running = @(Get-RunningVmx)
    Assert-True ($running.Count -eq 0) ('BOTH VMS MUST BE POWERED OFF BEFORE THE SNAPSHOT; running=' + ($running -join '; '))
    $winSnap = @(Get-SnapshotNames $WindowsVmxPath)
    Assert-True ($winSnap -contains $OldSnapshot) ('FROZEN WINDOWS BASELINE SNAPSHOT MISSING: ' + $OldSnapshot)
    Assert-True (-not ($winSnap -contains $NewSnapshot)) 'V11 SNAPSHOT ALREADY EXISTS - PRESERVE AND STOP'
    New-Item -ItemType Directory -Path $FinalDir -Force | Out-Null

    $auth = Get-Content -LiteralPath $retrievedAuthority -Raw | ConvertFrom-Json
    Assert-True ([string]$auth.status -ceq 'PASS' -and [int]$auth.sample_count -eq 10) 'RETRIEVED AUTHORITY NOT PASS/10'
    $rows = @(Import-Csv -LiteralPath $retrievedManifest)
    Assert-True ($rows.Count -eq 10) 'RETRIEVED MANIFEST ROW COUNT != 10'
    $sum = ($rows | Measure-Object -Property materialized_bytes -Sum).Sum
    Assert-True ([int64]$sum -eq $ExpectedBytes) ('RETRIEVED MANIFEST TOTAL BYTES != ' + $ExpectedBytes)

    Copy-Item -LiteralPath $retrievedManifest -Destination (Join-Path $FinalDir 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv')
    Copy-Item -LiteralPath $retrievedAuthority -Destination (Join-Path $FinalDir 'P5G_V11_WINDOWS_AUTHORITY.json')
    Copy-Item -LiteralPath $retrievedReport -Destination (Join-Path $FinalDir 'P5G_V11_WINDOWS_REPORT.txt')
    $FinalManifest = Join-Path $FinalDir 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv'

    $dBefore = Get-DriveFreeGiB 'D:'
    Write-Host ('CREATING THE POWERED-OFF SNAPSHOT ' + $NewSnapshot + ' (VM OFF, disk-only, no memory capture)...')
    $snapOut = @(& $Vmrun -T ws snapshot $WindowsVmxPath $NewSnapshot 2>&1 | ForEach-Object { [string]$_ })
    Assert-True ($LASTEXITCODE -eq 0) ('SNAPSHOT CREATION FAILED: ' + ($snapOut -join ' | '))
    Start-Sleep -Seconds 3
    $after = @(Get-SnapshotNames $WindowsVmxPath)
    Assert-True ($after -contains $OldSnapshot) 'OLD BASELINE SNAPSHOT DISAPPEARED'
    Assert-True ($after -contains $NewSnapshot) 'NEW SNAPSHOT NOT VISIBLE AFTER CREATION'
    Assert-True (@(Get-RunningVmx).Count -eq 0) 'A VM IS RUNNING AFTER SNAPSHOT CREATION'
    $dAfter = Get-DriveFreeGiB 'D:'
    $deltaGiB = [math]::Round($dBefore - $dAfter, 3)
    $deltaMiB = [math]::Round(($dBefore - $dAfter) * 1024, 1)

    $receipt = [ordered]@{
        schema_version = '1.0'
        gate = 'P5G_V11_WINDOWS_POST_MATERIALIZATION'
        status = 'PASS'
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        decision_ref = 'D-163/D-164'
        expected_tsv_sha256 = $ExpectedSha
        guest_helper_sha256 = $HelperSha
        archive_sha256 = $ArchiveSha
        archive_bytes = $ArchiveBytes
        retrieved_authority_sha256 = Get-Sha $retrievedAuthority
        materialization_manifest_sha256 = Get-Sha $FinalManifest
        sample_count = 10
        keeper_copy_count = 9
        archive_materialized_count = 1
        total_bytes = [int64]$sum
        r4_root_preserved_untouched = [bool]$auth.r4_root_preserved_untouched
        r4_clearwater_placeholder_present = [bool]$auth.r4_clearwater_placeholder_present
        malware_executed = $false
        telemetry_started = $false
        old_snapshot = $OldSnapshot
        old_snapshot_present_after = $true
        new_snapshot = $NewSnapshot
        new_snapshot_present_after = $true
        snapshot_created_while_vm_off = $true
        guest_memory_snapshot_requested = $false
        vms_running_after_snapshot = 0
        d_free_gib_before_snapshot = $dBefore
        d_free_gib_after_snapshot = $dAfter
        observed_snapshot_storage_delta_gib = $deltaGiB
        observed_snapshot_storage_delta_mib = $deltaMiB
        official_campaign_slots_consumed = 0
        next_control = 'APPLY_WINDOWS_SAMPLE_REPLACEMENT_D163.ps1 -WindowsMaterializationManifestSha <sha> -Freeze'
    }
    Write-Utf8NoBom (Join-Path $FinalDir 'P5G_V11_WINDOWS_SNAPSHOT_RECEIPT.json') (($receipt | ConvertTo-Json -Depth 8) + "`n")
    Write-Utf8NoBom (Join-Path $FinalDir 'P5G_V11_WINDOWS_SNAPSHOT_LIST_AFTER.txt') (($after -join "`r`n") + "`r`n")

    $hashRows = foreach ($p in @($ExpectedHost, $HelperHost, $ArchiveHost, $retrievedManifest, $retrievedAuthority, $retrievedReport, $FinalManifest)) {
        [pscustomobject]@{ file = $p; bytes = (Get-Item -LiteralPath $p).Length; sha256 = Get-Sha $p }
    }
    $hashRows | Export-Csv -LiteralPath (Join-Path $FinalDir 'P5G_V11_WINDOWS_MATERIALIZATION_EVIDENCE_SHA256.csv') -NoTypeInformation -Encoding UTF8

    Write-Host 'WINDOWS V11 MATERIALIZATION FINALIZE: PASS' -ForegroundColor Green
    Write-Host ('  samples        : 10 (9 keeper copies + 1 archive), ' + $sum + ' bytes')
    Write-Host ('  manifest sha   : ' + (Get-Sha $FinalManifest))
    Write-Host ('  new snapshot   : ' + $NewSnapshot + ' (created while the VM was OFF)')
    Write-Host ('  D: free        : ' + $dBefore + ' -> ' + $dAfter + ' GiB (delta ' + $deltaMiB + ' MiB)')
    Write-Host ('  slots consumed : 0')
    Write-Host ('  next           : APPLY_WINDOWS_SAMPLE_REPLACEMENT_D163.ps1 -WindowsMaterializationManifestSha ' + (Get-Sha $FinalManifest) + ' -Freeze')
    exit 0
}

throw ('UNKNOWN MODE: ' + $Mode)
