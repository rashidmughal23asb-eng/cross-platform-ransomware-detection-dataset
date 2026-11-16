# WINDOWS_V11_GUEST_MATERIALIZER.ps1
# ==================================
# Runs INSIDE the Windows 11 guest (Administrator PowerShell). Builds the new V11 sample
# cycle C:\RansomLab\MalwareStaging\P5G\V11\Samples\ from:
#   * the nine already-verified R4 keepers  -> byte-for-byte COPY (the R4 root is never modified)
#   * the Nefilim AES archive              -> 7-Zip extraction with the published password
# and verifies every artifact by SHA-256, byte count, exact path and PE machine.
#
# D-164 §3: ZERO EXECUTION. This helper never launches a sample, never maps an image, never
# starts telemetry and never touches the network. It only copies bytes, extracts an archive
# with a benign tool and hashes files. No process may ever be started from the sample root.
#
# Fail-closed: the V11 root must NOT exist, the R4 root must hold exactly the 10 frozen
# read-only samples, the expected-hash TSV must name exactly 10 rows, and the evidence root
# must not exist. Any deviation preserves the state and stops.
#
# Inputs (transferred by the host driver):
#   C:\Windows\Temp\WINDOWS_V11_EXPECTED_SHA256.tsv
#   C:\Windows\Temp\WINDOWS_V11_NEFILIM_ARCHIVE.zip
# Output:
#   C:\RansomLab\Evidence\P5G_V11_WINDOWS_MATERIALIZATION\P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv
#   C:\RansomLab\Evidence\P5G_V11_WINDOWS_MATERIALIZATION\P5G_V11_WINDOWS_AUTHORITY.json
#   C:\RansomLab\Evidence\P5G_V11_WINDOWS_MATERIALIZATION\P5G_V11_WINDOWS_REPORT.txt

param(
    [string]$ExpectedPath = 'C:\Windows\Temp\WINDOWS_V11_EXPECTED_SHA256.tsv',
    [string]$ArchivePath = 'C:\Windows\Temp\WINDOWS_V11_NEFILIM_ARCHIVE.zip'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-SHA256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Utf8NoBom([string]$Path, [string]$Text) { $E = New-Object System.Text.UTF8Encoding($false); [IO.File]::WriteAllText($Path, $Text, $E) }

# Minimal PE reader: DOS header -> e_lfanew -> "PE\0\0" -> COFF machine (UInt16).
function Get-PeMachine([string]$Path) {
    $S = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $R = New-Object IO.BinaryReader($S)
    try {
        if ($S.Length -lt 128) { return $null }
        if ($R.ReadUInt16() -ne 0x5A4D) { return $null }
        [void]$S.Seek(0x3C, [IO.SeekOrigin]::Begin)
        $O = $R.ReadInt32()
        if ($O -lt 64 -or $O -gt ($S.Length - 6)) { return $null }
        [void]$S.Seek($O, [IO.SeekOrigin]::Begin)
        if ($R.ReadUInt32() -ne 0x00004550) { return $null }
        return [int]$R.ReadUInt16()
    } finally { $R.Dispose(); $S.Dispose() }
}

$R4Root      = 'C:\RansomLab\MalwareStaging\P5G\R4'
$R4Samples   = Join-Path $R4Root 'Samples'
$V11Root     = 'C:\RansomLab\MalwareStaging\P5G\V11'
$V11Samples  = Join-Path $V11Root 'Samples'
$WorkRoot    = 'C:\RansomLab\MalwareStaging\P5G\V11\_work'
$EvidenceRoot    = 'C:\RansomLab\Evidence\P5G_V11_WINDOWS_MATERIALIZATION'
$EvidencePartial = $EvidenceRoot + '.partial'
$SevenZip    = 'C:\Program Files\7-Zip\7z.exe'
$ArchivePassword = 'infected'   # published MalwareBazaar AES password; not a credential
$AddedExclusion = $false

try {
    Write-Host '===== WINDOWS V11 GUEST-ONLY EXACT SAMPLE MATERIALIZATION (D-164) ====='
    Write-Host 'RansomwareExecutionAuthorizedNow=False'
    Write-Host 'TelemetryStartAuthorizedNow=False'
    Write-Host 'NetworkUseAuthorizedNow=False'

    $I = [Security.Principal.WindowsIdentity]::GetCurrent()
    $P = New-Object Security.Principal.WindowsPrincipal($I)
    Assert-True ($P.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR POWERSHELL REQUIRED INSIDE WINDOWS GUEST'
    Assert-True (Test-Path -LiteralPath $ExpectedPath -PathType Leaf) 'EXPECTED-HASH TSV MISSING'
    Assert-True (Test-Path -LiteralPath $ArchivePath -PathType Leaf) 'NEFILIM ARCHIVE MISSING'
    Assert-True (Test-Path -LiteralPath $R4Samples -PathType Container) 'R4 SAMPLE ROOT MISSING'
    Assert-True (-not (Test-Path -LiteralPath $V11Root)) 'V11 SAMPLE ROOT ALREADY EXISTS - PRESERVE AND STOP'
    Assert-True (-not (Test-Path -LiteralPath $EvidenceRoot)) 'V11 FINAL EVIDENCE ALREADY EXISTS - PRESERVE AND STOP'
    Assert-True (-not (Test-Path -LiteralPath $EvidencePartial)) 'V11 PARTIAL EVIDENCE EXISTS - PRESERVE AND STOP'
    Assert-True (Test-Path -LiteralPath $SevenZip -PathType Leaf) '7-ZIP NOT FOUND AT EXPECTED PATH'

    # --- the frozen expected set ----------------------------------------------------------
    $Rows = @()
    foreach ($Line in (Get-Content -LiteralPath $ExpectedPath)) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        if ($Line.TrimStart().StartsWith('#')) { continue }
        $F = $Line -split "`t"
        Assert-True ($F.Count -ge 6) ('MALFORMED EXPECTED-HASH ROW: ' + $Line)
        $Sha = ([string]$F[0]).Trim().ToLowerInvariant()
        Assert-True ($Sha -match '^[0-9a-f]{64}$') ('INVALID EXPECTED SHA256: ' + $Sha)
        $Family = ([string]$F[1]).Trim()
        $RunId = ([string]$F[2]).Trim()
        $Bytes = [int64](([string]$F[3]).Trim())
        $PeHex = ([string]$F[4]).Trim().ToUpperInvariant()
        $Source = ([string]$F[5]).Trim().ToUpperInvariant()
        $ArcSha = if ($F.Count -ge 7) { ([string]$F[6]).Trim().ToLowerInvariant() } else { '' }
        $ArcBytes = if ($F.Count -ge 8) { ([string]$F[7]).Trim() } else { '' }
        Assert-True ($RunId -match '^W-R-\d{2}$') ('INVALID RUN ID: ' + $RunId)
        Assert-True ($Family -ne '') ('EMPTY FAMILY: ' + $RunId)
        Assert-True ($Bytes -gt 0) ('INVALID BYTE COUNT: ' + $RunId)
        Assert-True ($PeHex -match '^[0-9A-F]{4}$') ('INVALID PE MACHINE: ' + $RunId)
        Assert-True ($Source -in @('R4_COPY', 'ARCHIVE')) ('INVALID SOURCE: ' + $RunId)
        if ($Source -ceq 'ARCHIVE') {
            Assert-True ($ArcSha -match '^[0-9a-f]{64}$') ('ARCHIVE ROW WITHOUT ARCHIVE SHA: ' + $RunId)
            Assert-True ($ArcBytes -match '^\d+$') ('ARCHIVE ROW WITHOUT ARCHIVE BYTES: ' + $RunId)
        }
        $Rows += [pscustomobject]@{ Sha = $Sha; Family = $Family; RunId = $RunId; Bytes = $Bytes; PeHex = $PeHex; Source = $Source; ArcSha = $ArcSha; ArcBytes = $ArcBytes }
    }
    Assert-True ($Rows.Count -eq 10) ('EXPECTED-HASH ROW COUNT != 10: ' + $Rows.Count)
    Assert-True (@($Rows.RunId | Sort-Object -Unique).Count -eq 10) 'EXPECTED RUN IDS NOT UNIQUE'
    Assert-True (@($Rows.Sha | Sort-Object -Unique).Count -eq 10) 'EXPECTED SAMPLE HASHES NOT UNIQUE'
    Assert-True (@($Rows | Where-Object { $_.Source -ceq 'R4_COPY' }).Count -eq 9) 'EXPECTED R4_COPY COUNT != 9'
    Assert-True (@($Rows | Where-Object { $_.Source -ceq 'ARCHIVE' }).Count -eq 1) 'EXPECTED ARCHIVE COUNT != 1'
    $Nef = @($Rows | Where-Object { $_.Source -ceq 'ARCHIVE' })[0]
    Assert-True ($Nef.RunId -ceq 'W-R-09' -and $Nef.Family -ceq 'Nefilim') 'ARCHIVE ROW IS NOT THE NEFILIM SLOT'

    # --- the frozen R4 root must be exactly the ten read-only keepers+placeholder ----------
    $R4Files = @(Get-ChildItem -LiteralPath $R4Samples -File -Force | Sort-Object Name)
    Assert-True ($R4Files.Count -eq 10) ('R4 SAMPLE COUNT != 10: ' + $R4Files.Count)
    Assert-True (@($R4Files | Where-Object { -not $_.IsReadOnly }).Count -eq 0) 'R4 SAMPLE SET CONTAINS A WRITABLE FILE'
    foreach ($R in $Rows) {
        $Src = Join-Path $R4Samples ($R.Sha + '.sample')
        if ($R.Source -ceq 'R4_COPY') {
            Assert-True (Test-Path -LiteralPath $Src -PathType Leaf) ('R4 SOURCE MISSING: ' + $R.RunId)
            Assert-True ((Get-SHA256 $Src) -ceq $R.Sha) ('R4 SOURCE SHA DRIFT: ' + $R.RunId)
            Assert-True ((Get-Item -LiteralPath $Src).Length -eq $R.Bytes) ('R4 SOURCE BYTE DRIFT: ' + $R.RunId)
        }
    }
    # The R4 placeholder (ClearWater) must still be present and untouched: quarantined by cycle.
    $ClearWater = Join-Path $R4Samples '00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746.sample'
    Assert-True (Test-Path -LiteralPath $ClearWater -PathType Leaf) 'R4 CLEARWATER PLACEHOLDER MISSING'
    Assert-True ((Get-SHA256 $ClearWater) -ceq '00202340108c101d59bbfb3daa4bbd6b4436c167e3c9734c07bfbdcb1402f746') 'R4 CLEARWATER PLACEHOLDER SHA DRIFT'

    # --- environment gates (unchanged from the R4 gate) ------------------------------------
    $Up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count
    $V4 = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' }).Count
    $V6 = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' }).Count
    $FWOff = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled }).Count
    $Shared = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { [string]$_.Root -match '(?i)(vmware-host|hgfs|shared folders)' }).Count
    $Procmon = @(Get-Process -Name 'Procmon', 'Procmon64' -ErrorAction SilentlyContinue).Count
    Assert-True ($Up -eq 0) 'WINDOWS GUEST NETWORK ADAPTER UP'
    Assert-True ($V4 -eq 0 -and $V6 -eq 0) 'WINDOWS GUEST DEFAULT ROUTE PRESENT'
    Assert-True ($FWOff -eq 0) 'WINDOWS FIREWALL PROFILE DISABLED'
    Assert-True ($Shared -eq 0) 'VMWARE SHARED FILESYSTEM PRESENT'
    Assert-True ($Procmon -eq 0) 'PROCMON MUST NOT BE RUNNING DURING MATERIALIZATION'

    $Mp = Get-MpComputerStatus -ErrorAction Stop
    Assert-True ([bool]$Mp.AntivirusEnabled) 'DEFENDER ANTIVIRUS DISABLED'
    Assert-True ([bool]$Mp.RealTimeProtectionEnabled) 'DEFENDER REAL-TIME PROTECTION DISABLED'
    Assert-True ([bool]$Mp.BehaviorMonitorEnabled) 'DEFENDER BEHAVIOR MONITOR DISABLED'
    Assert-True ([bool]$Mp.AMServiceEnabled) 'DEFENDER AM SERVICE DISABLED'

    # The frozen analysis root C:\RansomLab is excluded at RUN TIME by the controller's AV
    # helper (the analysis surfaces), not at materialisation time. At materialisation time the
    # only scoped exclusion is the R4 cycle root (added by the R4 gate); assert it is still
    # present so the AV policy has not regressed, and that Defender global protection is on.
    $Prefs = Get-MpPreference -ErrorAction Stop
    $Exc = @($Prefs.ExclusionPath | ForEach-Object { [string]$_ })
    $R4Root = 'C:\RansomLab\MalwareStaging\P5G\R4'
    $R4Exact = @($Exc | Where-Object { [string]::Equals($_, $R4Root, [StringComparison]::OrdinalIgnoreCase) }).Count
    Assert-True ($R4Exact -eq 1) 'R4 CYCLE DEFENDER EXCLUSION MISSING OR DUPLICATED'
    $V11Root = 'C:\RansomLab\MalwareStaging\P5G\V11'
    $V11Exact = @($Exc | Where-Object { [string]::Equals($_, $V11Root, [StringComparison]::OrdinalIgnoreCase) }).Count
    if ($V11Exact -eq 0) { Add-MpPreference -ExclusionPath $V11Root -ErrorAction Stop; $AddedExclusion = $true }
    $Prefs2 = Get-MpPreference -ErrorAction Stop
    $Exc2 = @($Prefs2.ExclusionPath | ForEach-Object { [string]$_ })
    $V11Exact2 = @($Exc2 | Where-Object { [string]::Equals($_, $V11Root, [StringComparison]::OrdinalIgnoreCase) }).Count
    Assert-True ($V11Exact2 -eq 1) 'V11 CYCLE DEFENDER EXCLUSION NOT PRESENT EXACTLY ONCE'
    $AnalysisRoot = 'C:\RansomLab'
    $AnalysisExact = @($Exc2 | Where-Object { [string]::Equals($_, $AnalysisRoot, [StringComparison]::OrdinalIgnoreCase) }).Count
    # Recorded for evidence; not a gate (the controller adds this at run time).
    $AnalysisRootExcludedAtMaterialisation = ($AnalysisExact -ge 1)

    New-Item -ItemType Directory -Path $V11Root -Force | Out-Null
    New-Item -ItemType Directory -Path $V11Samples -Force | Out-Null
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $EvidencePartial -Force | Out-Null

    # --- 1) the nine keepers: byte-for-byte copy, R4 never modified -----------------------
    foreach ($R in ($Rows | Where-Object { $_.Source -ceq 'R4_COPY' } | Sort-Object RunId)) {
        $Src = Join-Path $R4Samples ($R.Sha + '.sample')
        $Dst = Join-Path $V11Samples ($R.Sha + '.sample')
        Assert-True (-not (Test-Path -LiteralPath $Dst)) ('V11 TARGET ALREADY EXISTS: ' + $R.RunId)
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
        Assert-True ((Get-SHA256 $Dst) -ceq $R.Sha) ('V11 COPY SHA DRIFT: ' + $R.RunId)
        Assert-True ((Get-Item -LiteralPath $Dst).Length -eq $R.Bytes) ('V11 COPY BYTE DRIFT: ' + $R.RunId)
        $Machine = Get-PeMachine $Dst
        Assert-True ($null -ne $Machine) ('V11 COPY IS NOT PE: ' + $R.RunId)
        Assert-True (('{0:X4}' -f [int]$Machine) -ceq $R.PeHex) ('V11 COPY PE MACHINE MISMATCH: ' + $R.RunId)
        (Get-Item -LiteralPath $Dst).IsReadOnly = $true
        Write-Host ('COPIED   | ' + $R.RunId + ' | ' + $R.Family + ' | ' + $R.Sha.Substring(0, 12) + ' | PE=' + $R.PeHex + ' | PASS')
    }

    # --- 2) Nefilim: verify the archive, extract, verify, rename ---------------------------
    Assert-True ((Get-Item -LiteralPath $ArchivePath).Length -eq [int64]$Nef.ArcBytes) 'NEFILIM ARCHIVE BYTE DRIFT'
    Assert-True ((Get-SHA256 $ArchivePath) -ceq $Nef.ArcSha) 'NEFILIM ARCHIVE SHA DRIFT'
    $Work = Join-Path $WorkRoot $Nef.RunId
    New-Item -ItemType Directory -Path $Work -Force | Out-Null
    $Extracted = $null
    $A = @('x', '-y', '-bd', '-bso0', '-bsp0', '-bse1', ('-p' + $ArchivePassword), ('-o' + $Work), $ArchivePath)
    $O = @(& $SevenZip @A 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) ('7-ZIP EXTRACTION FAILED: ' + ($O -join ' | '))
    $X = @(Get-ChildItem -LiteralPath $Work -File -Recurse -Force -ErrorAction Stop)
    Assert-True ($X.Count -eq 1) ('EXTRACTED FILE COUNT != 1: ' + $X.Count)
    $Raw = $X[0]
    Assert-True ((Get-SHA256 $Raw.FullName) -ceq $Nef.Sha) 'NEFILIM EXTRACTED SHA MISMATCH'
    Assert-True ($Raw.Length -eq $Nef.Bytes) 'NEFILIM EXTRACTED BYTE MISMATCH'
    $Machine = Get-PeMachine $Raw.FullName
    Assert-True ($null -ne $Machine) 'NEFILIM EXTRACTED FILE IS NOT PE'
    Assert-True (('{0:X4}' -f [int]$Machine) -ceq $Nef.PeHex) ('NEFILIM PE MACHINE MISMATCH: expected=' + $Nef.PeHex + ' observed=' + ('{0:X4}' -f [int]$Machine))
    $Dst = Join-Path $V11Samples ($Nef.Sha + '.sample')
    Assert-True (-not (Test-Path -LiteralPath $Dst)) 'V11 TARGET ALREADY EXISTS: W-R-09'
    Move-Item -LiteralPath $Raw.FullName -Destination $Dst
    Remove-Item -LiteralPath $Work -Recurse -Force
    Assert-True ((Get-SHA256 $Dst) -ceq $Nef.Sha) 'NEFILIM FINAL SHA DRIFT'
    Assert-True ((Get-Item -LiteralPath $Dst).Length -eq $Nef.Bytes) 'NEFILIM FINAL BYTE DRIFT'
    (Get-Item -LiteralPath $Dst).IsReadOnly = $true
    Write-Host ('MATERIALIZED | W-R-09 | Nefilim | ' + $Nef.Sha.Substring(0, 12) + ' | PE=' + $Nef.PeHex + ' | PASS')

    if (Test-Path -LiteralPath $WorkRoot) { Remove-Item -LiteralPath $WorkRoot -Recurse -Force }

    # --- 3) whole-set verification --------------------------------------------------------
    $Files = @(Get-ChildItem -LiteralPath $V11Samples -File -Force | Sort-Object Name)
    Assert-True ($Files.Count -eq 10) ('V11 MATERIALIZED FILE COUNT != 10: ' + $Files.Count)
    Assert-True (@($Files | Where-Object { -not $_.IsReadOnly }).Count -eq 0) 'V11 SAMPLE SET CONTAINS A WRITABLE FILE'
    foreach ($R in $Rows) {
        $Dst = Join-Path $V11Samples ($R.Sha + '.sample')
        Assert-True (Test-Path -LiteralPath $Dst -PathType Leaf) ('V11 SAMPLE MISSING: ' + $R.RunId)
        Assert-True ((Get-SHA256 $Dst) -ceq $R.Sha) ('V11 SAMPLE SHA DRIFT: ' + $R.RunId)
        Assert-True ((Get-Item -LiteralPath $Dst).Length -eq $R.Bytes) ('V11 SAMPLE BYTE DRIFT: ' + $R.RunId)
        $Machine = Get-PeMachine $Dst
        Assert-True ($null -ne $Machine -and ('{0:X4}' -f [int]$Machine) -ceq $R.PeHex) ('V11 SAMPLE PE MACHINE MISMATCH: ' + $R.RunId)
    }
    $RunningUnder = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and ([string]$_.ExecutablePath).StartsWith($V11Samples, [StringComparison]::OrdinalIgnoreCase) })
    Assert-True ($RunningUnder.Count -eq 0) 'PROCESS EXECUTING FROM THE V11 SAMPLE ROOT'
    $Up2 = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count
    $V42 = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' }).Count
    $V62 = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' }).Count
    Assert-True ($Up2 -eq 0 -and $V42 -eq 0 -and $V62 -eq 0) 'WINDOWS NETWORK ISOLATION CHANGED DURING MATERIALIZATION'
    $Mp2 = Get-MpComputerStatus -ErrorAction Stop
    Assert-True ([bool]$Mp2.AntivirusEnabled -and [bool]$Mp2.RealTimeProtectionEnabled -and [bool]$Mp2.BehaviorMonitorEnabled -and [bool]$Mp2.AMServiceEnabled) 'WINDOWS DEFENDER GLOBAL PROTECTION CHANGED'

    # --- 4) evidence ----------------------------------------------------------------------
    $OutRows = @()
    foreach ($R in ($Rows | Sort-Object RunId)) {
        $Dst = Join-Path $V11Samples ($R.Sha + '.sample')
        $OutRows += [pscustomobject]@{
            run_id = $R.RunId; os = 'Windows'; family_stratum = $R.Family; sample_sha256 = $R.Sha
            materialized_path = $Dst; materialized_bytes = (Get-Item -LiteralPath $Dst).Length
            materialized_sha256 = (Get-SHA256 $Dst); pe_machine_hex = $R.PeHex
            source = $R.Source; read_only = $true; malware_executed = $false; telemetry_started = $false
        }
    }
    $ManifestOut = Join-Path $EvidencePartial 'P5G_V11_WINDOWS_MATERIALIZATION_MANIFEST.csv'
    $Csv = ((@($OutRows) | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"
    Write-Utf8NoBom $ManifestOut $Csv
    $ManifestSha = Get-SHA256 $ManifestOut

    $Auth = [ordered]@{
        schema_version = '1.0'; gate = 'P5G_V11_WINDOWS_GUEST'; status = 'PASS'
        created_utc = [DateTime]::UtcNow.ToString('o')
        decision_ref = 'D-163/D-164'
        sample_count = 10
        keeper_copy_count = 9
        archive_materialized_count = 1
        r4_root_preserved_untouched = $true
        r4_clearwater_placeholder_present = $true
        all_exact_sha256_verified = $true
        all_bytes_verified = $true
        all_paths_verified = $true
        all_pe_machines_verified = $true
        pe_machine_set = @('8664', '014C')
        canonical_sample_root = $V11Samples
        network_isolation_preserved = $true
        defender_global_protection_enabled = $true
        frozen_analysis_root_exclusion_exact_count_at_materialisation = $AnalysisExact
        raw_provider_archive_deleted_after_materialization = $true
        v11_sample_set_read_only = $true
        v11_root_running_process_count = 0
        malware_executed = $false
        telemetry_started = $false
        prospective_scoring_performed = $false
        containment_performed = $false
        manifest_sha256 = $ManifestSha
        next_control = 'P5G_V11_HOST_RETRIEVE_WINDOWS_EVIDENCE'
    }
    $AuthPath = Join-Path $EvidencePartial 'P5G_V11_WINDOWS_AUTHORITY.json'
    Write-Utf8NoBom $AuthPath (($Auth | ConvertTo-Json -Depth 10) + "`n")
    $ReportPath = Join-Path $EvidencePartial 'P5G_V11_WINDOWS_REPORT.txt'
    $Report = @(
        'P5G_V11_WINDOWS=PASS',
        'SamplesMaterialized=10',
        'KeeperCopies=9',
        'ArchiveMaterialized=1',
        'AllExactSHA256Verified=True',
        'AllBytesVerified=True',
        'AllPathsVerified=True',
        'AllPEMachinesVerified=True',
        'R4RootPreservedUntouched=True',
        'R4ClearwaterPlaceholderPresent=True',
        'NetworkIsolationPreserved=True',
        'DefenderGlobalProtectionEnabled=True',
        'RawProviderArchiveDeleted=True',
        'MalwareExecuted=False',
        'TelemetryStarted=False',
        'ProspectiveScoringPerformed=False'
    )
    Write-Utf8NoBom $ReportPath (($Report -join "`r`n") + "`r`n")
    foreach ($Pth in @($ManifestOut, $AuthPath, $ReportPath)) { (Get-Item -LiteralPath $Pth).IsReadOnly = $true }

    # Remove the transferred archive from the guest temp root (host copy is authoritative).
    if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }
    Assert-True (-not (Test-Path -LiteralPath $ArchivePath)) 'TRANSFERRED ARCHIVE RESIDUE REMAINS IN THE GUEST'

    Move-Item -LiteralPath $EvidencePartial -Destination $EvidenceRoot
    Write-Host '===== WINDOWS V11 FINAL ====='
    Write-Host 'Status : PASS'
    Write-Host 'SamplesMaterialized : 10 (9 keeper copies + 1 archive)'
    Write-Host 'AllExactSHA256Verified : True'
    Write-Host 'AllBytesVerified : True'
    Write-Host 'AllPathsVerified : True'
    Write-Host 'AllPEMachinesVerified : True (8664 x9, 014C x1)'
    Write-Host 'R4RootPreservedUntouched : True'
    Write-Host 'NetworkIsolationPreserved : True'
    Write-Host 'RansomwareExecuted : False'
    Write-Host 'TelemetryStarted : False'
    Write-Host 'RESULT : WINDOWS V11 GUEST-ONLY EXACT SAMPLE MATERIALIZATION PASS'
}
catch {
    Write-Host ('ERROR : ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'RansomwareExecuted : False' -ForegroundColor Red
    Write-Host 'RESULT : WINDOWS V11 NOT PASS / PRESERVE AND STOP' -ForegroundColor Red
    throw
}
