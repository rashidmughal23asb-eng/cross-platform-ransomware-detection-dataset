<#
.SYNOPSIS
  Fetch the 19 frozen Ubuntu V10 ransomware samples into the unified host intake.

.DESCRIPTION
  Reads the frozen 19-row manifest, then for each SHA-256:
    1. MalwareBazaar  POST https://mb-api.abuse.ch/api/v1/  (query=get_file, hash=<sha256>)
       -> returns a password-protected ZIP ("infected"), extracted with 7-Zip.
    2. VirusTotal     GET  https://www.virustotal.com/api/v3/files/<sha>/download
       -> only used when MalwareBazaar does not have the file.

  Every downloaded byte is verified against the frozen SHA-256. A mismatch is
  deleted and reported; nothing is trusted on the basis of filename or source.

SAFETY / SCOPE
  - Reads API keys at runtime from local text files. Keys are never echoed,
    logged, written to the ledger, or placed on a command line.
  - Never executes, opens, unpacks into an executable path, or runs VMware.
  - Writes ONLY into host_archive_intake_all19 (the 19 sample files).
  - Ledger, temp ZIPs and quotes live OUTSIDE the intake root, because the frozen
    audit hashes every file under that root and would flag them as unexpected.
  - Does not modify the frozen manifest, the audit script, or any frozen artifact.
  - Consumes zero official ransomware run slots.

.PARAMETER PlanOnly
  Availability check only: query MalwareBazaar + VirusTotal metadata, download nothing.

.PARAMETER Rank
  Restrict to specific frozen ranks, e.g. -Rank 1,2,3

.PARAMETER Force
  Re-download even when a hash-verified file is already present.

.PARAMETER AddDefenderExclusion
  Add the intake root to Microsoft Defender exclusions (requires admin).
  Without this, real-time protection may quarantine the ELF samples on write.

.EXAMPLE
  .\DOWNLOAD_UBUNTU_V10_19_SAMPLES.ps1 -PlanOnly

.EXAMPLE
  .\DOWNLOAD_UBUNTU_V10_19_SAMPLES.ps1 -AddDefenderExclusion
#>

[CmdletBinding()]
param(
    [string]$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs",
    [string]$MbKeyFile = "C:\Users\Cyber-01\Desktop\Abuse.ch.txt",
    [string]$VtKeyFile = "C:\Users\Cyber-01\Desktop\VirusTotal.txt",
    [string]$SevenZip = "C:\Program Files\7-Zip\7z.exe",
    [switch]$PlanOnly,
    [switch]$Force,
    [int[]]$Rank,
    [switch]$AddDefenderExclusion,
    [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --------------------------------------------------------------------------
# Frozen paths (identical to AUDIT_UBUNTU_V10_HOST_INTAKE_19_SHA256_V1_1.ps1)
# --------------------------------------------------------------------------
$FrozenManifest = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_MAXIMAL_POOL_20261110_V10_TRULY_FRESH\FROZEN_SELECTION_20261110\UBUNTU_V10_FROZEN_SELECTION_MANIFEST.csv"
$IntakeRoot     = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110\host_archive_intake_all19"
$WorkRoot       = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110\download_work"
$EvidenceRoot   = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_MATERIALIZATION_INTAKE_20261110\download_evidence"
$AuditScript    = Join-Path $Root "01_SHARED\scripts\host\sample_selection\AUDIT_UBUNTU_V10_HOST_INTAKE_19_SHA256_V1_1.ps1"

$MbApi = "https://mb-api.abuse.ch/api/v1/"
$VtApi = "https://www.virustotal.com/api/v3/files"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function Write-Step([string]$Message)  { Write-Host $Message -ForegroundColor Cyan }
function Write-Warn2([string]$Message) { Write-Host $Message -ForegroundColor Yellow }

function Get-ApiKey([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label API key file not found: $Path" }
    $raw = (Get-Content -LiteralPath $Path -Raw).Trim()
    $raw = $raw -replace "^\uFEFF", ""
    $raw = $raw.Trim('"', "'", " ", "`r", "`n", "`t")
    if ($raw -match '[:=]') { $raw = ($raw -split '[:=]')[-1].Trim() }
    if ($raw.Length -lt 16) { throw "$Label API key looks invalid (length $($raw.Length))." }
    return $raw
}

function Save-HttpFile {
    param(
        [string]$Uri, [string]$Method = "Get", [hashtable]$Headers = @{},
        $Body = $null, [string]$OutPath, [int]$TimeoutSec = 300, [int]$MaxAttempts = 4
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $p = @{
                Uri = $Uri; Method = $Method; Headers = $Headers; OutFile = $OutPath
                TimeoutSec = $TimeoutSec; UseBasicParsing = $true; ErrorAction = "Stop"
            }
            if ($null -ne $Body) { $p["Body"] = $Body; $p["ContentType"] = "application/x-www-form-urlencoded" }
            $null = Invoke-WebRequest @p
            return [pscustomobject]@{ ok = $true; status = 200; error = "" }
        }
        catch {
            $status = 0
            try { if ($null -ne $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } } catch { }
            $msg = $_.Exception.Message
            $retryable = ($status -eq 0 -or $status -eq 408 -or $status -eq 429 -or $status -ge 500)
            if ($attempt -lt $MaxAttempts -and $retryable) {
                Start-Sleep -Seconds ([math]::Min(20, [math]::Pow(2, $attempt)))
                continue
            }
            return [pscustomobject]@{ ok = $false; status = $status; error = $msg }
        }
    }
}

function Get-HttpJson {
    param([string]$Uri, [hashtable]$Headers = @{}, $Body = $null, [string]$Method = "Get", [int]$MaxAttempts = 4)
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $p = @{ Uri = $Uri; Method = $Method; Headers = $Headers; TimeoutSec = 120; UseBasicParsing = $true; ErrorAction = "Stop" }
            if ($null -ne $Body) { $p["Body"] = $Body; $p["ContentType"] = "application/x-www-form-urlencoded" }
            $r = Invoke-WebRequest @p
            return [pscustomobject]@{ ok = $true; status = [int]$r.StatusCode; json = ($r.Content | ConvertFrom-Json) }
        }
        catch {
            $status = 0
            try { if ($null -ne $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } } catch { }
            $retryable = ($status -eq 0 -or $status -eq 429 -or $status -ge 500)
            if ($attempt -lt $MaxAttempts -and $retryable) { Start-Sleep -Seconds ([math]::Min(20, [math]::Pow(2, $attempt))); continue }
            return [pscustomobject]@{ ok = $false; status = $status; json = $null }
        }
    }
}

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Find-VerifiedFile([string]$Dir, [string]$ExpectedSha) {
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -File -Recurse -ErrorAction SilentlyContinue)) {
        if ($f.Length -gt 0 -and (Get-Sha256 $f.FullName) -eq $ExpectedSha) { return $f.FullName }
    }
    return $null
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $FrozenManifest -PathType Leaf)) { throw "Frozen manifest missing: $FrozenManifest" }
if (-not (Test-Path -LiteralPath $AuditScript -PathType Leaf))    { throw "Frozen audit script missing: $AuditScript" }
if (-not $PlanOnly -and -not (Test-Path -LiteralPath $SevenZip -PathType Leaf)) {
    throw "7-Zip not found at $SevenZip. MalwareBazaar returns password-protected ZIPs."
}

New-Item -ItemType Directory -Force -Path $IntakeRoot   | Out-Null
New-Item -ItemType Directory -Force -Path $WorkRoot     | Out-Null
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$MbKey = Get-ApiKey $MbKeyFile "MalwareBazaar"
$VtKey = ""
try { $VtKey = Get-ApiKey $VtKeyFile "VirusTotal" } catch { Write-Warn2 "VirusTotal key unusable: $($_.Exception.Message)" }

Write-Step "MalwareBazaar key loaded ($($MbKey.Length) chars)."
if ($VtKey) { Write-Step "VirusTotal key loaded ($($VtKey.Length) chars)." } else { Write-Warn2 "VirusTotal fallback disabled." }

# ---- Defender: warn or opt-in exclusion -----------------------------------
$exclusionAdded = $false
try {
    $mp = Get-MpPreference
    $rtOn = -not [bool]$mp.DisableRealtimeMonitoring
    $exPaths = @($mp.ExclusionPath | Where-Object { $_ })
    $covered = $false
    foreach ($e in $exPaths) {
        if ($IntakeRoot.ToLowerInvariant().StartsWith(([string]$e).ToLowerInvariant())) { $covered = $true }
    }
    if ($rtOn -and -not $covered) {
        if ($AddDefenderExclusion) {
            $isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) { throw "AddDefenderExclusion requires an elevated PowerShell." }
            Add-MpPreference -ExclusionPath $IntakeRoot -ErrorAction Stop
            Add-MpPreference -ExclusionPath $WorkRoot   -ErrorAction Stop
            $exclusionAdded = $true
            Write-Warn2 "Defender exclusions added for intake + work roots."
        }
        else {
            Write-Warn2 ""
            Write-Warn2 "!! Defender real-time protection is ON and does NOT exclude:"
            Write-Warn2 "   $IntakeRoot"
            Write-Warn2 "   Samples may be quarantined on write and hash verification will fail."
            Write-Warn2 "   Re-run with -AddDefenderExclusion (elevated), or add the exclusion manually."
            Write-Warn2 ""
        }
    }
    else { Write-Step "Defender: real-time protection is not a blocker for the intake path." }
}
catch { Write-Warn2 "Defender check skipped: $($_.Exception.Message)" }

# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------
$rows = @(Import-Csv -LiteralPath $FrozenManifest)
if ($rows.Count -ne 19) { throw "Frozen manifest must contain 19 rows (found $($rows.Count))." }
$rows = @($rows | Sort-Object { [int]$_.frozen_rank })

if ($Rank) {
    $rows = @($rows | Where-Object { $Rank -contains [int]$_.frozen_rank })
    if ($rows.Count -eq 0) { throw "No manifest rows matched -Rank $($Rank -join ',')." }
}

$ledger = New-Object System.Collections.Generic.List[object]
$stats = @{ verified = 0; downloaded = 0; already = 0; failed = 0; unavailable = 0; planOnly = 0 }

Write-Step ("Processing {0} of 19 frozen rows. PlanOnly={1} Force={2}" -f $rows.Count, [bool]$PlanOnly, [bool]$Force)
Write-Host ""

foreach ($r in $rows) {
    $rk     = [int]$r.frozen_rank
    $role   = ([string]$r.role).Trim()
    $family = ([string]$r.family).Trim()
    $sha    = ([string]$r.sha256).Trim().ToLowerInvariant()
    $bytes  = [int64]$r.file_size_bytes
    $tag    = "rank {0,2} {1,-16} {2}" -f $rk, $family, $sha.Substring(0, 16)

    $status = ""; $source = ""; $note = ""
    $mbStatus = ""; $mbName = ""; $mbSig = ""
    $vtExists = $false

    # -- existing verified copy? -------------------------------------------
    if (-not $Force) {
        $existing = Find-VerifiedFile $IntakeRoot $sha
        if ($existing) {
            $stats["verified"] = $stats["verified"] + 1
            $stats["already"]  = $stats["already"]  + 1
            $ledger.Add([pscustomobject]@{
                frozen_rank = $rk; role = $role; family = $family; expected_sha256 = $sha
                expected_bytes = $bytes; mb_query_status = "NOT_QUERIED"; mb_file_name = ""; mb_signature = ""
                vt_metadata_exists = ""; source_used = "EXISTING"; status = "PRESENT_VERIFIED"
                actual_sha256 = $sha; actual_bytes = (Get-Item -LiteralPath $existing).Length
                note = "already in intake"; timestamp_utc = [DateTime]::UtcNow.ToString("o")
            })
            Write-Host ("{0}  PRESENT_VERIFIED" -f $tag) -ForegroundColor Green
            continue
        }
    }

    # -- MalwareBazaar availability ---------------------------------------
    $mbHeaders = @{ "Auth-Key" = $MbKey }
    $mbInfo = Get-HttpJson -Uri $MbApi -Headers $mbHeaders -Method "Post" -Body @{ query = "get_info"; hash = $sha }
    if ($mbInfo.ok -and $null -ne $mbInfo.json) {
        $mbStatus = [string]$mbInfo.json.query_status
        if ($mbStatus -eq "ok" -and $mbInfo.json.data) {
            $d = @($mbInfo.json.data)[0]
            if ($d.PSObject.Properties.Name -contains "file_name") { $mbName = [string]$d.file_name }
            if ($d.PSObject.Properties.Name -contains "signature") { $mbSig  = [string]$d.signature }
        }
    }
    else { $mbStatus = "REQUEST_FAILED" }

    # -- VirusTotal metadata (only needed if MB lacks the file) ------------
    if ($mbStatus -ne "ok" -and $VtKey) {
        $vtMeta = Get-HttpJson -Uri ("$VtApi/$sha") -Headers @{ "x-apikey" = $VtKey }
        if ($vtMeta.ok -and $null -ne $vtMeta.json -and $vtMeta.json.data) { $vtExists = $true }
    }

    if ($PlanOnly) {
        $stats["planOnly"] = $stats["planOnly"] + 1
        $ledger.Add([pscustomobject]@{
            frozen_rank = $rk; role = $role; family = $family; expected_sha256 = $sha
            expected_bytes = $bytes; mb_query_status = $mbStatus; mb_file_name = $mbName; mb_signature = $mbSig
            vt_metadata_exists = $vtExists; source_used = "PLAN"; status = "SKIPPED_PLAN_ONLY"
            actual_sha256 = ""; actual_bytes = ""; note = "no bytes downloaded"
            timestamp_utc = [DateTime]::UtcNow.ToString("o")
        })
        $colour = "Yellow"; if ($mbStatus -eq "ok") { $colour = "Green" }
        Write-Host ("{0}  MB={1,-22} VT_meta={2}  {3}" -f $tag, $mbStatus, $vtExists, $mbName) -ForegroundColor $colour
        Start-Sleep -Milliseconds 600
        continue
    }

    $work = Join-Path $WorkRoot ([string]$rk)
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $work | Out-Null

    $finalSha = ""; $finalBytes = 0

    # -- 1) MalwareBazaar download ----------------------------------------
    if ($mbStatus -eq "ok") {
        $zip = Join-Path $work "mb.zip"
        $dl = Save-HttpFile -Uri $MbApi -Headers $mbHeaders -Method "Post" -Body @{ query = "get_file"; sha256_hash = $sha } -OutPath $zip

        if ($dl.ok -and (Test-Path -LiteralPath $zip)) {
            $magic = @(Get-Content -LiteralPath $zip -Encoding Byte -TotalCount 2)
            if ($magic.Count -eq 2 -and $magic[0] -eq 0x50 -and $magic[1] -eq 0x4B) {
                & $SevenZip x $zip "-o$work" "-pinfected" -y 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $hit = Find-VerifiedFile $work $sha
                    if ($hit) {
                        $finalSha = $sha
                        $finalBytes = (Get-Item -LiteralPath $hit).Length
                        $source = "MALWAREBAZAAR"
                    }
                    else { $status = "FAIL_HASH_MISMATCH"; $note = "MB archive extracted but SHA-256 did not match" }
                }
                else { $status = "MB_EXTRACT_FAILED"; $note = "7-Zip exit $LASTEXITCODE" }
            }
            else {
                try {
                    $errObj = Get-Content -LiteralPath $zip -Raw | ConvertFrom-Json
                    $note = "MB get_file: $($errObj.query_status)"
                }
                catch { $note = "MB get_file returned non-ZIP payload" }
                $status = "MB_DOWNLOAD_DECLINED"
            }
        }
        else { $status = "MB_DOWNLOAD_FAILED"; $note = "HTTP $($dl.status) $($dl.error)" }
        Start-Sleep -Milliseconds 800
    }

    # -- 2) VirusTotal download fallback ----------------------------------
    if (-not $finalSha -and $status -ne "FAIL_HASH_MISMATCH") {
        if ($VtKey) {
            $vtOut = Join-Path $work "vt.bin"
            $vt = Save-HttpFile -Uri ("$VtApi/$sha/download") -Headers @{ "x-apikey" = $VtKey } -OutPath $vtOut

            if ($vt.ok -and (Test-Path -LiteralPath $vtOut)) {
                $got = Get-Sha256 $vtOut
                if ($got -eq $sha) {
                    $finalSha = $sha
                    $finalBytes = (Get-Item -LiteralPath $vtOut).Length
                    $source = "VIRUSTOTAL"
                }
                else { $status = "FAIL_HASH_MISMATCH"; $note = "VT payload hash $got" }
            }
            elseif ($vt.status -eq 401 -or $vt.status -eq 403 -or $vt.status -eq 404) {
                if (-not $status) { $status = "UNAVAILABLE_VT_DOWNLOAD_REQUIRES_PREMIUM" }
                $note = (@("VT download HTTP $($vt.status)") + @($note | Where-Object { $_ })) -join "; "
            }
            else {
                if (-not $status) { $status = "VT_DOWNLOAD_FAILED" }
                $note = (@("VT HTTP $($vt.status) $($vt.error)") + @($note | Where-Object { $_ })) -join "; "
            }
        }
        elseif (-not $note) { $note = "no VT key" }
    }

    # -- 3) Finalize -------------------------------------------------------
    if ($finalSha) {
        if ($source -eq "MALWAREBAZAAR") { $src = Find-VerifiedFile $work $sha } else { $src = Join-Path $work "vt.bin" }
        $target = Join-Path $IntakeRoot ("{0}.sample" -f $sha)
        $staged = Join-Path $work ("out_{0}.sample" -f $sha)
        Copy-Item -LiteralPath $src -Destination $staged -Force
        Move-Item -LiteralPath $staged -Destination $target -Force

        if ((Get-Sha256 $target) -ne $sha) {
            Remove-Item -LiteralPath $target -Force
            $status = "FAIL_HASH_MISMATCH"
            $note = "post-write verification failed (Defender quarantine?)"
            $finalSha = ""
            $stats["failed"] = $stats["failed"] + 1
            Write-Warn2 ("{0}  {1}  {2}" -f $tag, $status, $note)
        }
        else {
            $status = "DOWNLOADED_VERIFIED"
            $stats["downloaded"] = $stats["downloaded"] + 1
            $stats["verified"]   = $stats["verified"]   + 1
            Write-Host ("{0}  DOWNLOADED_VERIFIED via {1}  {2:N0} B" -f $tag, $source, $finalBytes) -ForegroundColor Green
        }
    }
    else {
        if (-not $status) {
            if ($mbStatus -ne "ok" -and -not $vtExists) { $status = "UNAVAILABLE_BOTH" } else { $status = "UNAVAILABLE" }
        }
        if ($status -like "FAIL_*") { $stats["failed"] = $stats["failed"] + 1 }
        else { $stats["unavailable"] = $stats["unavailable"] + 1 }
        Write-Warn2 ("{0}  {1}  {2}" -f $tag, $status, $note)
    }

    $ledger.Add([pscustomobject]@{
        frozen_rank = $rk; role = $role; family = $family; expected_sha256 = $sha
        expected_bytes = $bytes; mb_query_status = $mbStatus; mb_file_name = $mbName; mb_signature = $mbSig
        vt_metadata_exists = $vtExists; source_used = $source; status = $status
        actual_sha256 = $(if ($finalSha) { $sha } else { "" })
        actual_bytes = $(if ($finalSha) { $finalBytes } else { "" })
        note = $note; timestamp_utc = [DateTime]::UtcNow.ToString("o")
    })

    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

# --------------------------------------------------------------------------
# Evidence + gate
# --------------------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ledgerPath = Join-Path $EvidenceRoot "UBUNTU_V10_19_DOWNLOAD_LEDGER.csv"
$ledger | Export-Csv -LiteralPath $ledgerPath -NoTypeInformation -Encoding UTF8

$present = @(Get-ChildItem -LiteralPath $IntakeRoot -File -Recurse -ErrorAction SilentlyContinue)
$expectedSet = @{}
foreach ($er in (Import-Csv -LiteralPath $FrozenManifest)) { $expectedSet[([string]$er.sha256).Trim().ToLowerInvariant()] = $true }
$exact = 0; $surplus = @()
foreach ($f in $present) {
    $h = Get-Sha256 $f.FullName
    if ($expectedSet.ContainsKey($h)) { $exact++ } else { $surplus += $f.FullName }
}

$mode = "DOWNLOAD"
if ($PlanOnly) { $mode = "PLAN_ONLY" }

$receipt = [ordered]@{
    schema_version = "1.0"
    timestamp_utc = [DateTime]::UtcNow.ToString("o")
    mode = $mode
    frozen_manifest = $FrozenManifest
    intake_root = $IntakeRoot
    rows_processed = $rows.Count
    exact_expected_hashes_present = $exact
    files_in_intake = $present.Count
    unexpected_files_in_intake = $surplus.Count
    downloaded_now = $stats["downloaded"]
    already_present = $stats["already"]
    unavailable = $stats["unavailable"]
    failed = $stats["failed"]
    defender_exclusion_added = $exclusionAdded
    malware_executed = $false
    vmware_started = $false
    official_run_slot_consumed = $false
    ledger_csv = $ledgerPath
    all_19_ready = ($exact -eq 19 -and $surplus.Count -eq 0)
}
$receiptPath = Join-Path $EvidenceRoot ("UBUNTU_V10_19_DOWNLOAD_RECEIPT_{0}.json" -f $stamp)
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

Write-Host ""
Write-Host ("Exact frozen hashes in intake : {0}/19" -f $exact)
Write-Host ("Files in intake (must be 19)  : {0}" -f $present.Count)
Write-Host ("Unexpected files in intake    : {0}" -f $surplus.Count)
Write-Host ("Ledger  : $ledgerPath")
Write-Host ("Receipt : $receiptPath")
Write-Host ""

if ($surplus.Count -gt 0) {
    Write-Warn2 "Unexpected files present in intake (remove before the frozen audit):"
    $surplus | ForEach-Object { Write-Warn2 "  $_" }
}

# Frozen audit (read-only) as the authoritative gate
$auditExit = $null
if (-not $SkipAudit -and -not $PlanOnly) {
    Write-Step "Running frozen host audit..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $AuditScript | ForEach-Object { Write-Host $_ }
    $auditExit = $LASTEXITCODE
    Write-Host ("Frozen audit exit code: {0}  (0 = PASS_EXACT_19_READY)" -f $auditExit)
}

if ($exact -eq 19 -and $surplus.Count -eq 0) {
    Write-Host ""
    Write-Host "RESULT: 19/19 exact frozen artifacts present. Ready for FINALIZE_UBUNTU_V10_AFTER_19_MATERIALIZED.ps1" -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "RESULT: intake incomplete. 0 official run slots consumed. Stop and report missing ranks." -ForegroundColor Red
exit 2
