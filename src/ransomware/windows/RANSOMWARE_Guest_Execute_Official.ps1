# RANSOMWARE_Guest_Execute_Official.ps1
#
# Windows ransomware guest executor.
# Pattern: follows P5G_R6_R8B_R4_R3_R7_Windows_GuestTelemetry.ps1 structure
# (Set-StrictMode, Assert-True, SHA helper, JSON receipts).
#
# Modes:
#   Prepare   - verify sample hash/bytes/mode, stage sample read-only, stage canary
#               corpus, verify isolation from inside guest
#   Run       - execute sample under bounded observation (60s max), watchdog (90s),
#               kill process tree at deadline, record actual_execution_seconds,
#               then (D-156) apply the bounded post-workload telemetry tail and STOP
#               THE CAPTURE inside the guest, before returning to the host
#   CanaryVerify - re-hash canary corpus after execution, record integrity
#
# D-038: natural early exit is valid (record actual_execution_seconds), no fill-to-60,
# no rerun to fill window.
# D-039: telemetry adapter is Sysmon+Procmon (host-side; guest only records binding).
# D-156: the capture boundary lives HERE (the guest executor), so no lab artefact that
# the malware can delete sits between the sample's exit and the end of the capture; and
# the argument vector is bound to the frozen per-family contract before the launch.
#
# No secrets in script; credentials never passed on command line.
#
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Run','CanaryVerify')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID,
    [Parameter(Mandatory=$true)][string]$ReceiptPath,
    [Parameter(Mandatory=$true)][string]$WorkRoot,
    # D-163: the corpus root is an EXPLICIT parameter, no longer derived from $WorkRoot. The
    # corpus must live outside the sample's own run subtree (the structural cause of 0/236):
    # both families that walk C:\RansomLab skip the subtree that contains their own image, and
    # on Windows that subtree WAS the corpus tree. The root is asserted below, fail-closed.
    [Parameter(Mandatory=$true)][string]$CanaryRoot,
    [Parameter(Mandatory=$true)][string]$RunID,
    [Parameter(Mandatory=$true)][int]$ExecutionOrder,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-R-[0-9]{2}$')][string]$SampleRunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$SampleSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+$')][string]$SampleBytes,
    [Parameter(Mandatory=$true)][string]$SampleGuestPath,
    [Parameter(Mandatory=$true)][ValidateSet('True','False')][string]$ReadOnly,
    [Parameter(Mandatory=$true)][string]$ModeOctal,
    [Parameter(Mandatory=$true)][ValidateSet('TRAIN','VALIDATION','TEST')][string]$Split,
    [Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Repetition,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-R-[0-9]{2}-[AB]$')][string]$ScenarioRunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^R[0-9]{2}-WIN-[AB]$')][string]$FixtureSeed,
    [Parameter(Mandatory=$true)][ValidateSet('RANSOMWARE')][string]$GroundTruth,
    [Parameter(Mandatory=$true)][ValidateSet('MALICIOUS_PRIMARY_SUBJECT')][string]$ProcessDensityRole,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9./\-]+$')][string]$FamilyStratum,
    [Parameter(Mandatory=$true)][ValidateSet('Sysmon+Procmon')][string]$TelemetryAdapter,
    [Parameter(Mandatory=$true)][ValidateSet('zip')][string]$EvidenceArchiveFormat,
    # D-153: the frozen per-sample invocation contract. DIRECT_EXE keeps the original
    # Start-Process semantics; RUNDLL32_EXPORT loads a DLL through its documented export.
    [Parameter(Mandatory=$true)][ValidateSet('DIRECT_EXE','RUNDLL32_EXPORT')][string]$InvocationMode,
    [Parameter(Mandatory=$false)][string]$LoaderPath='',
    [Parameter(Mandatory=$false)][string]$EntryPoint='',
    # D-156: the RESOLVED argument vector actually passed to the sample. It is 'NO_ARGUMENTS'
    # for the nine families whose binary documents no target argument, and the resolved form of
    # the frozen contract template for the family that documents one (Akira: --encryption_path
    # <CANARY>). The contract template itself is passed separately so the guest can prove that
    # the resolved vector is exactly the frozen template with <CANARY> bound to the corpus root.
    [Parameter(Mandatory=$true)][string]$SampleArguments,
    [Parameter(Mandatory=$true)][string]$ArgumentVectorContract,
    # D-156: the telemetry boundary parameters. The post-workload tail and the capture stop are
    # performed INSIDE the guest, by this already-running executor, so that no lab artefact that
    # the malware can delete sits between the sample's exit and the end of the capture.
    [Parameter(Mandatory=$false)][string]$TelemetryCaptureRoot='',
    [Parameter(Mandatory=$false)][string]$ProcmonPath='',
    [int]$PostTailSeconds=10,
    [int]$ObservationWindowSeconds=60,
    [int]$WatchdogSeconds=90
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Script:Stage='INIT'
$Script:AntivirusFallbackUsed=$false
# D-140: the measured values are kept at script scope so the FAIL receipt can carry them.
$Script:ActualSeconds=$null;$Script:SampleRuntimeSeconds=$null;$Script:KillSettleSeconds=$null;$Script:ExitCodeValue=$null
# D-156: the capture-boundary values are kept at script scope so a FAIL receipt can carry them.
$Script:CaptureStopUtc=$null;$Script:PostWorkloadCaptureSeconds=$null;$Script:CaptureStopOverheadSeconds=$null;$Script:CaptureStopStatus='NOT_REQUESTED'
# D-151: the containment outcome is kept at script scope so a FAIL receipt can carry it too.
$Script:JobObjectCreated=$false;$Script:JobObjectAssigned=$false;$Script:JobObjectTerminated=$false
$Script:JobObjectError='';$Script:ExecutorPriorityRaised=$false;$Script:SamplePriorityNormalized=$false

function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Utf8NoBom([string]$Path,[string]$Text){$E=New-Object Text.UTF8Encoding($false);[IO.File]::WriteAllText($Path,$Text,$E)}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};Write-Utf8NoBom $Path (($Object|ConvertTo-Json -Depth 20)+"`r`n")}
function Stage([string]$Name,[string]$Message){$Script:Stage=$Name;Write-Host ('[{0}] {1}' -f $Name,$Message) -ForegroundColor Cyan}

function Test-IsAntivirusBlock([string]$Message) {
    # D-136: recognise the guest antivirus's refusal. The Windows message is "Operation did not
    # complete successfully because the file contains a virus or potentially unwanted software";
    # "Access is denied" is the other way an antivirus filter driver denies a read.
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return (($Message -match 'virus or potentially unwanted software') -or ($Message -match 'Access is denied') -or ($Message -match 'UnauthorizedAccess'))
}
function Read-StagedSampleSha([string]$Path) {
    # D-136: read the staged sample. The controller excludes the guest analysis tree from
    # real-time scanning for the analysis window; this is the fail-safe for the case where the
    # exclusion could not be applied. A non-antivirus error is rethrown untouched.
    try { return (SHA $Path) }
    catch {
        $msg = [string]$_.Exception.Message
        if (-not (Test-IsAntivirusBlock $msg)) { throw }
        $Script:AntivirusFallbackUsed = $true
        Write-Host ('ANTIVIRUS BLOCKED THE READ OF '+$Path+' - disabling real-time protection once as a recorded fallback.') -ForegroundColor Yellow
        try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop }
        catch { throw ('SAMPLE_BLOCKED_BY_ANTIVIRUS:'+$Path+': the fallback failed: '+$_.Exception.Message) }
        Start-Sleep -Seconds 3
        try { return (SHA $Path) }
        catch { throw ('SAMPLE_BLOCKED_BY_ANTIVIRUS:'+$Path+': '+$msg) }
    }
}
function Get-PEImageInfo([string]$Path) {
    # D-153: read the PE header to prove the staged image type matches the frozen invocation
    # contract. A .exe file NAME is not evidence of an executable IMAGE: the WannaCry sample
    # is a DLL (IMAGE_FILE_DLL) and CreateProcess rejects it with ERROR_BAD_EXE_FORMAT.
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $len = [int]$fs.Length
        $buf = New-Object byte[] ([Math]::Min($len, 4096))
        $read = 0
        while ($read -lt $buf.Length) {
            $n = $fs.Read($buf, $read, $buf.Length - $read)
            if ($n -le 0) { break }
            $read += $n
        }
    } finally { $fs.Dispose() }
    $info = [ordered]@{ is_pe = $false; is_dll = $false; machine = ''; optional_magic = '' }
    if ($read -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return [pscustomobject]$info }
    $e = [BitConverter]::ToInt32($buf, 0x3C)
    if ($e -lt 0 -or ($e + 24) -gt $read) { return [pscustomobject]$info }
    if ($buf[$e] -ne 0x50 -or $buf[$e+1] -ne 0x45 -or $buf[$e+2] -ne 0 -or $buf[$e+3] -ne 0) { return [pscustomobject]$info }
    $coff = $e + 4
    $machine = [BitConverter]::ToUInt16($buf, $coff)
    $chars = [BitConverter]::ToUInt16($buf, $coff + 18)
    $opt = $coff + 20
    $magic = if (($opt + 2) -le $read) { [BitConverter]::ToUInt16($buf, $opt) } else { 0 }
    $info.is_pe = $true
    $info.is_dll = [bool]($chars -band 0x2000)
    $info.machine = ('0x{0:X4}' -f $machine)
    $info.optional_magic = $(if ($magic -eq 0x020b) { 'PE32+' } elseif ($magic -eq 0x010b) { 'PE32' } else { ('0x{0:X4}' -f $magic) })
    return [pscustomobject]$info
}

function Assert-InvocationContract {
    # D-153: the launch contract is closed. Only the two qualified modes are accepted, and a DLL
    # contract must name the system loader and a non-empty export.
    # D-156: the ARGUMENT VECTOR is now per family, but it is still CLOSED: it must be exactly
    # the frozen contract template with <CANARY> bound to this run's corpus root. Nothing can be
    # invented at run time - an argument that is not the frozen template fails before the sample
    # is started.
    if ($InvocationMode -ceq 'DIRECT_EXE') {
        Assert-True ([string]::IsNullOrEmpty($LoaderPath)) 'INVOCATION_DIRECT_HAS_LOADER'
        Assert-True ([string]::IsNullOrEmpty($EntryPoint)) 'INVOCATION_DIRECT_HAS_ENTRY_POINT'
    } elseif ($InvocationMode -ceq 'RUNDLL32_EXPORT') {
        Assert-True ($LoaderPath -match '^C:\\Windows\\System32\\rundll32\.exe$') ('INVOCATION_LOADER_NOT_FROZEN:'+$LoaderPath)
        Assert-True ($EntryPoint -match '^[A-Za-z_][A-Za-z0-9_@?$]{0,127}$') ('INVOCATION_ENTRY_POINT_INVALID:'+$EntryPoint)
    } else {
        throw ('INVOCATION_MODE_UNKNOWN:'+$InvocationMode)
    }
    Assert-True ($ArgumentVectorContract -match '^(NO_ARGUMENTS|--[a-z0-9_]+ <CANARY>)$') ('ARGUMENT_VECTOR_CONTRACT_NOT_FROZEN:'+$ArgumentVectorContract)
}

function Assert-CanaryExposureRoot {
    # D-163: the corpus root is fixed by the frozen exposure rule and is STRUCTURALLY SEPARATE
    # from the sample's own run subtree. Both conditions are fail-closed: no future edit can
    # silently restore the D-156/D-163 geometry (corpus inside <WorkRoot>, which is the subtree
    # every family that walks C:\RansomLab demonstrates that it skips).
    Assert-True (-not [string]::IsNullOrWhiteSpace($CanaryRoot)) 'CANARY_ROOT_REQUIRED'
    Assert-True ($CanaryRoot -match '^C:\\RansomLab\\Canary\\[A-Za-z0-9_]+$') ('CANARY_ROOT_NOT_THE_FROZEN_EXPOSURE_ROOT:'+$CanaryRoot)
    Assert-True (-not ($CanaryRoot -match '\s')) 'CANARY_ROOT_CONTAINS_WHITESPACE'
    Assert-True ($CanaryRoot -notmatch '[\\/]$') ('CANARY_ROOT_HAS_TRAILING_SEPARATOR:'+$CanaryRoot)
    $wr=[IO.Path]::GetFullPath($WorkRoot).TrimEnd('\')
    $cr=[IO.Path]::GetFullPath($CanaryRoot).TrimEnd('\')
    Assert-True (-not $cr.Equals($wr,[StringComparison]::OrdinalIgnoreCase)) 'CANARY_ROOT_EQUALS_WORK_ROOT'
    Assert-True (-not $cr.StartsWith($wr+'\',[StringComparison]::OrdinalIgnoreCase)) ('CANARY_ROOT_OUTSIDE_WORK_ROOT:corpus='+$cr+':workroot='+$wr)
}

function Resolve-ArgumentVector {
    # D-156: bind the frozen contract template to this run's corpus root. The resolution is
    # deterministic and is re-proved here (the guest does not trust the host's string).
    param([string]$CanaryRoot)
    Assert-True (-not [string]::IsNullOrWhiteSpace($CanaryRoot)) 'CANARY_ROOT_REQUIRED_FOR_ARGUMENT_RESOLUTION'
    $expected = ($ArgumentVectorContract -replace '<CANARY>', $CanaryRoot)
    Assert-True ($SampleArguments -ceq $expected) ('ARGUMENT_VECTOR_DOES_NOT_MATCH_THE_FROZEN_CONTRACT:expected=' + $expected + ':actual=' + $SampleArguments)
    $tokens = @()
    if ($ArgumentVectorContract -ne 'NO_ARGUMENTS') {
        $tokens = @($SampleArguments -split '\s+' | Where-Object { $_ -ne '' })
        Assert-True ($tokens.Count -eq 2) ('ARGUMENT_VECTOR_TOKEN_COUNT_NOT_2:' + $tokens.Count)
        # The corpus root is a lab path with no spaces; an argument that needed quoting would be
        # a different (invented) invocation, so it is rejected rather than silently quoted.
        Assert-True (-not ($CanaryRoot -match '\s')) 'CANARY_ROOT_CONTAINS_WHITESPACE'
        Assert-True ($tokens[1] -ceq $CanaryRoot) ('ARGUMENT_VECTOR_TARGET_IS_NOT_THE_CORPUS:' + $tokens[1])
    } else {
        Assert-True ($SampleArguments -ceq 'NO_ARGUMENTS') ('ARGUMENT_VECTOR_NOT_NO_ARGUMENTS:' + $SampleArguments)
    }
    return $tokens
}

function Verify-Isolation {
    # D-038/D-039: verify from inside guest that network is host-only, no egress.
    $def4 = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'})
    $def6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -eq '::/0'})
    Assert-True ($def4.Count -eq 0) ('ISOLATION_IPV4_DEFAULT_ROUTE:'+ $def4.Count)
    Assert-True ($def6.Count -eq 0) ('ISOLATION_IPV6_DEFAULT_ROUTE:'+ $def6.Count)
    # Confirm no external host reachable (DNS sinkhole): attempt a quick connect to a non-routable sinkhole.
    $sink = New-Object System.Net.Sockets.TcpClient
    try { $result = $sink.BeginConnect('10.255.255.1', 53, $null, $null); $ok = $result.AsyncWaitHandle.WaitOne(1500, $false); $sink.EndConnect($result) } catch { $ok = $false }
    $sink.Close()
    Assert-True (-not $ok) 'ISOLATION_EXTERNAL_REACHABLE'
}

function New-SampleJobObject {
    # D-151: a kernel Job Object contains the sample AND every descendant it spawns. The previous
    # teardown walked the process table from the ROOT PID with WMI and Stop-Process. On
    # 2026-11-13 (OpnKey, RAN_WIN_05_A) that walk killed the root but left an orphaned descendant
    # running; it kept the guest saturated until VMware Tools timed out and the VIX launch job
    # returned VIX_E_TOOLS_NOT_RUNNING (3016). The job is a containment/kill mechanism only - it
    # does not change the 60 s observation window, the 90 s watchdog or anything that is measured.
    if (-not ('RansomLabSampleJob' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RansomLabSampleJob {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@ -ErrorAction Stop
    }
    return [RansomLabSampleJob]::CreateJobObject([IntPtr]::Zero, $null)
}

function New-CanaryCorpus {
    param([string]$CanaryRoot, [string]$ManifestPath, [int]$Count)
    # D-132: the FROZEN common canary corpus (Corpus V2, FROZEN_CANARY_CORPUS_20261111.json,
    # sha 9d2b1685fa28b07a1408c0d80d4ae85ff642c5e8e9a30ee081ca541e22230d47): 236 files, ONE PER
    # DOCUMENTED TARGET EXTENSION, canary_%03d.<ext>, sizes cycling 256 KiB / 1 MiB / 4 MiB, every
    # fifth file in nested\, deterministic content (sha256('P5G_RANSOMWARE_CANARY_V1_%03d' % i)
    # repeated and truncated). The previous placeholder (25 x canary_NNN.dat, 16 KiB, no extensions)
    # was NOT the frozen methodology and left the extension-targeted samples with zero targets.
    # The manifest FORMAT is unchanged, so Verify-CanaryCorpus is untouched.
    #
    # D-156 (the 0/236 ROOT CAUSE): the corpus FILES are staged WITHOUT the Windows read-only
    # attribute, and the hash manifest is written OUTSIDE the corpus directory.
    #   (a) The read-only attribute was a mechanical Windows port of the POSIX mode 0444 and it is
    #       NOT semantically equivalent: on POSIX a read-only file is still renamed/unlinked when
    #       the DIRECTORY is writable (which is why the frozen Ubuntu half lost 235 of its 236
    #       canaries - the corpus was reached and destroyed), while on Windows a read-only file
    #       is a skip signal for the families that stat the attributes before opening a file.
    #       The D-156 PML probe proves it: GreenBlood encrypted 6973 files under C:\RansomLab
    #       (the corpus's own parent tree), with .txt/.csv/.json/.py originals that are all corpus
    #       extensions, yet NOT ONE of the 236 read-only corpus files - the only structural
    #       difference between them and the files beside them was the read-only attribute.
    #       A read-only corpus made the Windows canary measurement impossible BY CONSTRUCTION.
    #   (b) The manifest moves outside the corpus directory, exactly as the frozen Ubuntu half
    #       does (D-043: "the hash manifest lives OUTSIDE the encrypted/canary scope ... so a
    #       working ransomware encrypting $RUNROOT/Canary cannot destroy it before
    #       canary_verify"). With a reachable corpus the in-directory manifest WOULD be destroyed.
    # The corpus IDENTITY is unchanged: the same 236 names, the same sizes, the same deterministic
    # content and the same SHA-256 values as the frozen Ubuntu Corpus V2.
    $exts = @('accdb','aif','ani','asm','asp','avhd','avi','avoslinux','back','bak','bat','bitmap','bmp','bmxz','build','bundle','cab','cache','cad','cc','cdr','cer','cerror','cfg','cmd','conf','conti','cpl','cpp','crt','crypt','cs','css','csv','ctl','cur','curbrk','cxx','data','dbf','debf','debh','der','diagcab','diagpkg','dib','disk','dll','doc','docx','dqf','drv','dwg','dwph','emario','eml','encrptd','encryp','env','eot','exe','fdb','frm','gif','gnu','gzip','hck','hlp','icl','icns','ico','ics','idb','idx','ifire','img','ini','interlock','iso','jar','java','jfif','jpe','jpeg','jpg','jsp','kdbx','key','lbn','llm','llvmbc','lmario','lnk','log','lpb','mail','map','mario','mdb','mht','mhtml','minbrk','mmario','mod','mov','mpa','mpg','msc','msg','msp','msstyles','msu','mui','myd','myi','ncp','nmario','nomedia','note','nrg','nvram','ocx','odc','odf','odg','odi','odm','odp','ods','odt','opd','opt','ora','ost','ova','ovf','pack','pdf','pem','pfx','php','pid','pif','pmam','pmf','png','ppt','pptx','prf','property','psd','pst','py','pyc','qcow','qrx','rar','raw','rb','rdfxb','rel','rev','rm','rnd','ro','rtf','rtp','run','sample','scr','sh','shs','so','spl','sql','svg','swf','sys','tar','theme','themepack','tib','tif','tiff','tjh','tmp','tri','tth','txt','uel','unh','url','uul','vb','vbk','vbm','vbox','vbs','vcb','vdi','vfd','vhd','vhdx','vib','vmc','vmdk','vmem','vmsd','vmsn','vmss','vmtm','vmx','vmxf','vsdx','vsv','vswp','vue','war','wav','wmario','wmf','wmv','woff','work','wps','xls','xlsm','xlsx','xlt','xltm','xltx','xml','xmlb','xvd','zip','zipu')
    $sizes = @(262144, 1048576, 4194304)
    $nestedEvery = 5
    $hashes = [ordered]@{}
    1..$Count | ForEach-Object {
        $i = $_
        $ext = $exts[($i - 1) % $exts.Count]
        $size = $sizes[($i - 1) % $sizes.Count]
        $name = 'canary_{0:D3}.{1}' -f $i, $ext
        $rel = if (($i % $nestedEvery) -eq 0) { 'nested\' + $name } else { $name }
        $path = Join-Path $CanaryRoot $rel
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $seed = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(('P5G_RANSOMWARE_CANARY_V1_{0:D3}' -f $i)))
        # the content is the 32-byte seed repeated and truncated to the size (every size is a multiple of 32)
        $block = New-Object byte[] $size
        $chunk = New-Object byte[] 32000
        for ($k = 0; $k -lt 1000; $k++) { [Array]::Copy($seed, 0, $chunk, $k * 32, 32) }
        $pos = 0
        while (($pos + $chunk.Length) -le $size) { [Array]::Copy($chunk, 0, $block, $pos, $chunk.Length); $pos += $chunk.Length }
        if ($pos -lt $size) { [Array]::Copy($chunk, 0, $block, $pos, ($size - $pos)) }
        [IO.File]::WriteAllBytes($path, $block)
        # D-156: explicitly NORMAL attributes. The file is a MEASUREMENT TARGET and must be
        # reachable by a working ransomware; the read-only attribute is not part of the frozen
        # corpus identity (the name, size, content and hash are).
        (Get-Item -LiteralPath $path).Attributes = [IO.FileAttributes]::Normal
        $hashes[$rel] = (SHA $path)
    }
    $manifestDir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $manifestDir)) { New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null }
    Write-Json $ManifestPath ([ordered]@{count=$Count; algorithm='SHA-256'; files=$hashes; generated_utc=[DateTime]::UtcNow.ToString('o')})
    return @($hashes.Keys | Sort-Object)
}

function Verify-CanaryCorpus {
    param([string]$CanaryRoot, [string]$ManifestPath)
    Assert-True (Test-Path -LiteralPath $ManifestPath -PathType Leaf) ('CANARY_HASH_MANIFEST_MISSING:'+$ManifestPath)
    $expected = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    # D-163: a MISSING/renamed canary and a CONTENT change are different observations and are
    # recorded separately. Neither is a gate (canary modification is not a pass/fail condition).
    $mismatches = @()
    $missing = @()
    $hashMismatches = @()
    foreach ($name in @($expected.files.PSObject.Properties.Name)) {
        $path = Join-Path $CanaryRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $mismatches += $name; $missing += $name; continue }
        $actual = (SHA $path)
        if ($actual -cne $expected.files.$name) { $mismatches += $name; $hashMismatches += $name }
    }
    return [ordered]@{total=$expected.count; checked=@($expected.files.PSObject.Properties.Name).Count; mismatches=@($mismatches); missing=@($missing); hash_mismatches=@($hashMismatches); all_intact=($mismatches.Count -eq 0)}
}

try {
    Assert-InvocationContract
    Assert-CanaryExposureRoot
    if ($Mode -eq 'Prepare') {
        Stage 'PREPARE' ('Verify sample '+ $SampleRunId +' and stage read-only + canary corpus')
        # G1: sample hash/bytes/mode verification (re-verify in guest)
        Assert-True (Test-Path -LiteralPath $SampleGuestPath -PathType Leaf) ('SAMPLE_SOURCE_MISSING:'+ $SampleGuestPath)
        $actualSha = (SHA $SampleGuestPath).ToLowerInvariant()
        Assert-True ($actualSha -ceq $SampleSha256.ToLowerInvariant()) ('SAMPLE_SHA256_DRIFT:'+ $actualSha)
        $actualBytes = [int64](Get-Item -LiteralPath $SampleGuestPath).Length
        Assert-True ($actualBytes -eq [int64]$SampleBytes) ('SAMPLE_BYTES_DRIFT:'+ $actualBytes)
        Assert-True ([string]$ReadOnly -ceq 'True') ('SAMPLE_NOT_READ_ONLY_SOURCE')

        # Create unique per-run work root (the SAMPLE tree only)
        $sampleRoot = Join-Path $WorkRoot 'Sample'
        # D-163: the corpus root is the explicit, frozen exposure root - NOT a child of the
        # sample's own run subtree. It must start empty: after a snapshot revert it does not
        # exist, and a leftover from an interrupted attempt is purged so that the 236-file
        # assertion describes THIS run.
        $canaryRoot = $CanaryRoot
        New-Item -ItemType Directory -Path $sampleRoot -Force | Out-Null
        $canaryPurged = $false
        if (Test-Path -LiteralPath $canaryRoot) { Remove-Item -LiteralPath $canaryRoot -Recurse -Force; $canaryPurged = $true }
        New-Item -ItemType Directory -Path $canaryRoot -Force | Out-Null

        # Stage sample read-only (never the production staging path).
        # Staged as .exe: Windows ShellExecute resolves the executable by extension,
        # and the frozen T-004 qualified launcher used the same convention.
        $stagedSample = Join-Path $sampleRoot ($SampleSha256 + '.exe')
        Copy-Item -LiteralPath $SampleGuestPath -Destination $stagedSample -Force
        Set-ItemProperty -Path $stagedSample -Name IsReadOnly -Value $true
        Assert-True ((Get-Item -LiteralPath $stagedSample).IsReadOnly) 'STAGED_SAMPLE_NOT_READ_ONLY'

        # D-153: the frozen contract must match the IMAGE, not the staging extension.
        $pe = Get-PEImageInfo -Path $stagedSample
        Assert-True ([bool]$pe.is_pe) 'STAGED_SAMPLE_NOT_PE'
        if ($InvocationMode -ceq 'RUNDLL32_EXPORT') { Assert-True ([bool]$pe.is_dll) 'INVOCATION_CONTRACT_DLL_EXPECTED' }
        else { Assert-True (-not [bool]$pe.is_dll) 'INVOCATION_CONTRACT_EXE_EXPECTED' }

        # Stage canary corpus (pre-hashed decoy files)
        # D-132: the FROZEN common corpus is 236 files (Corpus V2), not the 25-file placeholder.
        # D-156: the files are writable (a reachable measurement target) and the hash manifest is
        # written OUTSIDE the corpus directory (the frozen Ubuntu D-043 pattern), so a working
        # ransomware that reaches the corpus cannot destroy the reference before the verification.
        $canaryManifestPath = Join-Path $WorkRoot 'canary_hashes.json'
        $canaryFiles = New-CanaryCorpus -CanaryRoot $canaryRoot -ManifestPath $canaryManifestPath -Count 236
        Assert-True ($canaryFiles.Count -eq 236) 'CANARY_CORPUS_SIZE_MISMATCH'
        # D-156: the corpus is a MEASUREMENT TARGET - it must be reachable. The attribute is
        # asserted here so a future change cannot silently re-arm the D-156 root cause.
        $readOnlyCanaries = @($canaryFiles | Where-Object { (Get-Item -LiteralPath (Join-Path $canaryRoot $_)).IsReadOnly })
        Assert-True ($readOnlyCanaries.Count -eq 0) ('CANARY_CORPUS_FILES_ARE_READ_ONLY:' + $readOnlyCanaries.Count)
        # D-156: the manifest is OUTSIDE the corpus directory.
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $canaryRoot 'canary_hashes.json'))) 'CANARY_MANIFEST_INSIDE_CORPUS_DIRECTORY'

        # D-156: bind the frozen argument-vector contract to this run's corpus root.
        $argvTokens = Resolve-ArgumentVector -CanaryRoot $canaryRoot

        # G4: isolation verified from inside guest
        Verify-Isolation

        $receipt = [ordered]@{
            schema_version='1.0';gate='RANSOMWARE_GUEST_PREPARE';status='PASS';AttemptID=$AttemptID;RunID=$RunID;ExecutionOrder=$ExecutionOrder
            sample_run_id=$SampleRunId;family_stratum=$FamilyStratum;split=$Split;repetition=$Repetition
            scenario_run_id=$ScenarioRunId;fixture_seed=$FixtureSeed;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole
            sample_sha256=$SampleSha256;sample_bytes=$SampleBytes;sample_guest_path=$SampleGuestPath;sample_staged_path=$stagedSample
            invocation_mode=$InvocationMode;loader_path=$LoaderPath;entry_point=$EntryPoint;sample_arguments=$SampleArguments
            argument_vector_contract=$ArgumentVectorContract;sample_argument_tokens=@($argvTokens);sample_argument_count=@($argvTokens).Count
            target_mechanism=$(if($ArgumentVectorContract -ceq 'NO_ARGUMENTS'){'DOCUMENTED_SCOPE_NO_EXPLICIT_TARGET'}else{'EXPLICIT_DOCUMENTED_SWITCH'})
            corpus_files_read_only=$false;corpus_manifest_outside_corpus=$true;corpus_manifest_path=$canaryManifestPath
            sample_image_dll=$pe.is_dll;sample_pe_machine=$pe.machine;sample_pe_magic=$pe.optional_magic
            read_only=$ReadOnly;mode_octal=$ModeOctal;telemetry_adapter=$TelemetryAdapter;evidence_archive_format=$EvidenceArchiveFormat
            isolation_verified=$true;canary_staged=$true;canary_count=$canaryFiles.Count;canary_root=$canaryRoot
            canary_root_outside_work_root=$true;canary_root_purged=$canaryPurged;canary_manifest_inside_corpus=$false
            ransomware_executed=$false;telemetry_started=$false;network_used=$false;sample_root_written=$false;timestamp=[DateTime]::UtcNow.ToString('o')
        }
        Write-Json $ReceiptPath $receipt
        Write-Host ('RANSOMWARE_GUEST_PREPARE=PASS SAMPLE='+ $SampleRunId +' SHA256='+ $SampleSha256.Substring(0,16)+' BYTES='+ $SampleBytes +' CANARY_COUNT='+ $canaryFiles.Count) -ForegroundColor Green
        exit 0
    }

    if ($Mode -eq 'Run') {
        Stage 'RUN' ('Execute sample '+ $SampleRunId +' under bounded observation: '+ $ObservationWindowSeconds +'s max, watchdog '+ $WatchdogSeconds +'s')
        $sampleRoot = Join-Path $WorkRoot 'Sample'
        # D-163: the SAME explicit exposure root the PREPARE stage populated. It is NOT derived
        # from $WorkRoot; Assert-CanaryExposureRoot (top of script) already re-proved that it is
        # outside the sample's own run subtree in THIS mode too.
        $canaryRoot = $CanaryRoot
        Assert-True (Test-Path -LiteralPath $canaryRoot -PathType Container) ('CANARY_ROOT_MISSING_AT_RUN:'+$canaryRoot)
        $stagedSample = Join-Path $sampleRoot ($SampleSha256 + '.exe')
        Assert-True (Test-Path -LiteralPath $stagedSample -PathType Leaf) 'STAGED_SAMPLE_MISSING'
        # D-136: the read is antivirus-aware; an antivirus block becomes a specific, recorded
        # failure instead of a generic crash that destroys the series.
        $stagedSha = (Read-StagedSampleSha -Path $stagedSample).ToLowerInvariant()
        Assert-True ($stagedSha -ceq $SampleSha256.ToLowerInvariant()) 'STAGED_SAMPLE_SHA_DRIFT'
        # D-153: re-prove the image type at execution time. A contract/image mismatch fails
        # BEFORE the loader is started, so a wrong mode cannot produce a misleading exit code.
        $pe = Get-PEImageInfo -Path $stagedSample
        Assert-True ([bool]$pe.is_pe) 'STAGED_SAMPLE_NOT_PE'
        if ($InvocationMode -ceq 'RUNDLL32_EXPORT') { Assert-True ([bool]$pe.is_dll) 'INVOCATION_CONTRACT_DLL_EXPECTED' }
        else { Assert-True (-not [bool]$pe.is_dll) 'INVOCATION_CONTRACT_EXE_EXPECTED' }

        function Kill-ProcessTree([int]$ProcessId) {
            # D-141: the teardown is FAST and still complete. The previous implementation
            # queried the process table ONCE PER LEVEL (a WMI round trip per node), which for a
            # wide tree cost ~9 s of the run's wall time - the lab's own overhead, charged to
            # the sample, and the reason the recorded durations exceeded the 65 s band
            # (GreenBlood 69.137 s, OpnKey 65.364 s). Now ONE snapshot per round, the tree is
            # walked depth-first so children are killed before their parent (the original
            # semantics), and the rounds repeat (bounded) until no descendant survives, so a
            # process spawned during the teardown is still killed.
            for ($round = 1; $round -le 5; $round++) {
                $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
                $byParent = @{}
                foreach ($p in $all) {
                    $pp = [int]$p.ParentProcessId
                    if (-not $byParent.ContainsKey($pp)) { $byParent[$pp] = New-Object System.Collections.ArrayList }
                    [void]$byParent[$pp].Add([int]$p.ProcessId)
                }
                $ordered = New-Object System.Collections.ArrayList
                $collect = {
                    param([int]$Id)
                    if ($byParent.ContainsKey($Id)) { foreach ($cid in @($byParent[$Id])) { & $collect $cid } }
                    [void]$ordered.Add($Id)
                }
                & $collect $ProcessId
                foreach ($id in @($ordered.ToArray())) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
                Start-Sleep -Milliseconds 200
                $targets = @($ordered.ToArray())
                $alive = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $targets -contains [int]$_.ProcessId })
                if ($alive.Count -eq 0) { break }
            }
        }

        # D-151: create the containment job BEFORE the sample can spawn. The job is created
        # best-effort: if the kernel object cannot be created, the legacy bounded tree walk is
        # still used and the receipt records the containment error.
        $jobHandle = [IntPtr]::Zero
        $jobAssigned = $false
        $jobTerminated = $false
        $jobError = ''
        try {
            $jobHandle = New-SampleJobObject
            if ($jobHandle -eq [IntPtr]::Zero) { throw ('CreateJobObject failed: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        } catch {
            $jobError = [string]$_.Exception.Message
            $jobHandle = [IntPtr]::Zero
        }
        $Script:JobObjectCreated = ($jobHandle -ne [IntPtr]::Zero)

        # D-038: bounded observation window. Start WITHOUT -Wait so the 60 s ceiling is real;
        # natural early exit is valid and is recorded as-is (no fill-to-60, no rerun).
        $startUtc = [DateTime]::UtcNow
        # D-136: an antivirus block on the LAUNCH is reported specifically.
        # D-153: the launch follows the FROZEN per-sample invocation contract. DIRECT_EXE keeps the
        # original semantics; RUNDLL32_EXPORT loads the DLL through its documented export, because
        # CreateProcess cannot load an IMAGE_FILE_DLL image (ERROR_BAD_EXE_FORMAT).
        $rootProcessPath = $stagedSample
        $loaderArguments = ''
        $stagedSampleLaunched = $true
        # D-156: the argument vector is bound to the frozen contract and re-proved here, in the
        # guest, before the sample is started. A vector that is not the frozen template fails
        # BEFORE the launch, so no run can ever use an invented argument.
        $argvTokens = Resolve-ArgumentVector -CanaryRoot $canaryRoot
        try {
            if ($InvocationMode -ceq 'RUNDLL32_EXPORT') {
                Assert-True (Test-Path -LiteralPath $LoaderPath -PathType Leaf) ('INVOCATION_LOADER_MISSING:'+$LoaderPath)
                $rootProcessPath = $LoaderPath
                $loaderArguments = '"' + $stagedSample + '",' + $EntryPoint
                $stagedSampleLaunched = $false
                $proc = Start-Process -FilePath $LoaderPath -ArgumentList $loaderArguments -WorkingDirectory $sampleRoot -PassThru -ErrorAction Stop
            } elseif (@($argvTokens).Count -gt 0) {
                # D-156: the documented explicit target (Akira: --encryption_path <CANARY>).
                $proc = Start-Process -FilePath $stagedSample -ArgumentList $argvTokens -WorkingDirectory $sampleRoot -PassThru -ErrorAction Stop
            } else {
                $proc = Start-Process -FilePath $stagedSample -WorkingDirectory $sampleRoot -PassThru -ErrorAction Stop
            }
        } catch {
            $launchMsg = [string]$_.Exception.Message
            if (Test-IsAntivirusBlock $launchMsg) { throw ('SAMPLE_LAUNCH_BLOCKED_BY_ANTIVIRUS:'+$rootProcessPath+': '+$launchMsg) }
            throw
        }
        $rootPid = [int]$proc.Id
        # D-151: assign IMMEDIATELY. Every child created after this point inherits the job, so the
        # teardown cannot leave a reparented or respawned descendant behind.
        if ($jobHandle -ne [IntPtr]::Zero) {
            try {
                if ([RansomLabSampleJob]::AssignProcessToJobObject($jobHandle, $proc.Handle)) { $jobAssigned = $true }
                else { $jobError = 'AssignProcessToJobObject failed: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            } catch { $jobError = [string]$_.Exception.Message }
        }
        $Script:JobObjectAssigned = $jobAssigned
        # D-151: the sample must NOT inherit the executor's priority. Normalize the SAMPLE first,
        # then raise the EXECUTOR, so only the watchdog/teardown is scheduled ahead of the sample.
        # This changes scheduling only: the 60 s window and the 90 s watchdog are untouched.
        $samplePriorityNormalized = $false
        try {
            $proc.PriorityClass = [Diagnostics.ProcessPriorityClass]::Normal
            $samplePriorityNormalized = $true
        } catch { }
        $Script:SamplePriorityNormalized = $samplePriorityNormalized
        $priorityRaised = $false
        try {
            [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::High
            $priorityRaised = $true
        } catch { }
        $Script:ExecutorPriorityRaised = $priorityRaised
        $Script:JobObjectError = $jobError
        $processTreeKilled = $false
        $exited = $proc.WaitForExit([int]($ObservationWindowSeconds * 1000))
        if (-not $exited) {
            $processTreeKilled = $true
            # D-151: the kernel terminates the WHOLE tree in one operation. The legacy walk stays
            # as a bounded fallback for any child created before the assignment race.
            if ($jobHandle -ne [IntPtr]::Zero -and $jobAssigned) {
                try {
                    $jobTerminated = [RansomLabSampleJob]::TerminateJobObject($jobHandle, [uint32]::MaxValue)
                    if (-not $jobTerminated) { $jobError = 'TerminateJobObject failed: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error() }
                } catch { $jobError = [string]$_.Exception.Message }
            }
            $Script:JobObjectTerminated = $jobTerminated
            $Script:JobObjectError = $jobError
            Kill-ProcessTree $rootPid
            $null = $proc.WaitForExit([int]($WatchdogSeconds * 1000))
        }
        $stopUtc = [DateTime]::UtcNow
        if ($jobHandle -ne [IntPtr]::Zero) {
            try { [void][RansomLabSampleJob]::CloseHandle($jobHandle) } catch { }
            $jobHandle = [IntPtr]::Zero
        }
        $actualSeconds = ($stopUtc - $startUtc).TotalSeconds
        $exitCode = -1
        try { if ($proc.HasExited) { $exitCode = [int]$proc.ExitCode } } catch { $exitCode = -1 }

        # D-140: the SAMPLE's own observable runtime is separated from the LAB's kill/settle
        # overhead. The wall time above ends when the process actually EXITED, which for a
        # watchdog-killed sample includes the time the teardown took - on 2026-11-13 the
        # GreenBlood run (W-R-04) took ~10.8 s to die after the deadline, so the lab's own
        # overhead was attributed to the sample and the run was rejected (70.7613358s > 60s).
        # The observation window bounds the SAMPLE's run; the teardown after the deadline is
        # the lab's and is bounded by the WATCHDOG BUDGET instead.
        $deadlineUtc = $startUtc.AddSeconds($ObservationWindowSeconds)
        $killSettleSeconds = 0.0
        $sampleRuntimeSeconds = $actualSeconds
        if ($processTreeKilled) {
            $killSettleSeconds = ($stopUtc - $deadlineUtc).TotalSeconds
            if ($killSettleSeconds -lt 0) { $killSettleSeconds = 0 }
            $sampleRuntimeSeconds = ($deadlineUtc - $startUtc).TotalSeconds
        }
        $Script:ActualSeconds=$actualSeconds
        $Script:SampleRuntimeSeconds=$sampleRuntimeSeconds
        $Script:KillSettleSeconds=$killSettleSeconds
        $Script:ExitCodeValue=$exitCode
        Assert-True ($sampleRuntimeSeconds -le ($ObservationWindowSeconds + 5)) ('SAMPLE_EXCEEDED_OBSERVATION_WINDOW:'+ $sampleRuntimeSeconds +'s > '+ $ObservationWindowSeconds+'s')
        Assert-True ($killSettleSeconds -le $WatchdogSeconds) ('KILL_SETTLE_EXCEEDED_WATCHDOG_BUDGET:'+ $killSettleSeconds +'s > '+ $WatchdogSeconds+'s')

        $exitCodeSource = $(if($processTreeKilled){'WATCHDOG_KILL'}else{'PROCESS_EXITCODE'})
        $terminationMode = $(if($processTreeKilled){'OBSERVATION_WINDOW_KILL'}else{'NATURAL_EXIT'})
        # D-139: classify the exit code. On Windows a process that dies from an unhandled
        # exception or a fast-fail exits with its NTSTATUS (0xC0000409 = STATUS_STACK_BUFFER_
        # OVERRUN, 0xC0000005 = STATUS_ACCESS_VIOLATION), which as a signed int32 is NEGATIVE.
        # That is a legitimate behavioural observation - D-038 already says a natural early exit
        # is valid and is recorded as-is - so it is CLASSIFIED and recorded here, never rejected.
        $exitCodeUnsigned = ([int64]$exitCode -band 0xFFFFFFFFL)
        $exitCodeHex = '0x' + $exitCodeUnsigned.ToString('X8')
        $exitCodeClass = 'NORMAL'
        if ($processTreeKilled) { $exitCodeClass = 'WATCHDOG_KILL' }
        elseif ($exitCode -lt 0) { $exitCodeClass = 'WINDOWS_NTSTATUS_CRASH' }

        # ---------------------------------------------------------------------------------------
        # D-156: THE CAPTURE BOUNDARY.
        # The bounded post-workload telemetry tail and the STOP CAPTURE are performed HERE, inside
        # the guest, by the executor that is already running. This is the whole point of the fix:
        # the previous order let the host's LAB_RESTORE (a VIX re-transfer of the helpers and the
        # canary reference) run while Procmon was still capturing, so the capture carried 29-40 s
        # of lab orchestration (334 s for OpnKey) and the capture window was no longer a
        # scientific measurement.
        # Here the order is structural and cannot drift:
        #   sample exit/termination -> bounded tail -> STOP CAPTURE -> (host) restore -> finalise
        # and nothing the malware can delete sits between the sample's exit and the capture stop.
        # ---------------------------------------------------------------------------------------
        $sampleStopUtc = $stopUtc
        $tailStartUtc = [DateTime]::UtcNow
        $captureStopUtc = $null
        $captureStopOverheadSeconds = 0.0
        $postWorkloadCaptureSeconds = 0.0
        $captureStopReceiptPath = ''
        $capturePmlBytes = 0
        $captureStopStatus = 'NOT_REQUESTED'
        if (-not [string]::IsNullOrWhiteSpace($TelemetryCaptureRoot)) {
            Assert-True (-not [string]::IsNullOrWhiteSpace($ProcmonPath)) 'PROCMON_PATH_REQUIRED_FOR_CAPTURE_STOP'
            Assert-True (Test-Path -LiteralPath $ProcmonPath -PathType Leaf) ('FROZEN_PROCMON_BINARY_MISSING:' + $ProcmonPath)
            $pml = Join-Path $TelemetryCaptureRoot 'capture.pml'
            $captureStopReceiptPath = Join-Path $TelemetryCaptureRoot 'capture_stop_receipt.json'
            # (1) the bounded post-workload telemetry period - the same 10 s tail the benign
            #     Windows half applies, and the same tail the Ubuntu half applies IN THE GUEST.
            if ($PostTailSeconds -gt 0) { Start-Sleep -Seconds $PostTailSeconds }
            $tailEndUtc = [DateTime]::UtcNow
            # (2) STOP CAPTURE. The timestamp is taken when Procmon is confirmed gone, so the
            #     capture window ends exactly where the recording ends.
            $stopRequestUtc = [DateTime]::UtcNow
            $stopProc = Start-Process -FilePath $ProcmonPath -ArgumentList @('/Terminate','/Quiet') -Wait -PassThru -ErrorAction Stop
            Assert-True ($stopProc.ExitCode -eq 0) ('PROCMON_TERMINATE_EXIT_CODE:' + $stopProc.ExitCode)
            $stillRunning = $true
            for ($i = 0; $i -lt 80; $i++) {
                if (@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count -eq 0) { $stillRunning = $false; break }
                Start-Sleep -Milliseconds 250
            }
            Assert-True (-not $stillRunning) 'PROCMON_DID_NOT_TERMINATE_AT_CAPTURE_STOP'
            $captureStopUtc = [DateTime]::UtcNow
            $captureStopOverheadSeconds = ($captureStopUtc - $stopRequestUtc).TotalSeconds
            $postWorkloadCaptureSeconds = ($captureStopUtc - $sampleStopUtc).TotalSeconds
            Assert-True (Test-Path -LiteralPath $pml -PathType Leaf) 'CAPTURE_PML_MISSING_AT_CAPTURE_STOP'
            $capturePmlInfo = Get-Item $pml
            $capturePmlBytes = [int64]$capturePmlInfo.Length
            Assert-True ($capturePmlBytes -gt 0) 'CAPTURE_PML_EMPTY_AT_CAPTURE_STOP'
            $stopReceipt = [ordered]@{
                schema_version='1.0';gate='RANSOMWARE_GUEST_CAPTURE_STOP';status='PASS';AttemptID=$AttemptID;RunID=$RunID;ExecutionOrder=$ExecutionOrder
                sample_run_id=$SampleRunId;sample_sha256=$SampleSha256
                sample_start_utc=$startUtc.ToString('o');sample_stop_utc=$sampleStopUtc.ToString('o')
                tail_start_utc=$tailStartUtc.ToString('o');tail_end_utc=$tailEndUtc.ToString('o')
                post_tail_seconds=$PostTailSeconds
                capture_stop_request_utc=$stopRequestUtc.ToString('o');capture_stop_utc=$captureStopUtc.ToString('o')
                capture_stop_overhead_seconds=[Math]::Round($captureStopOverheadSeconds,3)
                post_workload_capture_seconds=[Math]::Round($postWorkloadCaptureSeconds,3)
                capture_pml_path=$pml;capture_pml_bytes=$capturePmlBytes
                procmon_path=$ProcmonPath
                capture_closed=$true;capture_closed_by='GUEST_EXECUTOR_RUN_MODE'
                lab_restore_inside_capture=$false
                timestamp=[DateTime]::UtcNow.ToString('o')
            }
            Write-Json $captureStopReceiptPath $stopReceipt
            $captureStopStatus = 'PASS'
        }
        $Script:CaptureStopUtc=$captureStopUtc
        $Script:PostWorkloadCaptureSeconds=$postWorkloadCaptureSeconds
        $Script:CaptureStopOverheadSeconds=$captureStopOverheadSeconds
        $Script:CaptureStopStatus=$captureStopStatus
        $receipt = [ordered]@{
            schema_version='1.0';gate='RANSOMWARE_GUEST_RUN';status='PASS';AttemptID=$AttemptID;RunID=$RunID;ExecutionOrder=$ExecutionOrder
            sample_run_id=$SampleRunId;sample_sha256=$SampleSha256;sample_guest_path=$SampleGuestPath;split=$Split;repetition=$Repetition
            scenario_run_id=$ScenarioRunId;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole
            telemetry_adapter=$TelemetryAdapter;evidence_archive_format=$EvidenceArchiveFormat
            invocation_mode=$InvocationMode;loader_path=$LoaderPath;entry_point=$EntryPoint;sample_arguments=$SampleArguments
            argument_vector_contract=$ArgumentVectorContract;sample_argument_tokens=@($argvTokens);sample_argument_count=@($argvTokens).Count
            target_mechanism=$(if($ArgumentVectorContract -ceq 'NO_ARGUMENTS'){'DOCUMENTED_SCOPE_NO_EXPLICIT_TARGET'}else{'EXPLICIT_DOCUMENTED_SWITCH'})
            canary_root=$canaryRoot;canary_root_outside_work_root=$true;canary_manifest_inside_corpus=$false
            sample_image_dll=$pe.is_dll;sample_pe_machine=$pe.machine;sample_pe_magic=$pe.optional_magic
            root_process_path=$rootProcessPath;loader_arguments=$loaderArguments;staged_sample_launched_directly=$stagedSampleLaunched
            watchdog_armed=$true;root_pid=$rootPid;sample_exit_code=$exitCode;exit_code=$exitCode;exit_code_source=$exitCodeSource;termination_mode=$terminationMode;actual_execution_seconds=[Math]::Round($actualSeconds,3)
            observation_window_seconds=$ObservationWindowSeconds;watchdog_seconds=$WatchdogSeconds
            sample_runtime_seconds=[Math]::Round($sampleRuntimeSeconds,3);kill_settle_seconds=[Math]::Round($killSettleSeconds,3);observation_deadline_utc=$deadlineUtc.ToString('o')
            scientific_runtime_seconds=[Math]::Round($sampleRuntimeSeconds,3);termination_overhead_seconds=[Math]::Round($killSettleSeconds,3)
            # D-156: the capture boundary fields, recorded separately from the scientific runtime.
            sample_stop_utc=$sampleStopUtc.ToString('o')
            post_tail_seconds=$PostTailSeconds
            post_workload_capture_seconds=$(if($null -ne $postWorkloadCaptureSeconds){[Math]::Round($postWorkloadCaptureSeconds,3)}else{$null})
            capture_stop_utc=$(if($null -ne $captureStopUtc){$captureStopUtc.ToString('o')}else{$null})
            capture_stop_overhead_seconds=$(if($null -ne $captureStopOverheadSeconds){[Math]::Round($captureStopOverheadSeconds,3)}else{$null})
            capture_stop_status=$captureStopStatus
            capture_stop_receipt_path=$captureStopReceiptPath
            capture_pml_bytes=$capturePmlBytes
            capture_closed_inside_guest=$true
            lab_restore_inside_capture=$false
            process_tree_killed=$processTreeKilled;process_exit_code=$exitCode
            containment_job_object_created=$Script:JobObjectCreated;containment_job_object_assigned=$Script:JobObjectAssigned
            containment_job_object_terminated=$Script:JobObjectTerminated;containment_job_object_error=$Script:JobObjectError
            containment_executor_priority_raised=$Script:ExecutorPriorityRaised;containment_sample_priority_normalized=$Script:SamplePriorityNormalized
            exit_code_hex=$exitCodeHex;exit_code_class=$exitCodeClass
            start_utc=$startUtc.ToString('o');stop_utc=$stopUtc.ToString('o')
            ransomware_executed=$true;telemetry_started=$true;network_used=$false;sample_root_written=$false
            antivirus_blocked=$false;antivirus_fallback_used=$Script:AntivirusFallbackUsed
            timestamp=[DateTime]::UtcNow.ToString('o')
        }
        Write-Json $ReceiptPath $receipt
        # D-141: the logged WORKLOAD duration is the sample's own runtime; the teardown after the
        # deadline is the lab's and is reported separately, so a watchdog-killed sample reads
        # 60.0 s (inside the 60-65 s band) rather than the wall time including the teardown.
        # D-141: the logged WORKLOAD duration is the sample's own runtime; the teardown after the
        # deadline is the lab's and is reported separately, so a watchdog-killed sample reads
        # 60.0 s (inside the 60-65 s band) rather than the wall time including the teardown.
        Write-Host ('RANSOMWARE_GUEST_RUN=PASS SAMPLE='+ $SampleRunId +' EXIT_CODE='+ $exitCode +' scientific_runtime='+ [Math]::Round($sampleRuntimeSeconds,3)+'s (the SAMPLE, inside the '+$ObservationWindowSeconds+'s window) termination_overhead='+ [Math]::Round($killSettleSeconds,3)+'s (the LAB teardown after the deadline, bounded by the '+$WatchdogSeconds+'s emergency watchdog budget) wall='+ [Math]::Round($actualSeconds,3)+'s TREE_KILLED='+ $processTreeKilled +' TERMINATION='+ $terminationMode) -ForegroundColor Green
        # D-156: the capture boundary is reported separately from the scientific runtime.
        Write-Host ('  CAPTURE BOUNDARY (D-156): sample_stop='+ $sampleStopUtc.ToString('o') +' post_workload_capture='+ [Math]::Round($postWorkloadCaptureSeconds,3)+'s (tail '+$PostTailSeconds+'s + stop overhead) capture_stop='+ $(if($null -ne $captureStopUtc){$captureStopUtc.ToString('o')}else{'n/a'}) +' capture_closed_inside_guest='+ $captureStopStatus +' LAB_RESTORE_INSIDE_CAPTURE=FALSE') -ForegroundColor Green
        exit 0
    }

    if ($Mode -eq 'CanaryVerify') {
        Stage 'CANARY_VERIFY' ('Re-check canary corpus integrity after sample execution')
        # D-163: the explicit exposure root again, never a derivation from $WorkRoot.
        $canaryRoot = $CanaryRoot
        Assert-True (Test-Path -LiteralPath $canaryRoot -PathType Container) ('CANARY_ROOT_MISSING_AT_CANARY_VERIFY:'+$canaryRoot)
        # D-156: the hash manifest lives OUTSIDE the corpus directory (the frozen Ubuntu D-043
        # pattern), so a ransomware that reached the corpus cannot have destroyed the reference.
        $canaryManifestPath = Join-Path $WorkRoot 'canary_hashes.json'
        $mf=([IO.Path]::GetFullPath($canaryManifestPath));$cr=([IO.Path]::GetFullPath($canaryRoot)).TrimEnd('\')
        Assert-True (-not $mf.StartsWith($cr+'\',[StringComparison]::OrdinalIgnoreCase)) 'CANARY_MANIFEST_INSIDE_CORPUS_DIRECTORY'
        $result = Verify-CanaryCorpus -CanaryRoot $canaryRoot -ManifestPath $canaryManifestPath
        # Canary modification is EXPECTED ransomware-like behaviour; record but do not fail the run.
        # D-163: a MISSING canary and a CONTENT change are recorded separately, and the structural
        # separation is re-recorded in the receipt so the placement is legible without the source.
        $receipt = [ordered]@{
            schema_version='1.0';gate='RANSOMWARE_GUEST_CANARY_VERIFY';status='PASS';AttemptID=$AttemptID;RunID=$RunID;ExecutionOrder=$ExecutionOrder
            sample_run_id=$SampleRunId;split=$Split;repetition=$Repetition;ground_truth=$GroundTruth
            canary_total=$result.total;canary_checked=$result.checked;canary_mismatches=@($result.mismatches);canary_all_intact=$result.all_intact
            canary_missing=@($result.missing);canary_hash_mismatches=@($result.hash_mismatches)
            canary_modified=(-not $result.all_intact);canary_root=$canaryRoot;canary_manifest_path=$canaryManifestPath
            canary_root_outside_work_root=$true
            timestamp=[DateTime]::UtcNow.ToString('o')
        }
        Write-Json $ReceiptPath $receipt
        Write-Host ('RANSOMWARE_GUEST_CANARY_VERIFY=PASS SAMPLE='+ $SampleRunId +' CHECKED='+ $result.checked +' MISMATCHES='+ $result.mismatches.Count +' (missing '+@($result.missing).Count+' / hash '+@($result.hash_mismatches).Count+') CANARY_ROOT='+$canaryRoot) -ForegroundColor Green
        exit 0
    }

    throw ('UNKNOWN_MODE:'+ $Mode)
}
catch {
    # D-140: the FAIL receipt carries the measured values, so a rejected run is still evidence.
    $receipt = [ordered]@{schema_version='1.0';gate='RANSOMWARE_GUEST_EXECUTE';status='FAIL';AttemptID=$AttemptID;RunID=$RunID;ExecutionOrder=$ExecutionOrder;sample_run_id=$SampleRunId;mode=$Mode;error=$_.Exception.Message;invocation_mode=$InvocationMode;loader_path=$LoaderPath;entry_point=$EntryPoint;sample_arguments=$SampleArguments;argument_vector_contract=$ArgumentVectorContract;actual_execution_seconds=$Script:ActualSeconds;sample_runtime_seconds=$Script:SampleRuntimeSeconds;kill_settle_seconds=$Script:KillSettleSeconds;exit_code=$Script:ExitCodeValue;capture_stop_status=$Script:CaptureStopStatus;capture_stop_utc=$(if($null -ne $Script:CaptureStopUtc){$Script:CaptureStopUtc.ToString('o')}else{$null});post_workload_capture_seconds=$Script:PostWorkloadCaptureSeconds;capture_stop_overhead_seconds=$Script:CaptureStopOverheadSeconds;containment_job_object_created=$Script:JobObjectCreated;containment_job_object_assigned=$Script:JobObjectAssigned;containment_job_object_terminated=$Script:JobObjectTerminated;containment_job_object_error=$Script:JobObjectError;containment_executor_priority_raised=$Script:ExecutorPriorityRaised;containment_sample_priority_normalized=$Script:SamplePriorityNormalized;timestamp=[DateTime]::UtcNow.ToString('o')}
    $d=Split-Path -Parent $ReceiptPath; if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}
    Write-Json $ReceiptPath $receipt
    Write-Error $_.Exception.Message
    exit 1
}
