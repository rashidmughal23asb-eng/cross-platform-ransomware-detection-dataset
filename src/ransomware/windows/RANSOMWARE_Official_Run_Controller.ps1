# RANSOMWARE_Official_Run_Controller.ps1
#
# Windows ransomware official-run controller.
# Pattern: identical scaffolding to BENIGN_Official_Run_Controller.ps1 (native VIX,
# Credential Manager transport, snapshot revert per run, fail-closed gates, evidence
# packaging). Diverges per the ransomware threat model: live-sample execution under a
# bounded 60-s observation window + fixed 5-10 s post-exit telemetry tail + 90-s
# watchdog, canary corpus, host-only isolation verified from inside the guest.
#
# Timing model: DECISIONS.md D-038 (expected_duration_seconds = 60; no fill-to-60; no
# rerun on natural early exit). Telemetry: DECISIONS.md D-039 (Sysmon+Procmon).
# Split/manifest: DECISIONS.md D-037 (family-level 11/4/4 frozen).
#
# No secrets in scripts; credentials come from Credential Manager.
#
# RunMode: Pilot | Preflight | Official. Only Official consumes a campaign slot (1 of 40).
# Pilot/Preflight write to pilot_runs\ / preflight_runs\ and always record 0 slots consumed.
#
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CampaignRoot,
    [Parameter(Mandatory=$true)][ValidateSet('Pilot','Preflight','Official')][string]$RunMode,
    [Parameter(Mandatory=$true)][string]$VmrunPath,
    [Parameter(Mandatory=$true)][string]$VMwareGuiPath,
    [Parameter(Mandatory=$true)][string]$WindowsVmxPath,
    [Parameter(Mandatory=$true)][string]$UbuntuVmxPath,
    [string]$WindowsSnapshot='P5G_V11_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261115',
    [string]$UbuntuSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013',
    [int]$PreRollSeconds=5,
    [int]$PostTailSeconds=10,
    [int]$ObservationWindowSeconds=60,
    [int]$WatchdogSeconds=90,
    [Parameter(Mandatory=$true)][ValidatePattern('^RAN_WIN_[0-9]{2}_[AB]$')][string]$RunID,
    [Parameter(Mandatory=$true)][ValidateRange(1,40)][int]$ExecutionOrder,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-R-[0-9]{2}$')][string]$SampleRunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9./\-]+$')][string]$FamilyStratum,
    [Parameter(Mandatory=$true)][ValidateSet('TRAIN','VALIDATION','TEST')][string]$Split,
    [Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Repetition,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-R-[0-9]{2}-[AB]$')][string]$ScenarioRunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^R[0-9]{2}-WIN-[AB]$')][string]$FixtureSeed,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$SampleSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+$')][string]$SampleBytes,
    [Parameter(Mandatory=$true)][string]$SampleGuestPath,
    [Parameter(Mandatory=$true)][ValidateSet('True','False')][string]$ReadOnly,
    [Parameter(Mandatory=$true)][string]$ModeOctal,
    [Parameter(Mandatory=$true)][ValidateSet('RANSOMWARE')][string]$GroundTruth,
    [Parameter(Mandatory=$true)][ValidateSet('MALICIOUS_PRIMARY_SUBJECT')][string]$ProcessDensityRole,
    [Parameter(Mandatory=$true)][ValidateSet('zip')][string]$EvidenceArchiveFormat,
    [Parameter(Mandatory=$true)][ValidateSet('Sysmon+Procmon')][string]$TelemetryAdapter,
    [Parameter(Mandatory=$true)][ValidateSet('PENDING')][string]$Status
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false;$Script:NetworkRestoreReason='';$Script:NetworkRestoreAttempts=0
# D-153: the frozen per-sample invocation contract for this run.
$Script:InvocationMode='';$Script:InvocationLoader='';$Script:InvocationEntry='';$Script:InvocationArgs='NO_ARGUMENTS';$Script:InvocationContract=''
# D-156: the frozen per-sample TARGET contract for this run, and the capture-boundary timings.
$Script:TargetArgumentTemplate='NO_ARGUMENTS';$Script:TargetMechanism='';$Script:ResolvedArguments='NO_ARGUMENTS';$Script:TargetEvidence='';$Script:TargetExpectedEffect='';$Script:TargetEvidenceRef='';$Script:TargetArgumentCount=0
$Script:CaptureStartUtc='';$Script:CaptureStopUtc='';$Script:PostWorkloadCaptureSeconds=$null;$Script:CaptureStopOverheadSeconds=$null;$Script:CaptureWindowSeconds=$null;$Script:FinalizeSeconds=$null;$Script:LabRestoreStartUtc='';$Script:LabRestoreSeconds=$null;$Script:TelemetryRestoreSeconds=$null;$Script:CaptureClosedBeforeRestore=$false
$Script:WatchdogArmed=$false;$Script:SampleExitCode=$null;$Script:ActualExecutionSeconds=$null
$Script:TerminationMode=$null;$Script:ExitCodeSource=$null;$Script:WatchdogFired=$false;$Script:ProcessTreeKilled=$false
$Script:SampleExitCodeHex='';$Script:SampleExitCodeClass=''
$Script:SampleRuntimeSeconds=$null;$Script:KillSettleSeconds=$null
$Script:SampleTransportLost=$false;$Script:SampleTransportRecovered=$false;$Script:SampleTransportWaitSeconds=0.0;$Script:SampleReceiptRecovered=$false
$Script:AvHelperTransferred=$false

function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Utf8NoBom([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};Write-Utf8NoBom $Path (($Object|ConvertTo-Json -Depth 20)+"`r`n")}
function Write-AtomicCreate([string]$Path,[object]$Object){if(Test-Path -LiteralPath $Path){throw ('EVIDENCE_ALREADY_EXISTS:'+ $Path)};Write-Json $Path $Object;return $Path}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'RANSOMWARE_OFFICIAL_CONTROLLER.log') -Value $line -Encoding UTF8}}
function Stage([string]$Name,[string]$Message){$Script:Stage=$Name;Write-Host '';Write-Host ('='*88) -ForegroundColor Cyan;Write-Host ('[{0}] {1}' -f $Name,$Message) -ForegroundColor Cyan;Write-Host ('='*88) -ForegroundColor Cyan;Write-Log 'INFO' $Message}
function Get-RunningVmxSet{$h=@{};$out=@(& $VmrunPath -T ws list 2>&1|ForEach-Object{[string]$_});foreach($l in $out){$t=$l.Trim();if($t -match '^[A-Za-z]:\\.*\.vmx$'){$h[$t.ToLowerInvariant()]=$true}};return $h}
function Get-VmOn([string]$Vmx){(Get-RunningVmxSet).ContainsKey($Vmx.ToLowerInvariant())}
function Open-VMwareGuiTab([string]$Vmx,[string]$Label){Assert-True (Test-Path -LiteralPath $VMwareGuiPath -PathType Leaf) 'VMWARE_GUI_MISSING';Write-Log 'INFO' ('opening VMware GUI tab: '+$Label);[void](Start-Process -FilePath $VMwareGuiPath -ArgumentList ('"'+$Vmx+'"') -WindowStyle Normal -PassThru)}
function Get-UniqueVmsd([string]$Vmx){$a=@(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File);Assert-True ($a.Count -eq 1) ('VMSD_NOT_UNIQUE:'+ $Vmx);$a[0].FullName}
function Get-CurrentSnapshotName([string]$Vmx,[string]$Label){$v=Get-UniqueVmsd $Vmx;$lines=[IO.File]::ReadAllLines($v);$cur='';$map=@{};foreach($l in $lines){$m=[regex]::Match($l,'^\s*snapshot\.current\s*=\s*"([^"]*)"');if($m.Success){$cur=$m.Groups[1].Value};$m=[regex]::Match($l,'^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"');if($m.Success){$i=[int]$m.Groups[1].Value;if(-not$map.ContainsKey($i)){$map[$i]=@{}};$map[$i][$m.Groups[2].Value]=$m.Groups[3].Value}};Assert-True (-not[string]::IsNullOrWhiteSpace($cur)) ($Label+'_NO_CURRENT_SNAPSHOT');foreach($i in $map.Keys){if([string]$map[$i]['uid'] -ceq $cur){return [string]$map[$i]['displayName']}};throw ($Label+'_SNAPSHOT_UID_UNMAPPED')}
function Assert-CurrentSnapshot([string]$Vmx,[string]$Expected,[string]$Label){$a=Get-CurrentSnapshotName $Vmx $Label;Assert-True ($a -ceq $Expected) ($Label+'_SNAPSHOT_DRIFT expected='+$Expected+' actual='+$a)}
function Get-VmxAssignments([string]$Path){$m=@{};foreach($line in [IO.File]::ReadAllLines($Path)){$x=[regex]::Match($line,'^\s*([^#][^=]*?)\s*=\s*"([^"]*)"\s*$');if($x.Success){$m[$x.Groups[1].Value.Trim().ToLowerInvariant()]=$x.Groups[2].Value}};$m}
function Assert-VmxHardening([string]$Label,[string]$Path){$a=Get-VmxAssignments $Path;$req=[ordered]@{'isolation.tools.copy.disable'='TRUE';'isolation.tools.paste.disable'='TRUE';'isolation.tools.dnd.disable'='TRUE';'isolation.tools.hgfs.disable'='TRUE';'sharedfolder.maxnum'='0';'sharedfolder0.enabled'='FALSE';'sharedfolder0.present'='FALSE';'sharedfolder0.readaccess'='FALSE';'sharedfolder0.writeaccess'='FALSE';'ethernet0.startconnected'='FALSE';'usb.present'='FALSE'};foreach($k in $req.Keys){Assert-True $a.ContainsKey($k) ($Label+'_VMX_MISSING_'+$k);Assert-True ([string]$a[$k] -ceq [string]$req[$k]) ($Label+'_VMX_DRIFT_'+$k+'='+$a[$k])}}
function Disable-HostNetwork([object]$Baseline){$ups=@($Baseline.PhysicalAdapters|Where-Object{$_.InitialStatus -ceq 'Up'});Assert-True ($ups.Count -ge 1) 'NO_UP_PHYSICAL_ADAPTER';foreach($a in $ups){Disable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop};Start-Sleep -Seconds 3;$Script:IsolationStarted=$true;$v4=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '0.0.0.0/0'});$v6=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '::/0'});Assert-True ($v4.Count -eq 0) 'IPV4_DEFAULT_ROUTE_REMAINS';Assert-True ($v6.Count -eq 0) 'IPV6_DEFAULT_ROUTE_REMAINS';foreach($a in $ups){$cur=Get-NetAdapter -Name ([string]$a.Name) -ErrorAction Stop;Assert-True ([string]$cur.Status -ne 'Up') ('ADAPTER_REMAINS_UP:'+ $a.Name)};$proof=[ordered]@{status='PASS';disabled_adapters=@($ups.Name);ipv4_default_route_count=$v4.Count;ipv6_default_route_count=$v6.Count;windows_vmx_hardened=$true;ubuntu_vmx_hardened=$true;timestamp=[DateTime]::UtcNow.ToString('o')};Write-Json (Join-Path $Script:RunRoot 'evidence\HOST_ISOLATION_PROOF.json') $proof}
function Restore-HostNetwork([object]$Baseline){
    # D-147: the restoration is SSID-AGNOSTIC and bounded. It re-enables the frozen physical
    # adapters and confirms a usable host network - a default route plus the STABLE adapter
    # identity (alias, interface description, permanent hardware address, adapter state). It
    # does NOT require the pre-run SSID/BSSID, a DHCP address or gateway, or the transient
    # current MAC: any usable network on the SAME physical adapter satisfies the gate. The wait
    # is bounded (300 s) - it never waits indefinitely.
    $Script:NetworkRestoreReason=''
    $Script:NetworkRestoreAttempts=0
    foreach($a in @($Baseline.PhysicalAdapters)){if([string]$a.InitialStatus -ceq 'Up'){Enable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop}}
    $deadline=[DateTime]::UtcNow.AddSeconds(300);$attempt=0;$consecutiveExact=0;$last='NOT_TESTED'
    do{Start-Sleep -Seconds 2;$attempt++;$cur=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID;$check=Test-P5GNetworkRestored $Baseline $cur.PhysicalAdapters $cur.Routes ([pscustomobject]@{vms_safe=$true});if([bool]$check.restored){$consecutiveExact++;if($consecutiveExact -ge 3){$Script:NetworkRestoreReason=[string]$check.reason;$Script:NetworkRestoreAttempts=$attempt;Write-Host ('NETWORK RESTORE CONFIRMED: attempts='+$attempt+' consecutive_exact='+$consecutiveExact+' reason='+$Script:NetworkRestoreReason) -ForegroundColor Green;return $cur}}else{$consecutiveExact=0;$last=[string]$check.reason;if(($attempt % 10) -eq 0){Write-Host ('NETWORK RESTORE WAITING: attempts='+$attempt+' last_reason='+$last) -ForegroundColor Yellow}}}
    while([DateTime]::UtcNow -lt $deadline)
    throw ('NETWORK_RESTORE_NOT_CONFIRMED:attempts='+$attempt+':last_reason='+$last)
}
function Verify-Archive([string]$Zip,[object]$PackReceipt){Assert-True (Test-Path -LiteralPath $Zip -PathType Leaf) 'HOST_ARCHIVE_MISSING';$sha=SHA $Zip;Assert-True ($sha -ceq [string]$PackReceipt.archive_sha256) 'HOST_ARCHIVE_SHA_MISMATCH';Add-Type -AssemblyName System.IO.Compression.FileSystem;$z=[IO.Compression.ZipFile]::OpenRead($Zip);try{$names=@($z.Entries|ForEach-Object{$_.FullName});foreach($n in @('capture.pml','sysmon_process_tree.csv','telemetry_prepare_receipt.json','telemetry_capture_receipt.json','capture_stop_receipt.json','sample_execute_receipt.json','canary_integrity_receipt.json','archive_manifest.json')){Assert-True ($names -contains $n) ('ARCHIVE_ENTRY_MISSING:'+ $n)}}finally{$z.Dispose()};[ordered]@{status='PASS';archive_sha256=$sha;archive_bytes=(Get-Item $Zip).Length;verified_utc=[DateTime]::UtcNow.ToString('o')}}
function New-RunManifest([string]$RunRoot){$rows=@();foreach($f in Get-ChildItem -LiteralPath $RunRoot -Recurse -File|Sort-Object FullName){if($f.Name -eq 'PACKAGE_MANIFEST.csv' -or $f.Name -eq 'RUN_FULL_VERIFICATION.json'){continue};$rows+=[pscustomobject]@{relative_path=$f.FullName.Substring($RunRoot.Length+1);bytes=$f.Length;sha256=(SHA $f.FullName)}};$path=Join-Path $RunRoot 'PACKAGE_MANIFEST.csv';$rows|Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8;return $path}

$PackageRoot=$PSScriptRoot
# D-163/D-164: the bridge's Revert-ExactSnapshot checks the snapshot it reverts to against a
# caller-registered expectation (its default stays the historical R5 Windows baseline so benign
# and old qualification callers are unaffected). This controller registers THIS campaign's
# baseline BEFORE the bridge is dot-sourced, so a stale pin cannot revert to the wrong state.
$Script:HCQFrozenWindowsSnapshot=$WindowsSnapshot
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'HCQNativeBridge.ps1')

function Get-OptionalText($Object, [string]$Name) {
    # D-152: StrictMode makes a missing property access fatal, and an assertion MESSAGE is
    # evaluated eagerly - even when the assertion itself passes. The 21:10 Carso run (RAN_WIN_01_A)
    # had a PASS sample receipt with no 'error' field, so reading that absent field while BUILDING
    # (unused) failure message killed the run after a good 60 s observation. Optional fields are
    # now read through this helper, which returns '' when the field is absent.
    if ($null -eq $Object) { return '' }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return '' }
    return [string]$prop.Value
}

function Get-InvocationContract([string]$RunId, [string]$SampleSha256) {
    # Load the frozen per‘sample invocation contract CSV.
    $csvPath = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\manifests\WINDOWS_INVOCATION_CONTRACTS.csv'
    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
        throw 'INVOCATION_CONTRACT_CSV_MISSING:' + $csvPath
    }
    $rows = Import-Csv -LiteralPath $csvPath
    $row = $rows | Where-Object { $_.run_id -eq $RunId -and $_.sample_sha256 -eq $SampleSha256 }
    if (-not $row) {
        throw ('INVOCATION_CONTRACT_NOT_FOUND:' + $RunId + ':' + $SampleSha256)
    }
    # Return a custom object with the needed properties.
    return [PSCustomObject] @{
        run_id = $row.run_id
        family_stratum = $row.family_stratum
        image_type = $row.image_type
        invocation_mode = $row.invocation_mode
        loader_path = $row.loader_path
        entry_point = $row.entry_point
        sample_arguments = $row.sample_arguments
    }
}

function Get-TargetContract([string]$RunId, [string]$SampleSha256) {
    # D-156: the FROZEN per-family invocation/target contract. It is a second, separate frozen
    # artefact (01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv) so the D-153 launch
    # contract stays exactly as it was frozen, and it adds the ONE thing the launch contract
    # cannot express: the TARGET. Every row names the argument vector the binary itself
    # documents, the mechanism by which Corpus V2 becomes the target, the documented scope
    # evidence taken from the binary's own strings, and the expected canary effect.
    $csvPath = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs\01_SHARED\manifests\WINDOWS_FAMILY_TARGET_CONTRACTS.csv'
    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) {
        throw 'TARGET_CONTRACT_CSV_MISSING:' + $csvPath
    }
    $rows = Import-Csv -LiteralPath $csvPath
    $row = @($rows | Where-Object { $_.run_id -eq $RunId -and $_.sample_sha256 -eq $SampleSha256 })
    if ($row.Count -ne 1) {
        throw ('TARGET_CONTRACT_NOT_FOUND_OR_AMBIGUOUS:' + $RunId + ':' + $SampleSha256 + ':rows=' + $row.Count)
    }
    $r = $row[0]
    # The target contract must agree with the D-153 launch contract on every shared field.
    $inv = Get-InvocationContract -RunId $RunId -SampleSha256 $SampleSha256
    if ([string]$r.invocation_mode -cne [string]$inv.invocation_mode) { throw ('TARGET_CONTRACT_INVOCATION_MODE_MISMATCH:' + $RunId) }
    if ([string]$r.loader_path -cne [string]$inv.loader_path) { throw ('TARGET_CONTRACT_LOADER_MISMATCH:' + $RunId) }
    if ([string]$r.entry_point -cne [string]$inv.entry_point) { throw ('TARGET_CONTRACT_ENTRY_MISMATCH:' + $RunId) }
    # The argument vector is closed: NO_ARGUMENTS, or exactly one documented switch with the
    # corpus placeholder. Nothing else is accepted, so an argument can never be invented here.
    $vec = [string]$r.argument_vector_template
    if (-not ($vec -match '^(NO_ARGUMENTS|--[a-z0-9_]+ <CANARY>)$')) { throw ('TARGET_CONTRACT_ARGUMENT_VECTOR_NOT_CLOSED:' + $RunId + ':' + $vec) }
    return [PSCustomObject] @{
        run_id = $r.run_id
        family_stratum = $r.family_stratum
        argument_vector_template = $vec
        argument_count = [int]$r.argument_tokens
        target_mechanism = $r.target_mechanism
        corpus_root = $r.corpus_root
        documented_scope_evidence = $r.documented_scope_evidence
        expected_canary_effect = $r.expected_canary_effect
        evidence_ref = $r.evidence_ref
    }
}

function Wait-GuestCommandChannel([int]$TimeoutSeconds){
    # D-151: after a VIX tools loss (VIX_E_TOOLS_NOT_RUNNING = 3016) the guest program may still be
    # running and may still write its receipt. Wait for the command channel to return, bounded, then
    # let the guest receipt decide. This is a TRANSPORT wait only: the sample is never relaunched,
    # and the frozen 60 s window / 90 s watchdog are enforced inside the guest, unchanged.
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $attempt=0
    $last=''
    while([DateTime]::UtcNow -lt $deadline){
        $attempt++
        try{
            $rc=Invoke-HCQEncoded "exit 0" 30
            if($rc -eq 0){
                $elapsed=$TimeoutSeconds-($deadline-[DateTime]::UtcNow).TotalSeconds
                if($elapsed -lt 0){$elapsed=0}
                return [ordered]@{ready=$true;attempts=$attempt;waited_seconds=[Math]::Round($elapsed,3);last_error=''}
            }
        }catch{
            $last=[string]$_.Exception.Message
            if($last -notmatch 'VIX ERROR CODE:\s*3016' -and $last -notmatch 'HCQ GUEST PROGRAM TIMEOUT'){throw}
        }
        Start-Sleep -Seconds 5
    }
    return [ordered]@{ready=$false;attempts=$attempt;waited_seconds=$TimeoutSeconds;last_error=$last}
}

# Globals/functions above intentionally satisfy the ransomware host contract (native VIX,
# encrypted-VM open, guest login, file transfer, program exec) — hash-pinned, read-only.

$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $false
try {
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { $isAdmin = $principal.IsInRole('Administrators') }
    if (-not $isAdmin) { $isAdmin = $principal.IsInRole('S-1-5-32-544') }
} catch {}
if (-not $isAdmin) {
    Write-Host 'WARNING: Not running as Administrator; VIX operations may fail' -ForegroundColor Yellow
}
foreach($p in @($CampaignRoot,$VmrunPath,$VMwareGuiPath,$WindowsVmxPath,$UbuntuVmxPath)){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
Assert-VmxHardening 'Windows' $WindowsVmxPath;Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_AT_START'
Assert-True (-not(Get-VmOn $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_AT_START'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'

$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16)
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
# Mode-gated bookkeeping: only Official runs consume campaign slots.
$IsOfficial=($RunMode -ceq 'Official')
$QualificationOnly=(-not $IsOfficial)
$SlotsConsumed=$(if($IsOfficial){1}else{0})
$RunSubdir=$(if($IsOfficial){'official_runs'}elseif($RunMode -ceq 'Preflight'){'preflight_runs'}else{'pilot_runs'})
$Script:RunRoot=Join-Path $CampaignRoot ('04_WINDOWS\RANSOMWARE\'+$RunSubdir+'\'+$RunID+'_'+$Script:AttemptID+'_'+$stamp)
New-Item -ItemType Directory -Path $Script:RunRoot -Force|Out-Null
foreach($d in @('evidence','recovery')){New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot $d) -Force|Out-Null}
$OverallSw=[Diagnostics.Stopwatch]::StartNew()
$runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError=''
$samplePrepareHost=Join-Path $Script:RunRoot 'evidence\sample_prepare_receipt.json'
$sampleRunHost=Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json'
$telePrepHost=Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json'
$teleCapHost=Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json'
# D-156: the capture-boundary receipt is copied to the host as its own evidence file, so the
# proof that the capture was closed inside the guest is legible without unpacking the archive.
$captureStopHost=Join-Path $Script:RunRoot 'evidence\capture_stop_receipt.json'
$canaryHost=Join-Path $Script:RunRoot 'evidence\canary_integrity_receipt.json'
$packHost=Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json'
$archiveHost=Join-Path $Script:RunRoot 'capture_archive.zip'
$avStateHost=Join-Path $Script:RunRoot 'evidence\antivirus_state.json'
# D-141: the canary hash manifest is preserved ON THE HOST right after the prepare stage, and
# re-transmitted into the guest before the canary verification. The malware can destroy the
# corpus (and did delete the guest helpers); without the preserved reference the verification
# would fail the run instead of MEASURING what the malware did to the corpus.
$canaryManifestHost=Join-Path $Script:RunRoot 'evidence\canary_hashes.json'
$avPostHost=Join-Path $Script:RunRoot 'evidence\antivirus_state_post.json'
# D-148: the FROZEN Procmon authority contract - the JSON that the telemetry helper asserts at
# prepare AND at finalise. On 2026-11-13 the Akira run deleted it inside the guest, and the
# telemetry finalisation failed with FROZEN_PROCMON_AUTHORITY_MISSING AFTER the sample had run.
# The exact artifact is preserved on the HOST with its frozen SHA-256 (R7 package manifest and
# materialization receipt); it is re-transmitted and hash-verified, never edited. The raw
# capture is never reconstructed: a missing capture.pml stays a genuine measurement failure.
$ProcmonAuthorityGuestPath='C:\RansomLab\Evidence\Phase15\PostPanel\Gate7B2C1W_R2_TelemetryBaselineSuccessor\gate7_b2_c1w_r2_first_engineering_unit_contract_v1.1.json'
$ProcmonAuthoritySha256='c3d2e193fd8b1279f9f625c389c8b88c890ac417dd6d7d5b6b7fa0a2e01b519a'
$ProcmonAuthorityBytes=[int64]9997
$ProcmonAuthorityCandidates=@(
    'C:\D. RansomLab_Host_Preservation\Gate7\B2_R7Z_W_CHAT29_R7_FormalTelemetrySuccessorPackage_R1\package\gate7_b2_c1w_r2_first_engineering_unit_contract_v1.1.json'
    'C:\RansomLab_Host_Preservation\Gate7\B2_R7Z_W_CHAT29_R7_FormalTelemetrySuccessorPackage_R1\package\gate7_b2_c1w_r2_first_engineering_unit_contract_v1.1.json'
)
$ProcmonAuthorityHost=Join-Path $Script:RunRoot 'evidence\frozen_procmon_authority.json'
$Script:ProcmonAuthoritySource=''
$Script:ProcmonAuthorityVerified=$false
$Script:ProcmonAuthorityRetransmitted=$false
function Resolve-FrozenProcmonAuthority {
    # Fail-closed BEFORE the sample runs: if the exact frozen artifact is not available on the
    # host with its frozen bytes and hash, this run could not be finalised and must not start.
    $src=''
    foreach($cand in $ProcmonAuthorityCandidates){
        if(Test-Path -LiteralPath $cand -PathType Leaf){
            Assert-True ((SHA $cand) -ceq $ProcmonAuthoritySha256) ('FROZEN_PROCMON_AUTHORITY_HOST_HASH_MISMATCH:'+$cand)
            Assert-True ((Get-Item -LiteralPath $cand).Length -eq $ProcmonAuthorityBytes) ('FROZEN_PROCMON_AUTHORITY_HOST_BYTES_MISMATCH:'+$cand)
            if($src -eq ''){$src=[string]$cand}
        }
    }
    Assert-True (-not($src -eq '')) 'FROZEN_PROCMON_AUTHORITY_HOST_COPY_MISSING'
    Copy-Item -LiteralPath $src -Destination $ProcmonAuthorityHost -Force
    Assert-True ((SHA $ProcmonAuthorityHost) -ceq $ProcmonAuthoritySha256) 'FROZEN_PROCMON_AUTHORITY_PRESERVATION_HASH_MISMATCH'
    Assert-True ((Get-Item -LiteralPath $ProcmonAuthorityHost).Length -eq $ProcmonAuthorityBytes) 'FROZEN_PROCMON_AUTHORITY_PRESERVATION_BYTES_MISMATCH'
    $Script:ProcmonAuthoritySource=$src
    return $ProcmonAuthorityHost
}
# D-136: the guest analysis tree that the antivirus is excluded from for the analysis window
$guestAvRoot='C:\RansomLab'
$guestAvHelper='C:\RansomLab\RansomwareOfficial\'+$RunID+'\Helpers\'+$Script:AttemptID+'\RANSOMWARE_Guest_Antivirus.ps1'
$guestAvReceipt='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\antivirus_state.json'
$guestAvPostReceipt='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\antivirus_state_post.json'

try{
    Stage 'PRESTATE' 'Verify frozen snapshots, hardening, and restore both VMware GUI entries without changing VM power state'
    $null=Invoke-HCQGuiAttachBoth
    $tabs=@(Get-HCQWorkstationTabNames);Assert-True ($tabs -contains 'Windows 11') 'WINDOWS_GUI_TAB_NOT_VISIBLE_PRE_RUN';Assert-True ($tabs -contains 'Ubuntu') 'UBUNTU_GUI_TAB_NOT_VISIBLE_PRE_RUN'
    $Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID
    Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline

    Stage 'ISOLATION' 'Disable baseline physical adapters and require zero IPv4/IPv6 default routes'
    # Fail-closed: a ransomware run must never proceed with host egress available.
    Disable-HostNetwork $Script:NetworkBaseline
    $Script:IsolationStarted = $true

    Stage 'VM_START' 'Power on Windows by native VIX; Ubuntu remains OFF; restore visible VMware tabs'
    Start-VM $WindowsVmxPath 'Windows'
    # Guest-tools settle delay: WaitForToolsInGuest reports ready before the
    # guest file-copy service is fully available. Wait an extra 15 s before the
    # first Copy-ToGuest so the initial helper transfer succeeds reliably.
    Write-Host 'Waiting 30 s for guest file service to settle after boot...' -ForegroundColor Cyan
    Start-Sleep -Seconds 30
    Assert-True (-not(Get-VmOn $UbuntuVmxPath)) 'UBUNTU_POWERED_ON_UNEXPECTEDLY'
    $null=Invoke-HCQGuiAttachBoth

    $guestHelperRoot='C:\RansomLab\RansomwareOfficial\'+$RunID+'\Helpers\'+$Script:AttemptID
    $guestExec=(Join-Path $guestHelperRoot 'RANSOMWARE_Guest_Execute.ps1')
    $guestTel=(Join-Path $guestHelperRoot 'RANSOMWARE_Guest_Telemetry.ps1')
    $guestPack=(Join-Path $guestHelperRoot 'RANSOMWARE_Guest_Pack.ps1')
    Stage 'HELPER_TRANSFER' 'Transfer ransomware guest executor, telemetry, and packer helpers via native VIX'
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Execute_Official.ps1') $guestExec
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Telemetry.ps1') $guestTel
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Pack.ps1') $guestPack
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Antivirus.ps1') $guestAvHelper
    $Script:AvHelperTransferred=$true

    # D-143: the guest paths are defined BEFORE the AV_PREPARE stage, which uses the
    # staged sample's path (D-142); under StrictMode a use-before-definition is fatal.
    $guestWorkRoot='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\Workload'
    # D-163: the corpus root is FIXED by the frozen exposure rule and is a sibling of
    # C:\RansomLab\RansomwareOfficial inside the same excluded analysis surface - NEVER a child
    # of $guestWorkRoot. The sample lives in $guestWorkRoot\Sample, and both families that walk
    # C:\RansomLab demonstrably skip the subtree containing their own image, so a corpus inside
    # $guestWorkRoot is structurally unreachable (the measured 0/236). The root is passed to the
    # executor explicitly and re-asserted there; it is not re-derived from the work root.
    $guestCanaryRoot='C:\RansomLab\Canary\'+$RunID+'_'+$Script:AttemptID
    # D-156: the canary hash manifest lives OUTSIDE the corpus directory (the frozen Ubuntu D-043
    # pattern), so a ransomware that reaches the corpus cannot destroy the reference before the
    # canary verification.
    $guestCanaryManifest=Join-Path $guestWorkRoot 'canary_hashes.json'
    # D-142: the staged sample's path, so the antivirus helper can exclude the PROCESS
    # (a path exclusion cannot suppress a behavioural rule).
    $guestStagedSample=Join-Path $guestWorkRoot ('Sample\'+$SampleSha256+'.exe')

    # D-153: the frozen per-sample invocation contract. Nine of the ten Windows families are
    # ordinary EXEs and keep the original NO_ARGUMENTS launch; WannaCry (W-R-07) is a PE32+ DLL
    # whose image type cannot be launched by CreateProcess, so it is loaded through its single
    # documented export (PlayGame) by the system loader. The sample, its hash, the timing window,
    # the telemetry and the AV policy are untouched - only the LAUNCH METHOD is per-sample.
    # It is resolved BEFORE the AV_PREPARE stage, because the loader is the process the sample
    # runs inside and therefore the process the antivirus PROCESS exclusion must cover (D-153).
    $contract = Get-InvocationContract $RunID $SampleSha256
    Assert-True ([string]$contract.family_stratum -ceq $FamilyStratum) ('INVOCATION_CONTRACT_FAMILY_MISMATCH:'+ [string]$contract.family_stratum+' vs '+$FamilyStratum)
    $Script:InvocationMode=[string]$contract.invocation_mode
    $Script:InvocationLoader=[string]$contract.loader_path
    $Script:InvocationEntry=[string]$contract.entry_point
    $Script:InvocationArgs=[string]$contract.sample_arguments
    $Script:InvocationContract=[string]$contract.image_type
    Write-Host ('INVOCATION CONTRACT: mode='+$Script:InvocationMode+' image_type='+$Script:InvocationContract+' loader='+$Script:InvocationLoader+' entry='+$Script:InvocationEntry+' sample_arguments='+$Script:InvocationArgs) -ForegroundColor Green

    # D-156: the FROZEN per-family TARGET contract. It supplies the argument vector (the only
    # place a target argument may come from) and the evidence for it. The resolved vector is
    # the frozen template with <CANARY> bound to THIS run's corpus root, and the guest re-proves
    # that binding before it launches the sample.
    $target = Get-TargetContract $RunID $SampleSha256
    Assert-True ([string]$target.family_stratum -ceq $FamilyStratum) ('TARGET_CONTRACT_FAMILY_MISMATCH:'+ [string]$target.family_stratum+' vs '+$FamilyStratum)
    $Script:TargetArgumentTemplate=[string]$target.argument_vector_template
    $Script:TargetMechanism=[string]$target.target_mechanism
    $Script:TargetEvidence=[string]$target.documented_scope_evidence
    $Script:TargetExpectedEffect=[string]$target.expected_canary_effect
    $Script:TargetEvidenceRef=[string]$target.evidence_ref
    $Script:TargetArgumentCount=[int]$target.argument_count
    # D-163: the exposure root was fixed above; re-prove the separation on the host side too, so
    # a future edit of $guestWorkRoot cannot put the corpus back inside the sample's subtree.
    Assert-True (-not $guestCanaryRoot.Equals($guestWorkRoot,[StringComparison]::OrdinalIgnoreCase)) 'CANARY_ROOT_EQUALS_WORK_ROOT'
    Assert-True (-not $guestCanaryRoot.StartsWith($guestWorkRoot+'\',[StringComparison]::OrdinalIgnoreCase)) ('CANARY_ROOT_INSIDE_WORK_ROOT:'+$guestCanaryRoot)
    Assert-True ($guestCanaryRoot -match '^C:\\RansomLab\\Canary\\[A-Za-z0-9_]+$') ('CANARY_ROOT_NOT_THE_FROZEN_EXPOSURE_ROOT:'+$guestCanaryRoot)
    $Script:ResolvedArguments=($Script:TargetArgumentTemplate -replace '<CANARY>', $guestCanaryRoot)
    Write-Host ('TARGET CONTRACT: mechanism='+$Script:TargetMechanism+' argument_vector='+$Script:TargetArgumentTemplate+' -> '+$Script:ResolvedArguments) -ForegroundColor Green
    Write-Host ('  documented scope evidence: '+$Script:TargetEvidence) -ForegroundColor DarkGray
    Write-Host ('  expected canary effect    : '+$Script:TargetExpectedEffect) -ForegroundColor DarkGray

    # D-136: the guest antivirus must not interfere with the analysis. The Ubuntu guest has no
    # antivirus at all, so a Windows run in which Defender intercepts the sample measures the
    # antivirus, not the malware. The analysis tree is excluded from real-time scanning for the
    # analysis window; the exclusion is removed again in the recovery path and the frozen
    # snapshot is reverted afterwards, so the baseline is untouched.
    Stage 'AV_PREPARE' 'Record the guest antivirus state and exclude the guest analysis tree for the analysis window (D-136)'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestAvHelper`" -Mode Prepare -AttemptID $($Script:AttemptID) -RunID `"$RunID`" -ReceiptPath `"$guestAvReceipt`" -AnalysisRoot `"$guestAvRoot`" -SampleProcessPath `"$guestStagedSample`" -LoaderProcessPath `"$($Script:InvocationLoader)`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('ANTIVIRUS_STATE_FAILED:'+ $r.Text)
    Copy-FromGuest $guestAvReceipt $avStateHost
    $av=Get-Content -LiteralPath $avStateHost -Raw|ConvertFrom-Json
    # D-146: the frozen AV policy is CONTROLLED EXCLUSIONS, not a disabled antivirus - the
    # wording and the reported state must say exactly that.
    Assert-True ([bool]$av.av_interference_mitigated) ('AV_INTERFERENCE_NOT_MITIGATED: '+ [string]$av.antivirus_summary)
    $mit=[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'mode')
    Write-Host ('AV INTERFERENCE MITIGATION ACTIVE - frozen analysis exclusions applied: mode='+$mit+' | defender_realtime_protection_active='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'defender_realtime_protection_active')+' | exclusions_applied='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'path_exclusions_applied')+' | process_exclusions_applied='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'process_exclusions_applied')+' | detections='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'detections')+' | remediated='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'remediated')+' | threat_names='+[string](Get-P5GOptionalProperty $av.av_interference_mitigation 'threat_names')) -ForegroundColor Green

    $guestSamplePrepare='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\sample_prepare_receipt.json'
    $guestSampleRun='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\sample_execute_receipt.json'
$guestCanaryReceipt='C:\RansomLab\RansomwareOfficial\'+$RunID+'\'+$Script:AttemptID+'\canary_integrity_receipt.json'
    # D-153: the invocation contract was resolved BEFORE the AV_PREPARE stage (the loader is the
    # process the sample runs inside, so the antivirus PROCESS exclusion must cover it).
    Stage 'SAMPLE_PREPARE' ($RunMode+' '+$RunID+' '+$SampleRunId+' '+$FamilyStratum+': stage sample read-only, stage canary corpus, verify isolation from inside guest')
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestExec`" -Mode Prepare -AttemptID $($Script:AttemptID) -ReceiptPath `"$guestSamplePrepare`" -WorkRoot `"$guestWorkRoot`" -CanaryRoot `"$guestCanaryRoot`" -SampleSha256 $SampleSha256 -SampleBytes $SampleBytes -SampleGuestPath `"$SampleGuestPath`" -ReadOnly $ReadOnly -ModeOctal `"$ModeOctal`" -RunID `"$RunID`" -ExecutionOrder $ExecutionOrder -SampleRunId `"$SampleRunId`" -FamilyStratum `"$FamilyStratum`" -Split $Split -Repetition $Repetition -ScenarioRunId `"$ScenarioRunId`" -FixtureSeed `"$FixtureSeed`" -GroundTruth $GroundTruth -ProcessDensityRole $ProcessDensityRole -TelemetryAdapter `"$TelemetryAdapter`" -EvidenceArchiveFormat $EvidenceArchiveFormat -InvocationMode `"$($Script:InvocationMode)`" -LoaderPath `"$($Script:InvocationLoader)`" -EntryPoint `"$($Script:InvocationEntry)`" -SampleArguments `"$($Script:ResolvedArguments)`" -ArgumentVectorContract `"$($Script:TargetArgumentTemplate)`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('SAMPLE_PREPARE_FAILED:'+ $r.Text)
    Copy-FromGuest $guestSamplePrepare $samplePrepareHost
    # D-141: preserve the canary reference on the HOST before the sample runs - it is the
    # baseline the post-run verification compares against, and the malware can destroy it.
    try { Copy-FromGuest $guestCanaryManifest $canaryManifestHost; Write-Host ('CANARY REFERENCE PRESERVED ON THE HOST: '+$canaryManifestHost) -ForegroundColor Green }
    catch { Write-Log 'WARN' ('the canary hash manifest could not be preserved on the host: '+$_.Exception.Message) }
    $sp=Get-Content -LiteralPath $samplePrepareHost -Raw|ConvertFrom-Json;Assert-True ([string]$sp.status -ceq 'PASS') 'SAMPLE_PREPARE_RECEIPT_FAIL';Assert-True ([bool]$sp.isolation_verified) 'ISOLATION_NOT_VERIFIED';Assert-True ([bool]$sp.canary_staged) 'CANARY_NOT_STAGED'
    # D-163: the guest receipt must report the FROZEN exposure root, not a derived child of the
    # work root, and the separation must be legible in the receipt itself.
    Assert-True ([string]$sp.canary_root -ceq $guestCanaryRoot) ('CANARY_ROOT_RECEIPT_MISMATCH:'+ [string]$sp.canary_root+' vs '+$guestCanaryRoot)
    Assert-True ([bool]$sp.canary_root_outside_work_root) 'CANARY_ROOT_OUTSIDE_WORK_ROOT_NOT_RECORDED'
    Assert-True ([int]$sp.canary_count -eq 236) ('CANARY_COUNT_RECEIPT_MISMATCH:'+ [string]$sp.canary_count)

    # D-148: the frozen authority is resolved and hash-verified on the HOST before the sample is
    # allowed to run, and preserved inside this run's evidence for restoration after the window.
    $null=Resolve-FrozenProcmonAuthority
    Write-Host ('FROZEN PROCMON AUTHORITY PRESERVED ON THE HOST: sha256='+$ProcmonAuthoritySha256+' bytes='+$ProcmonAuthorityBytes+' source='+$Script:ProcmonAuthoritySource) -ForegroundColor Green
    # D-156: the frozen Procmon BINARY path is read from the host-side copy of the frozen
    # authority contract, so the guest executor can stop the capture without reading any guest
    # artefact that the malware could have deleted.
    $authorityJson = Get-Content -LiteralPath $ProcmonAuthorityHost -Raw | ConvertFrom-Json
    $procmonPath = [string]$authorityJson.source_authorities.procmon_path
    Assert-True (-not [string]::IsNullOrWhiteSpace($procmonPath)) 'FROZEN_PROCMON_PATH_NOT_IN_THE_AUTHORITY_CONTRACT'

    $guestCapture='C:\RansomLab\TelemetryOutput\'+$RunID+'_'+$Script:AttemptID
    Stage 'TELEMETRY_START' 'Start real frozen Sysmon+Procmon telemetry in guest before sample launch'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestTel`" -Mode Prepare -AttemptID $($Script:AttemptID) -RunID $RunID -GlobalOrder $ExecutionOrder -OutputRoot `"$guestCapture`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('TELEMETRY_PREPARE_FAILED:'+ $r.Text)
    Copy-FromGuest ($guestCapture+'\prepare_receipt.json') $telePrepHost
    $tp=Get-Content -LiteralPath $telePrepHost -Raw|ConvertFrom-Json;Assert-True ([string]$tp.status -ceq 'PASS' -and [bool]$tp.telemetry_ready) 'TELEMETRY_NOT_READY'
    Write-Host '*** TELEMETRY READY ***' -ForegroundColor Green
    Start-Sleep -Seconds $PreRollSeconds

    Stage 'SAMPLE_RUN' ('Execute ransomware sample under bounded observation: max '+$ObservationWindowSeconds+'s, watchdog '+$WatchdogSeconds+'s; then the '+$PostTailSeconds+'s post-workload tail and the capture stop, both inside the guest')
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestExec`" -Mode Run -AttemptID $($Script:AttemptID) -ReceiptPath `"$guestSampleRun`" -WorkRoot `"$guestWorkRoot`" -CanaryRoot `"$guestCanaryRoot`" -ObservationWindowSeconds $ObservationWindowSeconds -WatchdogSeconds $WatchdogSeconds -PostTailSeconds $PostTailSeconds -TelemetryCaptureRoot `"$guestCapture`" -ProcmonPath `"$procmonPath`" -RunID `"$RunID`" -ExecutionOrder $ExecutionOrder -SampleRunId `"$SampleRunId`" -SampleSha256 $SampleSha256 -SampleBytes $SampleBytes -SampleGuestPath `"$SampleGuestPath`" -ReadOnly $ReadOnly -ModeOctal `"$ModeOctal`" -Split $Split -Repetition $Repetition -TelemetryAdapter `"$TelemetryAdapter`" -ScenarioRunId `"$ScenarioRunId`" -FixtureSeed `"$FixtureSeed`" -GroundTruth $GroundTruth -ProcessDensityRole $ProcessDensityRole -FamilyStratum `"$FamilyStratum`" -EvidenceArchiveFormat $EvidenceArchiveFormat -InvocationMode `"$($Script:InvocationMode)`" -LoaderPath `"$($Script:InvocationLoader)`" -EntryPoint `"$($Script:InvocationEntry)`" -SampleArguments `"$($Script:ResolvedArguments)`" -ArgumentVectorContract `"$($Script:TargetArgumentTemplate)`""
    $r=$null
    $sampleTransportLost=$false
    $sampleTransportError=''
    $sampleTransportWaitSeconds=0.0
    try {
        $r=Invoke-GuestPowerShell $cmd ([int]($WatchdogSeconds+120))
    } catch {
        $sampleTransportError=[string]$_.Exception.Message
        if (($sampleTransportError -match 'VIX ERROR CODE:\s*3016') -or ($sampleTransportError -match 'HCQ GUEST PROGRAM TIMEOUT')) {
            $sampleTransportLost=$true
        } else { throw }
    }
    if (-not $sampleTransportLost -and $null -ne $r -and $r.ExitCode -ne 0) {
        $rtext=[string]$r.Text
        if (($rtext -match 'Requested guest process timeout') -or ($rtext -match 'VIX ERROR CODE:\s*3016')) {
            $sampleTransportLost=$true
            $sampleTransportError='WRAPPER: '+$rtext
        }
    }
    if ($sampleTransportLost) {
        # D-151: VIX 3016 is a TRANSPORT loss, not a sample failure. The guest executor keeps
        # running under its own 60 s / 90 s bounds; wait for the command channel, then let the
        # guest receipt decide. The sample is NEVER relaunched, so the observation is not
        # duplicated or biased.
        Write-Log 'WARN' ('SAMPLE_RUN transport lost ('+$sampleTransportError+'); waiting for VMware Tools; the guest receipt is authoritative and the sample will NOT be relaunched')
        $ch=Wait-GuestCommandChannel 180
        $sampleTransportWaitSeconds=[double]$ch.waited_seconds
        Assert-True ([bool]$ch.ready) ('SAMPLE_RUN_TRANSPORT_NOT_RECOVERED:'+$sampleTransportError+':last_error='+[string]$ch.last_error)
    }
    # D-140: the receipt is copied OUT of the guest BEFORE the exit code is asserted. On a
    # failed run the guest is reverted to the frozen snapshot, so a receipt that was never
    # copied would be LOST - and the failure evidence is exactly what is needed.
    # D-151: the copy is retried, because after a transport loss the guest executor may still be
    # finishing the teardown and writing the receipt.
    $receiptDeadline=[DateTime]::UtcNow.AddSeconds([double]($WatchdogSeconds+60))
    $sampleReceiptCopied=$false
    $lastReceiptError=''
    while (-not $sampleReceiptCopied -and [DateTime]::UtcNow -lt $receiptDeadline) {
        try { Copy-FromGuest $guestSampleRun $sampleRunHost; $sampleReceiptCopied=$true }
        catch { $lastReceiptError=[string]$_.Exception.Message; Start-Sleep -Seconds 5 }
    }
    if ($sampleTransportLost) {
        Assert-True $sampleReceiptCopied ('SAMPLE_RUN_RECEIPT_MISSING_AFTER_TRANSPORT_LOSS:'+$sampleTransportError+':last_copy_error='+$lastReceiptError)
    } elseif (-not $sampleReceiptCopied) {
        Write-Log 'WARN' ('the sample receipt could not be copied out of the guest: '+$lastReceiptError)
    }
    if (-not $sampleTransportLost) {
        if ($r.ExitCode -ne 0 -and $sampleReceiptCopied) {
            $srFail=Get-Content -LiteralPath $sampleRunHost -Raw|ConvertFrom-Json
            if ([string]$srFail.status -ceq 'FAIL') { Assert-True $false ('SAMPLE_EXECUTE_RECEIPT_FAIL:'+(Get-OptionalText $srFail 'error')) }
        }
        Assert-True ($r.ExitCode -eq 0) ('SAMPLE_RUN_FAILED:'+ $r.Text)
    }
    if ($sampleTransportLost) {
        Write-Json (Join-Path $Script:RunRoot 'evidence\sample_transport_recovery.json') ([ordered]@{schema_version='1.0';gate='SAMPLE_RUN_TRANSPORT_RECOVERY';status=$(if($sampleReceiptCopied){'PASS'}else{'FAIL'});run_id=$RunID;attempt_id=$Script:AttemptID;transport_error=$sampleTransportError;transport_wait_seconds=[Math]::Round($sampleTransportWaitSeconds,3);receipt_recovered=$sampleReceiptCopied;receipt_path=$guestSampleRun;sample_relaunched=$false;observation_window_seconds=$ObservationWindowSeconds;watchdog_seconds=$WatchdogSeconds;timestamp=[DateTime]::UtcNow.ToString('o')})
    }
    $Script:SampleTransportLost=$sampleTransportLost
    $Script:SampleTransportRecovered=($sampleTransportLost -and $sampleReceiptCopied)
    $Script:SampleTransportWaitSeconds=$sampleTransportWaitSeconds
    $Script:SampleReceiptRecovered=$sampleReceiptCopied
    $sr=Get-Content -LiteralPath $sampleRunHost -Raw|ConvertFrom-Json
    Assert-True ([string]$sr.status -ceq 'PASS') ('SAMPLE_EXECUTE_RECEIPT_FAIL:'+(Get-OptionalText $sr 'error'))
    Assert-True ([bool]$sr.watchdog_armed) 'WATCHDOG_NOT_ARMED'
    # D-153: the guest receipt must prove that the frozen contract was the one applied.
    Assert-True ([string]$sr.invocation_mode -ceq $Script:InvocationMode) ('INVOCATION_MODE_MISMATCH:'+ (Get-OptionalText $sr 'invocation_mode')+' vs '+$Script:InvocationMode)
    # D-156: the argument vector the guest actually applied must be the resolved frozen
    # template, and the template itself must be the one from the frozen target contract.
    Assert-True ([string]$sr.sample_arguments -ceq $Script:ResolvedArguments) ('INVOCATION_ARGUMENTS_MISMATCH:'+ (Get-OptionalText $sr 'sample_arguments')+' vs '+$Script:ResolvedArguments)
    Assert-True ([string]$sr.argument_vector_contract -ceq $Script:TargetArgumentTemplate) ('TARGET_CONTRACT_TEMPLATE_MISMATCH:'+ (Get-OptionalText $sr 'argument_vector_contract')+' vs '+$Script:TargetArgumentTemplate)
    Assert-True ([int]$sr.sample_argument_count -eq $Script:TargetArgumentCount) ('TARGET_CONTRACT_ARGUMENT_COUNT_MISMATCH:'+ (Get-OptionalText $sr 'sample_argument_count')+' vs '+$Script:TargetArgumentCount)
    # D-156: the capture boundary. The guest executor stopped Procmon BEFORE it returned, so the
    # capture is closed before ANY host-side orchestration starts. These assertions are the
    # fail-closed proof that LAB_RESTORE cannot occur inside an active capture.
    Assert-True ([string]$sr.capture_stop_status -ceq 'PASS') ('CAPTURE_STOP_NOT_COMPLETED:'+ (Get-OptionalText $sr 'capture_stop_status'))
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$sr.capture_stop_utc)) 'CAPTURE_STOP_UTC_MISSING'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$sr.sample_stop_utc)) 'SAMPLE_STOP_UTC_MISSING'
    Assert-True ([bool]$sr.capture_closed_inside_guest) 'CAPTURE_NOT_CLOSED_INSIDE_THE_GUEST'
    Assert-True (-not [bool]$sr.lab_restore_inside_capture) 'LAB_RESTORE_INSIDE_CAPTURE'
    $Script:CaptureStopUtc=[string]$sr.capture_stop_utc
    $Script:PostWorkloadCaptureSeconds=[double]$sr.post_workload_capture_seconds
    $Script:CaptureStopOverheadSeconds=[double]$sr.capture_stop_overhead_seconds
    $Script:CaptureClosedBeforeRestore=$true
    # D-156: the post-workload capture period is the bounded telemetry tail plus the stop
    # overhead. The benign-equivalent envelope is ~10-15 s; a longer period means lab
    # orchestration leaked back into the capture window and the run FAILS CLOSED.
    Assert-True ($Script:PostWorkloadCaptureSeconds -gt 0) 'POST_WORKLOAD_CAPTURE_SECONDS_NOT_POSITIVE'
    Assert-True ($Script:PostWorkloadCaptureSeconds -le ([double]$PostTailSeconds + 5.0)) ('POST_WORKLOAD_CAPTURE_OUTSIDE_THE_ENVELOPE:'+ $Script:PostWorkloadCaptureSeconds+'s > '+($PostTailSeconds+5)+'s')
    Assert-True ($Script:CaptureStopOverheadSeconds -le 30.0) ('CAPTURE_STOP_OVERHEAD_TOO_LARGE:'+ $Script:CaptureStopOverheadSeconds+'s')
    if ($Script:InvocationMode -ceq 'RUNDLL32_EXPORT') {
        Assert-True ([string]$sr.entry_point -ceq $Script:InvocationEntry) ('INVOCATION_ENTRY_POINT_MISMATCH:'+ (Get-OptionalText $sr 'entry_point')+' vs '+$Script:InvocationEntry)
        Assert-True ([string]$sr.loader_path -ceq $Script:InvocationLoader) ('INVOCATION_LOADER_MISMATCH:'+ (Get-OptionalText $sr 'loader_path'))
        Assert-True ([bool]$sr.sample_image_dll) 'INVOCATION_SAMPLE_IS_NOT_A_DLL'
        Assert-True (-not [bool]$sr.staged_sample_launched_directly) 'INVOCATION_DLL_WAS_LAUNCHED_DIRECTLY'
    } else {
        Assert-True ([bool]$sr.staged_sample_launched_directly) 'INVOCATION_EXE_WAS_NOT_LAUNCHED_DIRECTLY'
        Assert-True (-not [bool]$sr.sample_image_dll) 'INVOCATION_SAMPLE_IS_A_DLL_BUT_THE_CONTRACT_IS_DIRECT'
    }
    $Script:WatchdogArmed=$true
    $Script:SampleExitCode=[int]$sr.sample_exit_code
    # D-139: the exit code's class is recorded so a crash is legible in the evidence.
    $Script:SampleExitCodeHex=[string]$sr.exit_code_hex
    $Script:SampleExitCodeClass=[string]$sr.exit_code_class
    $Script:ActualExecutionSeconds=[double]$sr.actual_execution_seconds
    # D-041: every run records how the bounded window ended, not only the exit code.
    $Script:ProcessTreeKilled=[bool]$sr.process_tree_killed
    $Script:WatchdogFired=[bool]$sr.process_tree_killed
    $Script:TerminationMode=$(if($Script:ProcessTreeKilled){'OBSERVATION_WINDOW_KILL'}else{'NATURAL_EXIT'})
    $Script:ExitCodeSource=$(if($Script:ProcessTreeKilled){'WATCHDOG_KILL'}else{'PROCESS_EXITCODE'})
    Assert-True ([string]$sr.termination_mode -ceq $Script:TerminationMode) ('TERMINATION_MODE_MISMATCH:'+ [string]$sr.termination_mode+' vs '+$Script:TerminationMode)
    Assert-True ([string]$sr.exit_code_source -ceq $Script:ExitCodeSource) ('EXIT_CODE_SOURCE_MISMATCH:'+ [string]$sr.exit_code_source+' vs '+$Script:ExitCodeSource)
    # D-038: natural early exit is valid; do not fill to ObservationWindowSeconds.
    # D-140: the window gate applies to the SAMPLE's observable runtime, not to the wall time
    # that also carries the lab's kill/settle overhead (a watchdog-killed sample can take
    # seconds to die - ~10.8 s for GreenBlood). The teardown is bounded by the WATCHDOG BUDGET.
    $sampleRuntime=$sr.sample_runtime_seconds
    if ($null -eq $sampleRuntime) { $sampleRuntime=$sr.actual_execution_seconds }
    $sampleRuntime=[double]$sampleRuntime
    Assert-True ($sampleRuntime -le ([double]$ObservationWindowSeconds + 5.0)) ('SAMPLE_EXCEEDED_OBSERVATION_WINDOW:'+ $sampleRuntime+'s > '+$ObservationWindowSeconds+'s')
    if ([bool]$sr.process_tree_killed) { Assert-True ($sampleRuntime -ge ([double]$ObservationWindowSeconds - 5.0)) 'WATCHDOG_KILL_BEFORE_WINDOW' }
    if ($null -ne $sr.kill_settle_seconds) {
        Assert-True ([double]$sr.kill_settle_seconds -le [double]$WatchdogSeconds) ('KILL_SETTLE_EXCEEDED_WATCHDOG_BUDGET:'+ $sr.kill_settle_seconds+'s > '+$WatchdogSeconds+'s')
    }
    $Script:SampleRuntimeSeconds=$sampleRuntime
    $Script:KillSettleSeconds=[double]$sr.kill_settle_seconds
    # D-156: the capture-boundary receipt is copied out as its own host-side evidence file.
    try {
        Copy-FromGuest ($guestCapture+'\capture_stop_receipt.json') $captureStopHost
        $csr=Get-Content -LiteralPath $captureStopHost -Raw|ConvertFrom-Json
        Assert-True ([string]$csr.status -ceq 'PASS') 'CAPTURE_STOP_RECEIPT_NOT_PASS'
        Assert-True ([string]$csr.capture_stop_utc -ceq $Script:CaptureStopUtc) ('CAPTURE_STOP_RECEIPT_UTC_MISMATCH:'+ [string]$csr.capture_stop_utc+' vs '+$Script:CaptureStopUtc)
        Assert-True ([bool]$csr.capture_closed) 'CAPTURE_NOT_CLOSED_IN_THE_STOP_RECEIPT'
        Write-Host ('CAPTURE BOUNDARY RECEIPT COPIED TO THE HOST: capture_stop_utc='+$Script:CaptureStopUtc+' post_workload_capture='+$Script:PostWorkloadCaptureSeconds+'s') -ForegroundColor Green
    } catch {
        Write-Log 'WARN' ('the capture-stop receipt could not be copied out of the guest: '+$_.Exception.Message)
    }
    # D-139: the exit code must be PRESENT and CONSISTENT with the recorded termination mode.
    # The previous test (-ge 0) was a POSIX assumption - on POSIX an exit code is always 0-255,
    # so it could never fire - while on Windows a process that dies from an unhandled exception
    # exits with its NTSTATUS (0xC0000409 = STATUS_STACK_BUFFER_OVERRUN), which as a signed int32
    # is NEGATIVE. A crashing sample is a legitimate behavioural observation (D-038: a natural
    # early exit is valid and is recorded as-is) and must NOT fail the run; the R4 engineering
    # reference and the UBUNTU controller have no such gate at all. A crash is now CLASSIFIED and
    # RECORDED (exit_code_class / exit_code_hex) instead of being rejected.
    Assert-True ($null -ne $sr.process_exit_code) 'SAMPLE_EXIT_CODE_MISSING'
    $exitCodeConsistent=(([bool]$sr.process_tree_killed -and ([string]$sr.exit_code_source -ceq 'WATCHDOG_KILL')) -or
                          ((-not [bool]$sr.process_tree_killed) -and ([string]$sr.exit_code_source -ceq 'PROCESS_EXITCODE')))
    Assert-True $exitCodeConsistent 'SAMPLE_EXIT_CODE_INVALID'
    # D-141: the logged WORKLOAD duration is the sample's runtime; the teardown is reported
    # separately, so a watchdog-killed sample reads 60.0 s (inside the 60-65 s band).
    # D-146: the timing semantics, named for what each number measures. WORKLOAD_DURATION is
    # the SCIENTIFIC observation (the sample's own runtime inside the frozen window);
    # TEARDOWN is the lab's process-tree teardown AFTER the deadline (orchestration overhead,
    # bounded by the 90 s emergency watchdog budget); WALL is the orchestration total.
    Write-Host ('SAMPLE COMPLETE: SAMPLE='+$sr.sample_run_id+' EXIT_CODE='+$sr.sample_exit_code+' WORKLOAD_DURATION='+$sampleRuntime+'s (scientific observation window, max '+$ObservationWindowSeconds+'s) TEARDOWN='+$sr.kill_settle_seconds+'s (lab process-tree teardown after the deadline - orchestration, bounded by the '+$WatchdogSeconds+'s emergency watchdog budget) OBSERVATION_WINDOW='+$ObservationWindowSeconds+'s TERMINATION='+$Script:TerminationMode) -ForegroundColor Green

    # ---------------------------------------------------------------------------------------
    # D-156: THE TELEMETRY ORDER.
    #
    # The previous order was: sample -> LAB_RESTORE (a VIX re-transfer of the helpers and the
    # canary reference) -> 10 s tail -> telemetry finalisation -> canary verify -> pack. Because
    # LAB_RESTORE ran while Procmon was still capturing, the capture carried 29-40 s of lab
    # orchestration (334 s for OpnKey) and the capture window stopped being a scientific
    # measurement (D-154).
    #
    # The order is now:
    #   sample exit/termination -> bounded tail -> STOP CAPTURE   (INSIDE THE GUEST EXECUTOR)
    #   -> TELEMETRY_RESTORE -> TELEMETRY_FINALIZE -> LAB_RESTORE -> CANARY_VERIFY
    #   -> GUEST_PACK -> ARCHIVE_TRANSFER -> RECOVERY
    #
    # The capture is closed by the guest executor BEFORE this stage is even entered, so no host
    # orchestration - of any kind - can be inside the capture window. The TELEMETRY_RESTORE is a
    # MINIMAL, telemetry-scoped re-transfer: the finalisation needs the telemetry helper, the
    # telemetry prepare receipt, the frozen Procmon authority and the workload receipt, and the
    # malware deletes them (D-141/D-145/D-148). The general LAB_RESTORE stays where the user
    # requires it: after the telemetry finalisation.
    # ---------------------------------------------------------------------------------------
    Stage 'TELEMETRY_RESTORE' 'Re-transmit ONLY the telemetry finalisation inputs (the capture is already closed)'
    Assert-True $Script:CaptureClosedBeforeRestore 'CAPTURE_NOT_CLOSED_BEFORE_THE_TELEMETRY_RESTORE'
    $RestoreSw=[Diagnostics.Stopwatch]::StartNew()
    $Script:LabRestoreStartUtc=[DateTime]::UtcNow.ToString('o')
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Telemetry.ps1') $guestTel
    if (Test-Path -LiteralPath $telePrepHost -PathType Leaf) {
        Copy-ToGuest $telePrepHost ($guestCapture+'\prepare_receipt.json')
        Write-Host 'TELEMETRY PREPARE RECEIPT RE-TRANSMITTED INTO THE GUEST' -ForegroundColor Green
    } else { Write-Log 'WARN' 'the telemetry prepare receipt was not preserved on the host; the telemetry finalisation may fail' }
    # D-156: the workload receipt is the finalisation's root-process binding (root_pid, the
    # sample's start/stop UTC and the termination mode). The malware can delete it as well, so
    # the host's preserved copy is re-transmitted.
    Copy-ToGuest $sampleRunHost $guestSampleRun
    Write-Host 'SAMPLE EXECUTE RECEIPT RE-TRANSMITTED INTO THE GUEST (the finalisation binds the root process)' -ForegroundColor Green
    # D-148: the frozen Procmon authority contract is the SECOND lab artifact the malware deleted
    # on 2026-11-13 (Akira, RAN_WIN_06_A): the prepare had PASSed, the sample ran its full window,
    # and the finalisation then failed with FROZEN_PROCMON_AUTHORITY_MISSING. The exact frozen
    # artifact - hash-pinned in the R7 package manifest - is re-transmitted here and verified
    # INSIDE the guest (exit code 3 = missing, 4 = hash, 5 = bytes) before finalisation reads it.
    # Probe the guest's own copy BEFORE the restore, so the evidence distinguishes "the malware
    # deleted/corrupted the lab artifact" from "the baseline drifted". Exit 10 = missing,
    # 11 = hash mismatch, 12 = byte mismatch, 0 = already the frozen artifact.
    $authProbe="`$ErrorActionPreference='Stop';`$p='"+$ProcmonAuthorityGuestPath+"';if(-not(Test-Path -LiteralPath `$p -PathType Leaf)){exit 10};`$h=(Get-FileHash -LiteralPath `$p -Algorithm SHA256).Hash.ToLowerInvariant();if(`$h -cne '"+$ProcmonAuthoritySha256+"'){exit 11};if((Get-Item -LiteralPath `$p).Length -ne "+$ProcmonAuthorityBytes+"){exit 12};exit 0"
    $probeRc=Invoke-HCQEncoded $authProbe 120
    $guestStateBefore=$(switch($probeRc){0{'FROZEN_HASH_PRESENT'}10{'MISSING'}11{'HASH_MISMATCH'}12{'BYTE_MISMATCH'}default{'PROBE_ERROR_'+$probeRc}})
    Write-Host ('FROZEN PROCMON AUTHORITY GUEST STATE BEFORE RESTORE: '+$guestStateBefore+' (probe exit '+$probeRc+')') -ForegroundColor Yellow
    # D-150: the frozen artifact is READ-ONLY in the guest (the R8 deployment sets IsReadOnly), so a
    # VIX copy onto it fails with error 13 - observed on RAN_WIN_01_A on 2026-11-13 even though the
    # probe showed the frozen hash was already present. No copy is attempted when the guest copy
    # already matches; a real restore clears the attribute first and restores it afterwards.
    $authRestoreAction='ALREADY_FROZEN_NO_COPY_NEEDED'
    if($guestStateBefore -cne 'FROZEN_HASH_PRESENT'){
        $authRestoreAction='RE_TRANSMITTED_FROM_HOST'
        $authUnlock="`$p='"+$ProcmonAuthorityGuestPath+"';if(Test-Path -LiteralPath `$p -PathType Leaf){(Get-Item -LiteralPath `$p).IsReadOnly=`$false};exit 0"
        $null=Invoke-HCQEncoded $authUnlock 120
        Copy-ToGuest $ProcmonAuthorityHost $ProcmonAuthorityGuestPath
    }
    $authVerify="`$ErrorActionPreference='Stop';`$p='"+$ProcmonAuthorityGuestPath+"';if(-not(Test-Path -LiteralPath `$p -PathType Leaf)){exit 3};`$h=(Get-FileHash -LiteralPath `$p -Algorithm SHA256).Hash.ToLowerInvariant();`$b=(Get-Item -LiteralPath `$p).Length;if(`$h -cne '"+$ProcmonAuthoritySha256+"'){exit 4};if(`$b -ne "+$ProcmonAuthorityBytes+"){exit 5};exit 0"
    $authRc=Invoke-HCQEncoded $authVerify 120
    Assert-True ($authRc -eq 0) ('FROZEN_PROCMON_AUTHORITY_GUEST_HASH_MISMATCH:exit='+$authRc)
    $authLock="`$p='"+$ProcmonAuthorityGuestPath+"';if(Test-Path -LiteralPath `$p -PathType Leaf){(Get-Item -LiteralPath `$p).IsReadOnly=`$true};exit 0"
    $null=Invoke-HCQEncoded $authLock 120
    $Script:ProcmonAuthorityVerified=$true
    $Script:ProcmonAuthorityRetransmitted=($authRestoreAction -ceq 'RE_TRANSMITTED_FROM_HOST')
    Write-Json (Join-Path $Script:RunRoot 'evidence\frozen_procmon_authority_restore.json') ([ordered]@{schema_version='1.0';gate='FROZEN_PROCMON_AUTHORITY_RESTORE';status='PASS';run_id=$RunID;attempt_id=$Script:AttemptID;authority_guest_path=$ProcmonAuthorityGuestPath;authority_sha256=$ProcmonAuthoritySha256;authority_bytes=$ProcmonAuthorityBytes;host_source=$Script:ProcmonAuthoritySource;guest_state_before_restore=$guestStateBefore;restore_action=$authRestoreAction;guest_hash_verified=$true;guest_hash_verified_exit_code=$authRc;frozen_read_only_restored=$true;contents_altered=$false;raw_capture_substituted=$false;capture_closed_before_restore=$true;timestamp=[DateTime]::UtcNow.ToString('o')})
    if($authRestoreAction -ceq 'RE_TRANSMITTED_FROM_HOST'){Write-Host 'FROZEN PROCMON AUTHORITY RE-TRANSMITTED INTO THE GUEST' -ForegroundColor Green}else{Write-Host 'FROZEN PROCMON AUTHORITY ALREADY PRESENT AT THE FROZEN HASH - no copy needed' -ForegroundColor Green}
    # D-156: the independent, in-guest proof that the capture is closed. Procmon must NOT be
    # running at this point. If it were, the restore would be inside an active capture.
    $captureProbe="`$ErrorActionPreference='Stop';`$n=@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count;if(`$n -ne 0){exit 1};exit 0"
    $captureProbeRc=Invoke-HCQEncoded $captureProbe 60
    Assert-True ($captureProbeRc -eq 0) ('PROCMON_STILL_RUNNING_DURING_THE_TELEMETRY_RESTORE:exit='+$captureProbeRc)
    Write-Host 'CAPTURE CLOSED PROOF: Procmon is NOT running in the guest (the capture was stopped inside the guest executor before the restore).' -ForegroundColor Green
    $RestoreSw.Stop()
    $Script:TelemetryRestoreSeconds=[Math]::Round($RestoreSw.Elapsed.TotalSeconds,3)

    Stage 'TELEMETRY_FINALIZE' 'Verify the raw PML and build the compact Sysmon process-tree proof (the capture is already closed)'
    $FinalizeHostSw=[Diagnostics.Stopwatch]::StartNew()
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestTel`" -Mode Finalize -AttemptID $($Script:AttemptID) -RunID $RunID -GlobalOrder $ExecutionOrder -OutputRoot `"$guestCapture`" -WorkloadReceiptPath `"$guestSampleRun`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('TELEMETRY_FINALIZE_FAILED:'+ $r.Text)
    $FinalizeHostSw.Stop()
    $Script:FinalizeSeconds=[Math]::Round($FinalizeHostSw.Elapsed.TotalSeconds,3)
    Copy-FromGuest ($guestCapture+'\capture_receipt.json') $teleCapHost
    $tc=Get-Content -LiteralPath $teleCapHost -Raw|ConvertFrom-Json
    Assert-True ([string]$tc.status -ceq 'PASS') 'TELEMETRY_CAPTURE_RECEIPT_FAIL'
    Assert-True ([int64]$tc.capture_pml_bytes -gt 0) 'PROCMON_PML_EMPTY'
    Assert-True (-not[bool]$tc.capture_csv_materialized) 'FULL_CSV_SHOULD_BE_DEFERRED'
    Assert-True ([int]$tc.event_loss_count -eq 0) ('TELEMETRY_EVENT_LOSS:'+ $tc.event_loss_count)
    # D-156: the capture receipt must agree with the capture-stop receipt written by the
    # executor: the capture window is closed at the SAME instant in both, and the finalisation
    # happens strictly afterwards.
    Assert-True ([bool]$tc.capture_closed_before_finalize) 'CAPTURE_NOT_CLOSED_BEFORE_FINALIZE'
    Assert-True (-not [bool]$tc.lab_restore_inside_capture) 'LAB_RESTORE_INSIDE_CAPTURE'
    Assert-True ([string]$tc.capture_stop_utc -ceq $Script:CaptureStopUtc) ('CAPTURE_STOP_UTC_MISMATCH:'+ [string]$tc.capture_stop_utc+' vs '+$Script:CaptureStopUtc)
    $Script:CaptureStartUtc=[string]$tc.capture_start_utc
    $Script:CaptureWindowSeconds=[double]$tc.capture_window_seconds
    # D-156: the capture window is the SCIENTIFIC capture: the sample's window plus the bounded
    # tail plus the stop overhead. It must NOT contain any host orchestration.
    $captureWindowBudget = ([double]$ObservationWindowSeconds + [double]$WatchdogSeconds + [double]$PostTailSeconds + 30.0)
    Assert-True ($Script:CaptureWindowSeconds -gt 0) 'CAPTURE_WINDOW_SECONDS_NOT_POSITIVE'
    Assert-True ($Script:CaptureWindowSeconds -le $captureWindowBudget) ('CAPTURE_WINDOW_OUTSIDE_THE_ACCEPTANCE_BUDGET:'+ $Script:CaptureWindowSeconds+'s > '+$captureWindowBudget+'s')
    # D-156/D-165: the finalisation is a separate, measured phase and must not be confused with the
    # capture. The 120 s limit was an arbitrary engineering safeguard (Category B) TIGHTER than the
    # guest finalize subprocess's own 300 s WaitForExit bound (Invoke-GuestPowerShell) - the
    # controller rejected work its mechanism was permitted to finish (2026-11-15 LCRYX attempt:
    # 122.869 s guest / 131.267 s host). The bound is DERIVED FROM THE MECHANISM: the finalize may
    # take at most as long as the WaitForExit budget frozen at the call site. Genuine stalls still
    # fail closed (the subprocess throws 'Requested guest process timeout' at 300 s and the run
    # fails as TELEMETRY_FINALIZE_FAILED before this assertion). Capture closure and evidence
    # integrity are gated separately; the measured duration is always recorded in the receipt.
    Assert-True ($Script:FinalizeSeconds -le 300.0) ('TELEMETRY_FINALIZE_TOO_SLOW:'+ $Script:FinalizeSeconds+'s')

    # D-041: the telemetry capture receipt must carry the same termination evidence as the workload receipt.
    Assert-True ([string]$tc.termination_mode -ceq $Script:TerminationMode) ('TELEMETRY_TERMINATION_MODE_MISMATCH:'+ [string]$tc.termination_mode+' vs '+$Script:TerminationMode)
    Assert-True ([int]$tc.exit_code -eq [int]$Script:SampleExitCode) ('TELEMETRY_EXIT_CODE_MISMATCH:'+ [string]$tc.exit_code+' vs '+[string]$Script:SampleExitCode)
    Assert-True ([string]$tc.exit_code_source -ceq $Script:ExitCodeSource) ('TELEMETRY_EXIT_CODE_SOURCE_MISMATCH:'+ [string]$tc.exit_code_source+' vs '+$Script:ExitCodeSource)
    Write-Host ('REAL TELEMETRY: PML_BYTES='+$tc.capture_pml_bytes+' EVENT_LOSS='+$tc.event_loss_count+' CAPTURE_WINDOW='+$Script:CaptureWindowSeconds+'s (the scientific capture: sample window + '+$PostTailSeconds+'s tail + stop overhead) POST_WORKLOAD_CAPTURE='+$Script:PostWorkloadCaptureSeconds+'s FINALIZE='+$Script:FinalizeSeconds+'s (orchestration, AFTER the capture was closed)') -ForegroundColor Green

    # D-156: the general LAB_RESTORE, now AFTER the telemetry finalisation and therefore
    # provably outside the capture. It re-transfers the executor, the packer and the antivirus
    # helper for the canary verification and the packing, and the canary reference.
    Stage 'LAB_RESTORE' 'Re-transfer the guest helpers and the canary reference (the capture has been closed for a while)'
    $LabRestoreSw=[Diagnostics.Stopwatch]::StartNew()
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Execute_Official.ps1') $guestExec
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Pack.ps1') $guestPack
    Copy-ToGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Antivirus.ps1') $guestAvHelper
    if (Test-Path -LiteralPath $canaryManifestHost -PathType Leaf) {
        Copy-ToGuest $canaryManifestHost $guestCanaryManifest
        Write-Host 'CANARY REFERENCE RE-TRANSMITTED INTO THE GUEST' -ForegroundColor Green
    } else { Write-Log 'WARN' 'the canary reference was not preserved on the host; the canary verification may fail' }
    $LabRestoreSw.Stop()
    $Script:LabRestoreSeconds=[Math]::Round($LabRestoreSw.Elapsed.TotalSeconds,3)
    Write-Host ('LAB RESTORE COMPLETE: '+$Script:LabRestoreSeconds+'s - AFTER the capture was closed (capture_stop='+$Script:CaptureStopUtc+'), so it CANNOT be inside the capture.') -ForegroundColor Green

    Stage 'CANARY_VERIFY' 'Re-check pre-hashed canary corpus integrity after sample execution'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestExec`" -Mode CanaryVerify -AttemptID $($Script:AttemptID) -ReceiptPath `"$guestCanaryReceipt`" -WorkRoot `"$guestWorkRoot`" -CanaryRoot `"$guestCanaryRoot`" -RunID `"$RunID`" -ExecutionOrder $ExecutionOrder -SampleRunId `"$SampleRunId`" -SampleSha256 $SampleSha256 -SampleBytes $SampleBytes -SampleGuestPath `"$SampleGuestPath`" -ReadOnly $ReadOnly -ModeOctal `"$ModeOctal`" -Split $Split -Repetition $Repetition -TelemetryAdapter `"$TelemetryAdapter`" -ScenarioRunId `"$ScenarioRunId`" -FixtureSeed `"$FixtureSeed`" -GroundTruth $GroundTruth -ProcessDensityRole $ProcessDensityRole -FamilyStratum `"$FamilyStratum`" -EvidenceArchiveFormat $EvidenceArchiveFormat -InvocationMode `"$($Script:InvocationMode)`" -LoaderPath `"$($Script:InvocationLoader)`" -EntryPoint `"$($Script:InvocationEntry)`" -SampleArguments `"$($Script:ResolvedArguments)`" -ArgumentVectorContract `"$($Script:TargetArgumentTemplate)`""
    $r=Invoke-GuestPowerShell $cmd 60;Assert-True ($r.ExitCode -eq 0) ('CANARY_VERIFY_FAILED:'+ $r.Text)
    Copy-FromGuest $guestCanaryReceipt $canaryHost
    $cy=Get-Content -LiteralPath $canaryHost -Raw|ConvertFrom-Json;Assert-True ([string]$cy.status -ceq 'PASS') 'CANARY_RECEIPT_FAIL'
    # D-163: the verification must have read the SAME frozen exposure root, and the separation is
    # re-asserted from the receipt (fail-closed even if the executor were regressed).
    Assert-True ([string]$cy.canary_root -ceq $guestCanaryRoot) ('CANARY_VERIFY_ROOT_MISMATCH:'+ [string]$cy.canary_root+' vs '+$guestCanaryRoot)
    Assert-True ([int]$cy.canary_total -eq 236) ('CANARY_TOTAL_RECEIPT_MISMATCH:'+ [string]$cy.canary_total)
    Write-Host ('CANARY VERIFY: checked='+[string]$cy.canary_checked+' modified='+[string]$cy.canary_modified+' missing='+(@($cy.canary_missing).Count)+' hash_mismatches='+(@($cy.canary_hash_mismatches).Count)+' root='+[string]$cy.canary_root) -ForegroundColor Green
    # Canary modification is recorded as expected ransomware-like behaviour; it does not fail the run.

    Stage 'GUEST_PACK' 'Hash and fast-compress raw Procmon PML + compact process-tree + canary evidence inside guest'
    $PackHostSw=[Diagnostics.Stopwatch]::StartNew()
    $guestZip=$guestCapture+'\capture_archive.zip';$guestPackReceipt=$guestCapture+'\pack_receipt.json'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestPack`" -CaptureDir `"$guestCapture`" -SampleExecuteReceipt `"$guestSampleRun`" -CanaryReceipt `"$guestCanaryReceipt`" -OutputZip `"$guestZip`" -PackReceiptPath `"$guestPackReceipt`" -AttemptID $($Script:AttemptID) -RunID `"$RunID`" -SampleRunId `"$SampleRunId`""
    $r=Invoke-GuestPowerShell $cmd 600;Assert-True ($r.ExitCode -eq 0) ('GUEST_PACK_FAILED:'+ $r.Text)
    $PackHostSw.Stop()
    Copy-FromGuest $guestPackReceipt $packHost
    $pr=Get-Content -LiteralPath $packHost -Raw|ConvertFrom-Json;Assert-True ([string]$pr.status -ceq 'PASS') 'PACK_RECEIPT_FAIL';Assert-True ([bool]$pr.raw_procmon_pml_preserved) 'RAW_PML_NOT_PRESERVED';Assert-True (-not[bool]$pr.derived_full_csv_included) 'DERIVED_FULL_CSV_SHOULD_NOT_BE_PACKED'
    Write-Host ('PACK COMPLETE: ARCHIVE_BYTES='+$pr.archive_bytes+' PACK='+$PackHostSw.Elapsed.TotalSeconds.ToString('F1')+'s') -ForegroundColor Green

    Stage 'ARCHIVE_TRANSFER' 'Transfer compressed archive only; no loose bulk telemetry crosses to host'
    $TransferSw=[Diagnostics.Stopwatch]::StartNew()
    Copy-FromGuest $guestZip $archiveHost 900
    $TransferSw.Stop()
    $hv=Verify-Archive $archiveHost $pr
    $hv.transfer_elapsed_seconds=[Math]::Round($TransferSw.Elapsed.TotalSeconds,3)
    Write-Json (Join-Path $Script:RunRoot 'evidence\HOST_ARCHIVE_VERIFICATION.json') $hv
    Write-Host ('ARCHIVE TRANSFER COMPLETE: '+$TransferSw.Elapsed.TotalSeconds.ToString('F1')+'s') -ForegroundColor Green
    $runSucceeded=$true
}
catch{
    $mainError=$_.Exception.Message
    Write-Host ('RANSOMWARE '+$RunMode.ToUpperInvariant()+' RUN EXECUTION ERROR: '+$mainError) -ForegroundColor Red
}
finally{
    Stage 'RECOVERY' 'Stop Windows, revert exact frozen snapshot, verify Ubuntu unchanged, restore host network, restore VMware GUI entries'
    try{
        # D-136: capture the post-run antivirus state and drop the analysis-window exclusion
        # BEFORE the guest is stopped, so the evidence always records what the antivirus did
        # during the analysis window - on a successful run and on a failed one alike.
        if($Script:AvHelperTransferred){
            try{
                $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestAvHelper`" -Mode Finalize -AttemptID $($Script:AttemptID) -RunID `"$RunID`" -ReceiptPath `"$guestAvPostReceipt`" -AnalysisRoot `"$guestAvRoot`""
                $r=Invoke-GuestPowerShell $cmd 180
                if($r.ExitCode -eq 0){Copy-FromGuest $guestAvPostReceipt $avPostHost}
                else{Write-Log 'WARN' ('antivirus post-state exit '+$r.ExitCode)}
            }catch{Write-Log 'WARN' ('antivirus post-state capture failed: '+$_.Exception.Message)}
        }
        try{Stop-VM $WindowsVmxPath 'Windows'}catch{Write-Log 'WARN' ('Stop error: '+$_.Exception.Message)}
        Revert-ExactSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows'
        Assert-True (-not(Get-VmOn $WindowsVmxPath)) 'WINDOWS_RUNNING_AFTER_RECOVERY'
        Assert-True (-not(Get-VmOn $UbuntuVmxPath)) 'UBUNTU_RUNNING_AFTER_RECOVERY'
        Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows'
        Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'
        if($Script:IsolationStarted -and $null -ne $Script:NetworkBaseline){$postNet=Restore-HostNetwork $Script:NetworkBaseline}else{$postNet=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID}
        $null=Invoke-HCQGuiAttachBoth
        $tabs=@(Get-HCQWorkstationTabNames)
        $guiWin=($tabs -contains 'Windows 11');$guiUbu=($tabs -contains 'Ubuntu')
        Assert-True $guiWin 'WINDOWS_GUI_TAB_NOT_VISIBLE_AFTER_RECOVERY';Assert-True $guiUbu 'UBUNTU_GUI_TAB_NOT_VISIBLE_AFTER_RECOVERY'
        $rec=[ordered]@{status='PASS';windows_off=(-not(Get-VmOn $WindowsVmxPath));ubuntu_off=(-not(Get-VmOn $UbuntuVmxPath));windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot_expected=$WindowsSnapshot;ubuntu_snapshot_expected=$UbuntuSnapshot;network_exactly_restored=$true;network_ssid_agnostic=$true;network_restore_reason=$Script:NetworkRestoreReason;network_restore_attempts=$Script:NetworkRestoreAttempts;network_identity_policy='STABLE physical-adapter identity (alias + interface description + PERMANENT hardware address + adapter state) + a default route; NO dependency on SSID/BSSID/DHCP address/gateway/current randomized MAC';ipv4_default_route_count=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '0.0.0.0/0'}).Count;ipv6_default_route_count=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '::/0'}).Count;vmware_tab_names=$tabs;windows_gui_visible=$guiWin;ubuntu_gui_visible=$guiUbu;measured_utc=[DateTime]::UtcNow.ToString('o')}
        Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') $rec
        $recoverySucceeded=$true
    }catch{$recoveryError=$_.Exception.Message;Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red}
    try{Close-HCQVix}catch{}
}

$authEvidence=[ordered]@{procmon_authority_guest_path=$ProcmonAuthorityGuestPath;procmon_authority_sha256=$ProcmonAuthoritySha256;procmon_authority_bytes=$ProcmonAuthorityBytes;procmon_authority_host_source=$Script:ProcmonAuthoritySource;procmon_authority_preserved_on_host=([bool](Test-Path -LiteralPath $ProcmonAuthorityHost -PathType Leaf));procmon_authority_retransmitted_before_finalize=$Script:ProcmonAuthorityRetransmitted;procmon_authority_guest_hash_verified=$Script:ProcmonAuthorityVerified;procmon_authority_contents_altered=$false;raw_capture_substituted=$false;raw_capture_source='GUEST_RAW_PML_COPIED_UNMODIFIED'}
if(-not $runSucceeded -or -not $recoverySucceeded){
    $result=[ordered]@{schema_version='1.0';gate='RANSOMWARE_OFFICIAL_RUN';status='FAIL';AttemptID=$Script:AttemptID;qualification_only=$QualificationOnly;official_run=$IsOfficial;run_mode=$RunMode;official_campaign_slots_consumed=0;run_id=$RunID;execution_order=$ExecutionOrder;sample_run_id=$SampleRunId;family_stratum=$FamilyStratum;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunId;fixture_seed=$FixtureSeed;lead_application=$FamilyStratum;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole;termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;sample_exit_code_hex=$Script:SampleExitCodeHex;sample_exit_code_class=$Script:SampleExitCodeClass;sample_runtime_seconds=$Script:SampleRuntimeSeconds;kill_settle_seconds=$Script:KillSettleSeconds;invocation_mode=$Script:InvocationMode;invocation_image_type=$Script:InvocationContract;invocation_loader_path=$Script:InvocationLoader;invocation_entry_point=$Script:InvocationEntry;sample_arguments=$Script:InvocationArgs;procmon_authority=$authEvidence;sample_transport_lost=$Script:SampleTransportLost;sample_transport_recovered=$Script:SampleTransportRecovered;sample_transport_wait_seconds=$Script:SampleTransportWaitSeconds;sample_receipt_recovered=$Script:SampleReceiptRecovered;execution_error=$mainError;recovery_error=$recoveryError;run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')};Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') $result;throw ('RANSOMWARE_OFFICIAL_RUN_FAIL run_id='+$RunID+' execution='+$mainError+' recovery='+$recoveryError)
}
Stage 'PACKAGE_VERIFY' 'Create complete run manifest and verify all listed evidence hashes'
$OverallSw.Stop()
$result=[ordered]@{schema_version='1.0';gate='RANSOMWARE_OFFICIAL_RUN';status='PASS';AttemptID=$Script:AttemptID;qualification_only=$QualificationOnly;official_run=$IsOfficial;run_mode=$RunMode;official_campaign_slots_consumed=$SlotsConsumed;run_id=$RunID;execution_order=$ExecutionOrder;sample_run_id=$SampleRunId;family_stratum=$FamilyStratum;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunId;fixture_seed=$FixtureSeed;lead_application=$FamilyStratum;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole;telemetry=$TelemetryAdapter;evidence_archive_format=$EvidenceArchiveFormat;csv_materialization='DEFERRED_OFFLINE';compressed_only_bulk_telemetry_on_host=$true;recovery_verified=$true;procmon_authority=$authEvidence;watchdog_armed=$Script:WatchdogArmed;termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;sample_exit_code=$Script:SampleExitCode;sample_exit_code_hex=$Script:SampleExitCodeHex;sample_exit_code_class=$Script:SampleExitCodeClass;actual_execution_seconds=$Script:ActualExecutionSeconds;sample_runtime_seconds=$Script:SampleRuntimeSeconds;kill_settle_seconds=$Script:KillSettleSeconds;scientific_runtime_seconds=$Script:SampleRuntimeSeconds;invocation_mode=$Script:InvocationMode;invocation_image_type=$Script:InvocationContract;invocation_loader_path=$Script:InvocationLoader;invocation_entry_point=$Script:InvocationEntry;sample_arguments=$Script:InvocationArgs;resolved_argument_vector=$Script:ResolvedArguments;argument_vector_contract=$Script:TargetArgumentTemplate;target_mechanism=$Script:TargetMechanism;target_evidence_ref=$Script:TargetEvidenceRef;sample_transport_lost=$Script:SampleTransportLost;sample_transport_recovered=$Script:SampleTransportRecovered;sample_transport_wait_seconds=$Script:SampleTransportWaitSeconds;sample_receipt_recovered=$Script:SampleReceiptRecovered;termination_overhead_seconds=$Script:KillSettleSeconds;telemetry_tail_seconds=$PostTailSeconds;post_workload_capture_seconds=$Script:PostWorkloadCaptureSeconds;capture_stop_overhead_seconds=$Script:CaptureStopOverheadSeconds;capture_start_utc=$Script:CaptureStartUtc;capture_stop_utc=$Script:CaptureStopUtc;capture_window_seconds=$Script:CaptureWindowSeconds;capture_closed_before_restore=$Script:CaptureClosedBeforeRestore;lab_restore_inside_capture=$false;telemetry_restore_seconds=$Script:TelemetryRestoreSeconds;lab_restore_seconds=$Script:LabRestoreSeconds;finalization_orchestration_seconds=[Math]::Round($FinalizeHostSw.Elapsed.TotalSeconds,3);observation_window_seconds=$ObservationWindowSeconds;post_tail_seconds=$PostTailSeconds;watchdog_seconds=$WatchdogSeconds;workload=($SampleRunId+'_'+$FamilyStratum+'_RANSOMWARE_V1');telemetry_finalize_seconds=[Math]::Round($FinalizeHostSw.Elapsed.TotalSeconds,3);pack_seconds=[Math]::Round($PackHostSw.Elapsed.TotalSeconds,3);archive_transfer_seconds=[Math]::Round($TransferSw.Elapsed.TotalSeconds,3);total_run_seconds=[Math]::Round($OverallSw.Elapsed.TotalSeconds,3);run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')}
Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') $result
$manifest=New-RunManifest $Script:RunRoot
$rows=@(Import-Csv -LiteralPath $manifest);$pass=0;$fail=0;$details=@();foreach($row in $rows){$p=Join-Path $Script:RunRoot $row.relative_path;if((Test-Path -LiteralPath $p -PathType Leaf) -and ((Get-Item $p).Length -eq [int64]$row.bytes) -and ((SHA $p) -ceq [string]$row.sha256)){$pass++;$details+=[ordered]@{path=$row.relative_path;status='PASS'}}else{$fail++;$details+=[ordered]@{path=$row.relative_path;status='FAIL'}}};$full=[ordered]@{status=$(if($fail-eq0){'PASS'}else{'FAIL'});manifest_path=$manifest;manifest_sha256=(SHA $manifest);pass=$pass;fail=$fail;details=$details;timestamp=[DateTime]::UtcNow.ToString('o')};Write-Json (Join-Path $Script:RunRoot 'RUN_FULL_VERIFICATION.json') $full;Assert-True ($fail -eq 0) 'RUN_PACKAGE_SELF_VERIFICATION_FAILED'
Write-Host '';Write-Host ('FINAL WINDOWS '+$RunMode.ToUpperInvariant()+' RANSOMWARE RUN PASS: '+$RunID) -ForegroundColor Green;Write-Host ('Evidence package: '+$Script:RunRoot) -ForegroundColor Green;if($IsOfficial){Write-Host ('Official ransomware campaign slot completed: '+$ExecutionOrder+'/40; run_id='+$RunID) -ForegroundColor Yellow}else{Write-Host ('Mode='+$RunMode+'; campaign slots consumed=0; run_id='+$RunID) -ForegroundColor Yellow};Write-Host ('TOTAL OFFICIAL RUN SECONDS: '+$OverallSw.Elapsed.TotalSeconds.ToString('F1')) -ForegroundColor Green
$Script:RunRoot
