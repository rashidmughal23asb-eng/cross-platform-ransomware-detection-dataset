# RANSOMWARE_Official_Run_Controller.ps1
#
# Ubuntu ransomware official-run controller.
# Pattern: identical scaffolding to Ubuntu_Benign_Official_Run_Controller.ps1 (native VIX,
# Credential Manager transport via sudo credential file, snapshot revert per run,
# fail-closed gates, evidence packaging). Diverges per the ransomware threat model:
# live-sample execution under a bounded 60-s observation window + fixed 5-10 s post-exit
# telemetry tail + 90-s watchdog, canary corpus, host-only isolation verified from inside
# the guest. Samples are root-owned 0400, so the guest executor runs as root via the
# transferred sudo credential on stdin; the password is never in argv.
#
# Timing model: DECISIONS.md D-038 (expected_duration_seconds = 60; no fill-to-60; no
# rerun on natural early exit). Telemetry: DECISIONS.md D-039 (bpftrace+auditd).
# Split/manifest: DECISIONS.md D-037 (family-level 11/4/4 frozen).
#
# No secrets in scripts; credentials come from Credential Manager.
#
# RunMode: Pilot | Preflight | Official. Only Official consumes a campaign slot (1 of 40).
# Pilot/Preflight write to pilot_runs/ / preflight_runs/ and always record 0 slots consumed.
#
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$CampaignRoot,
 [Parameter(Mandatory=$true)][ValidateSet('Pilot','Preflight','Official')][string]$RunMode,
 [string]$VmrunPath='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
 [string]$VMwareGuiPath='C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
 [string]$WindowsVmxPath='D:\Windows 11\Windows 11.vmx',
 [string]$UbuntuVmxPath='D:\Ubuntu 24.04\Ubuntu.vmx',
 [string]$WindowsSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013',
 # D-115: the campaign baseline is the V11 post-materialization OFFLINE snapshot (the ten
 # qualified families are materialised there); the R5 baseline is preserved as the
 # qualification baseline of the earlier evidence.
 [string]$UbuntuSnapshot='P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112',
 [int]$PreRollSeconds=5,[int]$PostTailSeconds=10,[int]$ObservationWindowSeconds=60,[int]$WatchdogSeconds=90,
 [Parameter(Mandatory=$true)][ValidatePattern('^RAN_UBU_[0-9]{2}_[AB]$')][string]$RunID,
 [Parameter(Mandatory=$true)][ValidateRange(1,40)][int]$ExecutionOrder,
 [Parameter(Mandatory=$true)][ValidatePattern('^L-R-[0-9]{2}$')][string]$SampleRunId,
 [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9./\-]+$')][string]$FamilyStratum,
 [Parameter(Mandatory=$true)][ValidateSet('TRAIN','VALIDATION','TEST')][string]$Split,
 [Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Repetition,
 [Parameter(Mandatory=$true)][ValidatePattern('^L-R-[0-9]{2}-[AB]$')][string]$ScenarioRunId,
 [Parameter(Mandatory=$true)][ValidatePattern('^R[0-9]{2}-UBU-[AB]$')][string]$FixtureSeed,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{64}$')][string]$SampleSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+$')][string]$SampleBytes,
 [Parameter(Mandatory=$true)][string]$SampleGuestPath,
 [Parameter(Mandatory=$true)][ValidateSet('True')][string]$ReadOnly,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-7]{4}$')][string]$ModeOctal,
 [Parameter(Mandatory=$true)][ValidateSet('RANSOMWARE')][string]$GroundTruth,
 [Parameter(Mandatory=$true)][ValidateSet('MALICIOUS_PRIMARY_SUBJECT')][string]$ProcessDensityRole,
 [Parameter(Mandatory=$true)][ValidateSet('tar.gz')][string]$EvidenceArchiveFormat,
 [Parameter(Mandatory=$true)][ValidateSet('bpftrace+auditd')][string]$TelemetryAdapter,
 [Parameter(Mandatory=$true)][ValidateSet('PENDING')][string]$Status
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false
$Script:WatchdogArmed=$false;$Script:GuestSampleExecuteExitCode=$null;$Script:SampleExitCode=$null;$Script:ActualExecutionSeconds=$null
$Script:TerminationMode=$null;$Script:ExitCodeSource=$null;$Script:WatchdogFired=$false;$Script:ProcessTreeKilled=$false
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};[IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 20)+"`r`n"),(New-Object Text.UTF8Encoding($false)))}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'RANSOMWARE_OFFICIAL_CONTROLLER.log') -Value $line -Encoding UTF8}}
function Stage([string]$Name,[string]$Message){$Script:Stage=$Name;Write-Host '';Write-Host ('='*88) -ForegroundColor Cyan;Write-Host ('[{0}] {1}' -f $Name,$Message) -ForegroundColor Cyan;Write-Host ('='*88) -ForegroundColor Cyan;Write-Log 'INFO' $Message}
function Get-UniqueVmsd([string]$Vmx){$a=@(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File);Assert-True ($a.Count -eq 1) ('VMSD_NOT_UNIQUE:'+ $Vmx);$a[0].FullName}
function Get-CurrentSnapshotName([string]$Vmx,[string]$Label){$lines=[IO.File]::ReadAllLines((Get-UniqueVmsd $Vmx));$cur='';$map=@{};foreach($l in $lines){$m=[regex]::Match($l,'^\s*snapshot\.current\s*=\s*"([^"]*)"');if($m.Success){$cur=$m.Groups[1].Value};$m=[regex]::Match($l,'^\s*snapshot(\d+)\.(uid|displayName)\s*=\s*"([^"]*)"');if($m.Success){$i=[int]$m.Groups[1].Value;if(-not$map.ContainsKey($i)){$map[$i]=@{}};$map[$i][$m.Groups[2].Value]=$m.Groups[3].Value}};Assert-True (-not[string]::IsNullOrWhiteSpace($cur)) ($Label+'_NO_CURRENT_SNAPSHOT');foreach($i in $map.Keys){if([string]$map[$i]['uid'] -ceq $cur){return [string]$map[$i]['displayName']}};throw ($Label+'_SNAPSHOT_UID_UNMAPPED')}
function Assert-CurrentSnapshot([string]$Vmx,[string]$Expected,[string]$Label){$a=Get-CurrentSnapshotName $Vmx $Label;Assert-True ($a -ceq $Expected) ($Label+'_SNAPSHOT_DRIFT expected='+$Expected+' actual='+$a)}
function Get-VmxAssignments([string]$Path){$m=@{};foreach($line in [IO.File]::ReadAllLines($Path)){$x=[regex]::Match($line,'^\s*([^#][^=]*?)\s*=\s*"([^"]*)"\s*$');if($x.Success){$m[$x.Groups[1].Value.Trim().ToLowerInvariant()]=$x.Groups[2].Value}};$m}
function Assert-VmxHardening([string]$Label,[string]$Path){$a=Get-VmxAssignments $Path;$req=[ordered]@{'isolation.tools.copy.disable'='TRUE';'isolation.tools.paste.disable'='TRUE';'isolation.tools.dnd.disable'='TRUE';'isolation.tools.hgfs.disable'='TRUE';'sharedfolder.maxnum'='0';'sharedfolder0.enabled'='FALSE';'sharedfolder0.present'='FALSE';'sharedfolder0.readaccess'='FALSE';'sharedfolder0.writeaccess'='FALSE';'ethernet0.startconnected'='FALSE';'usb.present'='FALSE'};foreach($k in $req.Keys){Assert-True $a.ContainsKey($k) ($Label+'_VMX_MISSING_'+$k);Assert-True ([string]$a[$k] -ceq [string]$req[$k]) ($Label+'_VMX_DRIFT_'+$k+'='+$a[$k])}}
function Disable-HostNetwork([object]$Baseline){$ups=@($Baseline.PhysicalAdapters|Where-Object{$_.InitialStatus -ceq 'Up'});Assert-True ($ups.Count -ge 1) 'NO_UP_PHYSICAL_ADAPTER';foreach($a in $ups){Disable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop};Start-Sleep -Seconds 3;$Script:IsolationStarted=$true;Write-Json (Join-Path $Script:RunRoot 'evidence\HOST_ISOLATION_PROOF.json') ([ordered]@{status='PASS';disabled_adapters=@($ups.Name);ipv4_default_route_count=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '0.0.0.0/0'}).Count;ipv6_default_route_count=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '::/0'}).Count;timestamp=[DateTime]::UtcNow.ToString('o')})}
function Restore-HostNetwork([object]$Baseline){
    foreach($a in @($Baseline.PhysicalAdapters)){if([string]$a.InitialStatus -ceq 'Up'){Enable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop}}
    $deadline=[DateTime]::UtcNow.AddSeconds(300);$attempt=0;$consecutiveRestored=0;$last='NOT_TESTED'
    do{Start-Sleep -Seconds 2;$attempt++;$cur=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID;$check=Test-P5GNetworkRestored $Baseline $cur.PhysicalAdapters $cur.Routes ([pscustomobject]@{vms_safe=$true});if([bool]$check.restored){$consecutiveRestored++;if($consecutiveRestored -ge 3){Write-Host ('NETWORK ADAPTER RESTORE CONFIRMED: attempts='+$attempt+' consecutive_restored='+$consecutiveRestored) -ForegroundColor Green;return $cur}}else{$consecutiveRestored=0;$last=[string]$check.reason;if(($attempt % 10) -eq 0){Write-Host ('NETWORK ADAPTER RESTORE WAITING: attempts='+$attempt+' last_reason='+$last) -ForegroundColor Yellow}}}
    while([DateTime]::UtcNow -lt $deadline)
    throw ('NETWORK_ADAPTER_RESTORE_NOT_CONFIRMED:attempts='+$attempt+':last_reason='+$last)
}
function Open-VMwareGuiTab([string]$Vmx,[string]$Label){Write-Log 'INFO' ('opening VMware GUI tab: '+$Label);[void](Start-Process -FilePath $VMwareGuiPath -ArgumentList ('"'+$Vmx+'"') -WindowStyle Normal -PassThru)}
try{Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop;Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop}catch{throw ('UIAUTOMATION_UNAVAILABLE:'+ $_.Exception.Message)}
function Get-VmwareLockOwnerPid{ $owners=New-Object 'Collections.Generic.List[int]';foreach($v in @($WindowsVmxPath,$UbuntuVmxPath)){$lck=$v+'.lck';if(-not(Test-Path -LiteralPath $lck -PathType Container)){continue};foreach($f in @(Get-ChildItem -LiteralPath $lck -File -ErrorAction SilentlyContinue)){$txt='';try{$txt=Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue}catch{};$m=[regex]::Match([string]$txt,'(\d{3,6})-\d+\(vmware\.exe\)');if($m.Success){$pid2=[int]$m.Groups[1].Value;if(-not$owners.Contains($pid2)){$owners.Add($pid2)}}}};return @($owners.ToArray()) }
function Get-WorkstationTabNames{ $procs=@(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue|Where-Object{$_.MainWindowHandle -ne 0});if($procs.Count -eq 0){return @()};$owners=@(Get-VmwareLockOwnerPid);$ordered=@();foreach($o in $owners){$ordered+=@($procs|Where-Object{$_.Id -eq $o})};$ordered+=@($procs|Where-Object{$owners -notcontains $_.Id});foreach($proc in $ordered){$root=$null;try{$root=[System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)}catch{};if($null -eq $root){continue};$walker=[System.Windows.Automation.TreeWalker]::RawViewWalker;$stack=New-Object System.Collections.Stack;$stack.Push($root);$found=New-Object 'Collections.Generic.List[string]';$guard=0;while($stack.Count -gt 0 -and $guard -lt 3000){$guard++;$e=$stack.Pop();$cls='';try{$cls=[string]$e.Current.ClassName}catch{};if($cls -ceq 'vmware.TabStrip'){$ch=$walker.GetFirstChild($e);while($null -ne $ch){$ccls='';try{$ccls=[string]$ch.Current.ClassName}catch{};if($ccls -ceq 'CNoFlickerButton'){$nm='';try{$nm=[string]$ch.Current.Name}catch{};if(-not[string]::IsNullOrWhiteSpace($nm)){$found.Add($nm)}};$ch=$walker.GetNextSibling($ch)}};$kid=$walker.GetFirstChild($e);while($null -ne $kid){$stack.Push($kid);$kid=$walker.GetNextSibling($kid)}};if($found.Count -gt 0){return @($found.ToArray()|Sort-Object -Unique)}};return @() }
function Remove-RogueVmwareInstances{ $owners=@(Get-VmwareLockOwnerPid);foreach($proc in @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)){if($owners -contains $proc.Id){continue};try{$proc|Stop-Process -Force -ErrorAction SilentlyContinue}catch{}};Start-Sleep -Milliseconds 500 }
function Ensure-GuiEntries{
    $beforeW=Get-VmOn $VmrunPath $WindowsVmxPath
    $beforeU=Get-VmOn $VmrunPath $UbuntuVmxPath
    $names=@(Get-WorkstationTabNames)
    if($names -notcontains 'Windows 11'){Open-VMwareGuiTab $WindowsVmxPath 'Windows'}
    $names=@(Get-WorkstationTabNames)
    if($names -notcontains 'Ubuntu'){Open-VMwareGuiTab $UbuntuVmxPath 'Ubuntu'}
    $deadline=[DateTime]::UtcNow.AddSeconds(90);$final=@()
    do{Start-Sleep -Seconds 3;$final=@(Get-WorkstationTabNames);if(($final -contains 'Windows 11') -and ($final -contains 'Ubuntu')){break}}while([DateTime]::UtcNow -lt $deadline)
    Write-Log 'INFO' ('VMware GUI tabs detected: '+(@($final) -join ','))
    Assert-True ($final -contains 'Windows 11') 'WINDOWS_GUI_TAB_NOT_VISIBLE'
    Assert-True ($final -contains 'Ubuntu') 'UBUNTU_GUI_TAB_NOT_VISIBLE'
    Assert-True ((Get-VmOn $VmrunPath $WindowsVmxPath) -eq $beforeW) 'GUI_ATTACH_CHANGED_WINDOWS_POWER'
    Assert-True ((Get-VmOn $VmrunPath $UbuntuVmxPath) -eq $beforeU) 'GUI_ATTACH_CHANGED_UBUNTU_POWER'
}
function New-RunManifest([string]$Root){$rows=@();foreach($f in Get-ChildItem -LiteralPath $Root -Recurse -File|Sort-Object FullName){if($f.Name -in @('PACKAGE_MANIFEST.csv','RUN_FULL_VERIFICATION.json')){continue};$rows+=[pscustomobject]@{relative_path=$f.FullName.Substring($Root.Length+1);bytes=$f.Length;sha256=(SHA $f.FullName)}};$p=Join-Path $Root 'PACKAGE_MANIFEST.csv';$rows|Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8;return $p}
function Save-UbuntuGuestDiagnostics([string]$GuestRunRoot){
    if([string]::IsNullOrWhiteSpace($GuestRunRoot)){return}
    $dst=Join-Path $Script:RunRoot 'evidence\guest_diagnostics';New-Item -ItemType Directory -Path $dst -Force|Out-Null
    $rels=@('work/guest_helper_sample_prepare.log','work/guest_helper_telemetry_start.log','work/guest_helper_sample_execute.log','work/guest_helper_telemetry_finalize.log','work/guest_helper_canary_verify.log','work/guest_helper_pack.log','evidence/bpftrace.stderr.txt','evidence/bpftrace.dryrun.stderr.txt','evidence/sample.stdout.txt','evidence/sample.stderr.txt','evidence/sample_prepare_receipt.json','evidence/telemetry_prepare_receipt.json','evidence/sample_execute_receipt.json','evidence/telemetry_capture_receipt.json','evidence/canary_integrity_receipt.json','evidence/guest_pack_receipt.json')
    foreach($rel in $rels){try{Copy-FromUbuntuGuest ($GuestRunRoot+'/'+$rel) (Join-Path $dst ($rel -replace '/','_'))}catch{}}
}

$PackageRoot=$PSScriptRoot
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'UbuntuNativeBridge.ps1')
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
foreach($p in @($CampaignRoot,$VmrunPath,$VMwareGuiPath,$WindowsVmxPath,$UbuntuVmxPath)){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
Assert-VmxHardening 'Windows' $WindowsVmxPath;Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_RUN';Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_RUN'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'
$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16);$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$IsOfficial=($RunMode -ceq 'Official');$QualificationOnly=(-not $IsOfficial);$SlotsConsumed=$(if($IsOfficial){1}else{0})
$RunSubdir=$(if($IsOfficial){'official_runs'}elseif($RunMode -ceq 'Preflight'){'preflight_runs'}else{'pilot_runs'})
$Script:RunRoot=Join-Path $CampaignRoot ('05_UBUNTU\RANSOMWARE\'+$RunSubdir+'\'+$RunID+'_'+$Script:AttemptID+'_'+$stamp);New-Item -ItemType Directory -Path $Script:RunRoot -Force|Out-Null;foreach($d in @('evidence','recovery')){New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot $d) -Force|Out-Null}
$Overall=[Diagnostics.Stopwatch]::StartNew();$runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError='';$guestRunRoot=$null
try{
 Stage 'PRESTATE' 'Verify exact snapshots, hardening, VM state, and VMware GUI entries';Ensure-GuiEntries;$Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID;Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline
 Stage 'ISOLATION' 'Disable baseline physical adapters and require zero IPv4/IPv6 default routes';Disable-HostNetwork $Script:NetworkBaseline
 Stage 'VM_START' 'Power on Ubuntu by native VIX; Windows remains OFF';Start-UbuntuVM $VmrunPath $UbuntuVmxPath;Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_POWERED_ON_UNEXPECTEDLY';Ensure-GuiEntries
 $guestHelper='/tmp/RANSOMWARE_Guest_Official_'+$RunID+'_'+$Script:AttemptID+'.sh';$guestTrace='/tmp/RANSOMWARE_Compound_Trace_'+$Script:AttemptID+'.bt';$guestCred='/tmp/RANSOMWARE_UBUNTU_OFFICIAL_'+$RunID+'_'+$Script:AttemptID+'.sudo';$guestRunRoot='/tmp/ransomware_official/'+$RunID+'/'+$Script:AttemptID;$guestArchive='/tmp/RANSOMWARE_UBUNTU_OFFICIAL_'+$RunID+'_'+$Script:AttemptID+'.tar.gz'
 Stage 'HELPER_TRANSFER' 'Transfer ransomware Ubuntu executor, telemetry, and packer helpers by native VIX';Copy-ToUbuntuGuest (Join-Path $PackageRoot 'RANSOMWARE_Guest_Official.sh') $guestHelper;Copy-ToUbuntuGuest (Join-Path $PackageRoot 'UBUNTU_Compound_Trace.bt') $guestTrace;New-UbuntuSudoCredentialFile $guestCred|Out-Null
 Stage 'SAMPLE_PREPARE' ($RunMode+' '+$RunID+' '+$SampleRunId+' '+$FamilyStratum+': stage sample read-only (root-owned 0400), stage canary corpus, verify isolation from inside guest as root')
 $rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper sample_prepare $($Script:AttemptID) $guestRunRoot $SampleSha256 $SampleBytes $SampleGuestPath $ModeOctal $guestCred ubuntu $SampleRunId $FamilyStratum $Split $Repetition $ScenarioRunId $FixtureSeed $GroundTruth $ProcessDensityRole $TelemetryAdapter $EvidenceArchiveFormat $RunID $ExecutionOrder" 300;Assert-True ($rc -eq 0) 'UBUNTU_SAMPLE_PREPARE_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/sample_prepare_receipt.json') (Join-Path $Script:RunRoot 'evidence\sample_prepare_receipt.json');$sp=Get-Content (Join-Path $Script:RunRoot 'evidence\sample_prepare_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$sp.status -ceq 'PASS') 'UBUNTU_SAMPLE_PREPARE_RECEIPT_FAIL';Assert-True ([bool]$sp.isolation_verified) 'ISOLATION_NOT_VERIFIED';Assert-True ([bool]$sp.canary_staged) 'CANARY_NOT_STAGED'
 Stage 'TELEMETRY_START' 'Start bpftrace process-tree/file telemetry plus auditd verification before sample launch';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper telemetry_start $($Script:AttemptID) $guestRunRoot $guestTrace $guestCred ubuntu $SampleRunId $FamilyStratum $Split $Repetition $ScenarioRunId $FixtureSeed $GroundTruth $ProcessDensityRole $TelemetryAdapter $EvidenceArchiveFormat $RunID $ExecutionOrder" 300;Assert-True ($rc -eq 0) 'UBUNTU_TELEMETRY_START_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/telemetry_prepare_receipt.json') (Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json');$tp=Get-Content (Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$tp.status -ceq 'PASS' -and [bool]$tp.telemetry_ready) 'UBUNTU_TELEMETRY_NOT_READY';Write-Host '*** TELEMETRY READY ***' -ForegroundColor Green;Start-Sleep -Seconds $PreRollSeconds
 # D-115: the frozen qualified invocation contract for this family. The per-family argv
 # table IS the frozen family set manifest - the single authority, already hash-verified.
 $familySetManifest=Join-Path $CampaignRoot '01_SHARED\sample_selection\UBUNTU_V11_FINAL_FAMILY_SET_20261112\UBUNTU_V11_FINAL_FAMILY_SET_MANIFEST.csv'
 Assert-True (Test-Path -LiteralPath $familySetManifest) ('FAMILY_SET_MANIFEST_MISSING:'+$familySetManifest)
 $familySetRows=@(Import-Csv -LiteralPath $familySetManifest)
 $familyRows=@($familySetRows | Where-Object { [string]$_.family -ceq [string]$FamilyStratum })
 Assert-True ($familyRows.Count -eq 1) ('FAMILY_NOT_IN_THE_FROZEN_FAMILY_SET:'+[string]$FamilyStratum)
 $frozenContract=[string]$familyRows[0].frozen_contract
 Assert-True (-not [string]::IsNullOrWhiteSpace($frozenContract)) ('EMPTY_FROZEN_CONTRACT:'+[string]$FamilyStratum)
 Assert-True ([string]$familyRows[0].sha256 -ceq [string]$SampleSha256) ('FAMILY_SET_IDENTITY_MISMATCH:'+[string]$FamilyStratum)
 $canaryRoot=$guestRunRoot+'/Canary'
 $argvString=($frozenContract -replace '<CANARY>',$canaryRoot)
 $argvTokens=@($argvString -split '\s+' | Where-Object { $_ -ne '' })
 Assert-True ($argvTokens.Count -ge 1) ('EMPTY_INVOCATION_ARGV:'+[string]$FamilyStratum)
 Write-Host ('  invocation contract (frozen): '+$frozenContract+'  ->  '+$argvString)
 Stage 'SAMPLE_RUN' ('Execute ransomware sample under the frozen qualified contract ('+$argvString+') under bounded observation: max '+$ObservationWindowSeconds+'s, watchdog '+$WatchdogSeconds+'s');$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper sample_execute $($Script:AttemptID) $guestRunRoot $guestTrace $ObservationWindowSeconds $WatchdogSeconds $guestCred ubuntu $SampleRunId $SampleSha256 $SampleGuestPath $Split $Repetition $TelemetryAdapter $RunID $ExecutionOrder $GroundTruth $ProcessDensityRole $EvidenceArchiveFormat $($argvTokens.Count) $($argvTokens -join ' ')" ([int]($WatchdogSeconds+120));
  # D-123: the VIX agent process that starts the guest program runs as the NON-ROOT guest
  # user, so a sample that kills the guest's non-root processes (Hive does, by design) also
  # kills the VIX job - VIX then reports a killed job (raw exit code 137) even though the
  # frozen helper ran the stage to its end. The QUALIFICATION's frozen gate (the D-038 standard)
  # accepts EITHER a zero raw exit code OR a complete, fully asserted receipt, and keeps the raw
  # code in the evidence so the channel failure stays visible. NOTHING is relaxed here: status,
  # watchdog_armed, termination_mode, exit_code_source and the observation-window bound are still
  # asserted exactly as before, and a missing or inconsistent receipt still fails the stage.
  $Script:GuestSampleExecuteExitCode=$rc;$sr=$null
  try{Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/sample_execute_receipt.json') (Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json')}catch{}
  if(Test-Path -LiteralPath (Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json')){try{$sr=Get-Content (Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json') -Raw|ConvertFrom-Json}catch{$sr=$null}}
  $receiptGate=$false
  if($null -ne $sr){if([string]$sr.status -ceq 'PASS' -and [bool]$sr.watchdog_armed -and [double]$sr.actual_execution_seconds -le ([double]$ObservationWindowSeconds+5.0)){$receiptGate=$true}}
  Assert-True (($rc -eq 0) -or $receiptGate) 'UBUNTU_SAMPLE_EXECUTE_FAILED'
  Assert-True ($null -ne $sr) 'UBUNTU_SAMPLE_EXECUTE_RECEIPT_MISSING'
  Assert-True ([string]$sr.status -ceq 'PASS') 'UBUNTU_SAMPLE_EXECUTE_RECEIPT_FAIL';Assert-True ([bool]$sr.watchdog_armed) 'WATCHDOG_NOT_ARMED';$Script:WatchdogArmed=$true;$Script:SampleExitCode=[int]$sr.sample_exit_code;$Script:ActualExecutionSeconds=[double]$sr.actual_execution_seconds;$Script:ProcessTreeKilled=[bool]$sr.process_tree_killed;$Script:WatchdogFired=[bool]$sr.watchdog_fired;$Script:TerminationMode=$(if([bool]$sr.process_tree_killed -or [bool]$sr.watchdog_fired){'OBSERVATION_WINDOW_KILL'}else{'NATURAL_EXIT'});$Script:ExitCodeSource=$(if([bool]$sr.process_tree_killed){'WATCHDOG_KILL'}else{'PROCESS_EXITCODE'});Assert-True ([string]$sr.termination_mode -ceq $Script:TerminationMode) ('TERMINATION_MODE_MISMATCH:'+ [string]$sr.termination_mode+' vs '+$Script:TerminationMode);Assert-True ([string]$sr.exit_code_source -ceq $Script:ExitCodeSource) ('EXIT_CODE_SOURCE_MISMATCH:'+ [string]$sr.exit_code_source+' vs '+$Script:ExitCodeSource);Assert-True ([double]$sr.actual_execution_seconds -le ([double]$ObservationWindowSeconds + 5.0)) ('SAMPLE_EXCEEDED_OBSERVATION_WINDOW:'+ $sr.actual_execution_seconds+'s > '+$ObservationWindowSeconds+'s');if ([bool]$sr.process_tree_killed) { Assert-True ([double]$sr.actual_execution_seconds -ge ([double]$ObservationWindowSeconds - 5.0)) 'WATCHDOG_KILL_BEFORE_WINDOW' };Assert-True ([int]$sr.root_pid -gt 0) 'ROOT_PID_INVALID';Assert-True (([int]$sr.process_exit_code -ge 0) -or ([bool]$sr.process_tree_killed)) 'SAMPLE_EXIT_CODE_INVALID';Write-Host ('SAMPLE COMPLETE: ROOT_PID='+$sr.root_pid+' EXIT_CODE='+$sr.sample_exit_code+' ACTUAL_DURATION='+$sr.actual_execution_seconds+'s OBSERVATION_WINDOW='+$ObservationWindowSeconds+'s TERMINATION='+$Script:TerminationMode) -ForegroundColor Green
 Stage 'TELEMETRY_TAIL' 'Fixed '+$PostTailSeconds+' s post-exit telemetry tail (applied inside the guest), then stop/finalize telemetry';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper telemetry_finalize $($Script:AttemptID) $guestRunRoot $PostTailSeconds $guestCred ubuntu $SampleRunId $ActualExecutionSeconds $SampleExitCode $TelemetryAdapter $RunID $ExecutionOrder" 180;Assert-True ($rc -eq 0) 'UBUNTU_TELEMETRY_FINALIZE_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/telemetry_capture_receipt.json') (Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json');$tr=Get-Content (Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$tr.status -ceq 'PASS') 'UBUNTU_TELEMETRY_CAPTURE_FAIL';Assert-True ([int]$tr.event_loss_count -eq 0) ('TELEMETRY_EVENT_LOSS:'+ $tr.event_loss_count);Assert-True ([string]$tr.termination_mode -ceq $Script:TerminationMode) ('TELEMETRY_TERMINATION_MODE_MISMATCH:'+ [string]$tr.termination_mode+' vs '+$Script:TerminationMode);Assert-True ([int]$tr.exit_code -eq [int]$Script:SampleExitCode) ('TELEMETRY_EXIT_CODE_MISMATCH:'+ [string]$tr.exit_code+' vs '+[string]$Script:SampleExitCode);Assert-True ([string]$tr.exit_code_source -ceq $Script:ExitCodeSource) ('TELEMETRY_EXIT_CODE_SOURCE_MISMATCH:'+ [string]$tr.exit_code_source+' vs '+$Script:ExitCodeSource);Write-Host ('REAL TELEMETRY: ROWS='+$tr.telemetry_rows+' AUDIT_EXEC_BYTES='+$tr.audit_exec_bytes+' AUDIT_FILE_BYTES='+$tr.audit_file_bytes+' EVENT_LOSS='+$tr.event_loss_count) -ForegroundColor Green
 Stage 'CANARY_VERIFY' 'Re-check pre-hashed canary corpus integrity after sample execution';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper canary_verify $($Script:AttemptID) $guestRunRoot $guestCred ubuntu $SampleRunId $FamilyStratum" 60;Assert-True ($rc -eq 0) 'UBUNTU_CANARY_VERIFY_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/canary_integrity_receipt.json') (Join-Path $Script:RunRoot 'evidence\canary_integrity_receipt.json');$cy=Get-Content (Join-Path $Script:RunRoot 'evidence\canary_integrity_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$cy.status -ceq 'PASS') 'UBUNTU_CANARY_RECEIPT_FAIL'
 Stage 'GUEST_PACK' 'Hash and fast-compress bpftrace, auditd, sample-execute, canary and lifecycle evidence inside Ubuntu';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper pack $($Script:AttemptID) $guestRunRoot $guestArchive $guestCred ubuntu $SampleRunId $FamilyStratum $RunID" 240;Assert-True ($rc -eq 0) 'UBUNTU_GUEST_PACK_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/guest_pack_receipt.json') (Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json');$pr=Get-Content (Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$pr.status -ceq 'PASS') 'UBUNTU_PACK_RECEIPT_FAIL';Assert-True ([bool]$pr.raw_bpftrace_preserved) 'RAW_BPFTRACE_NOT_PRESERVED';Assert-True (-not [bool]$pr.derived_full_csv_included) 'DERIVED_FULL_CSV_SHOULD_NOT_BE_PACKED'
 Stage 'ARCHIVE_TRANSFER' 'Transfer compressed archive only; no loose raw bulk telemetry crosses to host';$hostArchive=Join-Path $Script:RunRoot 'capture_archive.tar.gz';Copy-FromUbuntuGuest $guestArchive $hostArchive 600;Assert-True ((SHA $hostArchive) -ceq [string]$pr.archive_sha256) 'UBUNTU_ARCHIVE_SHA_MISMATCH';$listing=@(& tar -tzf $hostArchive 2>&1);Assert-True ($LASTEXITCODE -eq 0) 'UBUNTU_ARCHIVE_LIST_FAILED';foreach($n in @('evidence/bpftrace.csv','evidence/audit_exec.log','evidence/audit_file.log','evidence/sample_execute_receipt.json','evidence/telemetry_capture_receipt.json','evidence/canary_integrity_receipt.json','evidence/SHA256SUMS.txt')){Assert-True (@($listing|Where-Object{$_ -ceq $n}).Count -eq 1) ('UBUNTU_ARCHIVE_ENTRY_MISSING:'+ $n)}
 $runSucceeded=$true
 Stage 'CREDENTIAL_CLEANUP' 'Shred the transferred sudo credential inside the guest';try{$null=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper cleanup $($Script:AttemptID) $guestRunRoot $guestCred ubuntu" 60}catch{Write-Log 'WARN' ('CREDENTIAL_CLEANUP_ERROR: '+$_.Exception.Message)}
}catch{$mainError=$_.Exception.Message;if($guestRunRoot){try{Save-UbuntuGuestDiagnostics $guestRunRoot}catch{}};Write-Host ('RANSOMWARE '+$RunMode.ToUpperInvariant()+' RUN EXECUTION ERROR: '+$mainError) -ForegroundColor Red}
finally{
 Stage 'RECOVERY' 'Stop Ubuntu, revert exact frozen snapshot, verify Windows unchanged, restore host network and VMware GUI entries'
 try{try{Stop-UbuntuVM $VmrunPath $UbuntuVmxPath}catch{Write-Log 'WARN' ('Stop error: '+$_.Exception.Message)};Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $UbuntuSnapshot;Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_RUNNING_AFTER_RECOVERY';Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_RUNNING_AFTER_RECOVERY';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu';Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';if($Script:IsolationStarted){$null=Restore-HostNetwork $Script:NetworkBaseline};Ensure-GuiEntries;Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') ([ordered]@{status='PASS';ubuntu_off=$true;windows_off=$true;ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');network_restored=$true;gui_entries_restored=$true;timestamp=[DateTime]::UtcNow.ToString('o')});$recoverySucceeded=$true}catch{$recoveryError=$_.Exception.Message;Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red};try{Close-UbuntuVix}catch{}}
if(-not$runSucceeded -or -not$recoverySucceeded){Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') ([ordered]@{status='FAIL';qualification_only=$QualificationOnly;official_run=$IsOfficial;run_mode=$RunMode;official_campaign_slots_consumed=0;run_id=$RunID;execution_order=$ExecutionOrder;sample_run_id=$SampleRunId;family_stratum=$FamilyStratum;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunId;fixture_seed=$FixtureSeed;lead_application=$FamilyStratum;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole;termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;execution_error=$mainError;recovery_error=$recoveryError;run_root=$Script:RunRoot});throw ('UBUNTU_RANSOMWARE_OFFICIAL_RUN_FAIL run_id='+$RunID+' execution='+$mainError+' recovery='+$recoveryError)}
Stage 'PACKAGE_VERIFY' 'Create complete run manifest and verify all listed evidence hashes';$Overall.Stop();Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') ([ordered]@{status='PASS';qualification_only=$QualificationOnly;official_run=$IsOfficial;run_mode=$RunMode;official_campaign_slots_consumed=$SlotsConsumed;run_id=$RunID;execution_order=$ExecutionOrder;sample_run_id=$SampleRunId;family_stratum=$FamilyStratum;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunId;fixture_seed=$FixtureSeed;lead_application=$FamilyStratum;ground_truth=$GroundTruth;process_density_role=$ProcessDensityRole;telemetry=$TelemetryAdapter;evidence_archive_format=$EvidenceArchiveFormat;csv_materialization='DEFERRED_OFFLINE';compressed_only_bulk_telemetry_on_host=$true;recovery_verified=$true;watchdog_armed=$Script:WatchdogArmed;guest_sample_execute_exit_code=$Script:GuestSampleExecuteExitCode;termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;sample_exit_code=$Script:SampleExitCode;actual_execution_seconds=$Script:ActualExecutionSeconds;observation_window_seconds=$ObservationWindowSeconds;post_tail_seconds=$PostTailSeconds;watchdog_seconds=$WatchdogSeconds;workload=($SampleRunId+'_'+$FamilyStratum+'_RANSOMWARE_V1');telemetry_finalize_seconds=[Math]::Round($Overall.Elapsed.TotalSeconds,3);total_run_seconds=[Math]::Round($Overall.Elapsed.TotalSeconds,3);run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')});$manifest=New-RunManifest $Script:RunRoot;$rows=@(Import-Csv $manifest);$fail=0;foreach($row in $rows){$p=Join-Path $Script:RunRoot $row.relative_path;if((-not (Test-Path -LiteralPath $p -PathType Leaf)) -or ((SHA $p) -cne [string]$row.sha256)){$fail++}};Write-Json (Join-Path $Script:RunRoot 'RUN_FULL_VERIFICATION.json') ([ordered]@{status=$(if($fail-eq0){'PASS'}else{'FAIL'});fail=$fail;manifest_sha256=(SHA $manifest)});Assert-True ($fail -eq 0) 'UBUNTU_RUN_PACKAGE_SELF_VERIFICATION_FAILED';Write-Host '';Write-Host ('FINAL UBUNTU '+$RunMode.ToUpperInvariant()+' RANSOMWARE RUN PASS: '+$RunID) -ForegroundColor Green;Write-Host ('Evidence package: '+$Script:RunRoot) -ForegroundColor Green;if($IsOfficial){Write-Host ('Official ransomware campaign slot completed: '+$ExecutionOrder+'/40; run_id='+$RunID) -ForegroundColor Yellow}else{Write-Host ('Mode='+$RunMode+'; campaign slots consumed=0; run_id='+$RunID) -ForegroundColor Yellow};Write-Host ('TOTAL '+$RunMode.ToUpperInvariant()+' RUN SECONDS: '+$Overall.Elapsed.TotalSeconds.ToString('F1')) -ForegroundColor Green;$Script:RunRoot
