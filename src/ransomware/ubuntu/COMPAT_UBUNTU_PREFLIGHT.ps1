# COMPAT_UBUNTU_PREFLIGHT.ps1
#
# Zero-slot Ubuntu compatibility/preflight for the 6 Ubuntu ransomware samples
# that have not yet shown a valid executed workload on Ubuntu:
#   L-R-01 (Qilin/Agenda)  L-R-02 (Bert)  L-R-04 (BrainCipher)
#   L-R-05 (MarioLocker)   L-R-07 (INC/Lynx)  L-R-09 (Buhti)
#
# One full frozen-pattern cycle per sample, one sample at a time:
#   revert/verify frozen snapshot -> host/guest isolation -> boot (native VIX)
#   -> sample_prepare (trust-but-verify 0400, canary, isolation) -> telemetry
#   (auditd + bpftrace) -> execute under the FROZEN documented invocation
#   contract -> 60 s bounded observation + 90 s watchdog -> NATURAL_EXIT vs
#   OBSERVATION_WINDOW_KILL -> 10 s post-exit telemetry tail -> canary verify ->
#   guest pack -> transfer archive -> host hash verify -> power off/revert ->
#   recovery verification before the next sample.
#
# Frozen per-sample invocation contracts (D-042 read-only inspection evidence;
# NOTHING invented — each argv token matches a documented string in
# evidence/<sample>/usage_hits.txt):
#   L-R-01: --password <pw> -p <CANARY>          (Usage: -p,--path <string> / --password <string>)
#   L-R-02: --path <CANARY> --threads 1 --silent (Usage example: elf.exe --path /vmfs/ --threads 5;
#                                                  --silent (-s) = do not stop VMs mode)
#   L-R-04: <CANARY> -time 5                     (Usage: %s /path/to/be/encrypted [-time seconds])
#   L-R-05: <CANARY>                             (Usage: %s /path/to/be/encrypted)
#   L-R-07: --dir <CANARY>                       (USAGE: --dir <DIRECTORY> Encrypt only selected directory)
#   L-R-09: <CANARY>                             (Usage: %s /path/to/be/encrypted)
#
# Rules honoured: 0 official campaign slots consumed; samples root-owned 0400;
# fresh throwaway canary corpus per cycle; nothing persists in Ubuntu after
# revert; halt-on-first-failure (exact failure + evidence package is written,
# no rerun with changed arguments). Frozen production scripts
# (RANSOMWARE_Official_Run_Controller.ps1 / RANSOMWARE_Guest_Official.sh) are
# NOT used and NOT modified — this pilot is a self-contained port of that
# pattern plus the argv contract (D-042: the runner must carry the frozen
# per-sample invocation contract).
#
# If a sample fails to launch, shows a platform mismatch, telemetry fails,
# isolation fails, or recovery fails: HALT, record FAIL + exact evidence, stop
# the remaining cycles. Do not proceed to official ransomware runs.

[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$CampaignRoot,
 [string]$VmrunPath='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
 [string]$VMwareGuiPath='C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
 [string]$WindowsVmxPath='D:\Windows 11\Windows 11.vmx',
 [string]$UbuntuVmxPath='D:\Ubuntu 24.04\Ubuntu.vmx',
 [string]$WindowsSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013',
 [string]$UbuntuSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013',
 [int]$PreRollSeconds=5,[int]$PostTailSeconds=10,[int]$ObservationWindowSeconds=60,[int]$WatchdogSeconds=90
)
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false
$Script:WatchdogArmed=$false;$Script:SampleExitCode=$null;$Script:ActualExecutionSeconds=$null
$Script:TerminationMode=$null;$Script:ExitCodeSource=$null;$Script:WatchdogFired=$false;$Script:ProcessTreeKilled=$false
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};[IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 20)+"`r`n"),(New-Object Text.UTF8Encoding($false)))}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'COMPAT_PREFLIGHT_CONTROLLER.log') -Value $line -Encoding UTF8}}
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
    do{Start-Sleep -Seconds 2;$attempt++;$cur=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $Script:CurrentSampleRunID;$check=Test-P5GNetworkRestored $Baseline $cur.PhysicalAdapters $cur.Routes ([pscustomobject]@{vms_safe=$true});if([bool]$check.restored){$consecutiveRestored++;if($consecutiveRestored -ge 3){Write-Host ('NETWORK ADAPTER RESTORE CONFIRMED: attempts='+$attempt+' consecutive_restored='+$consecutiveRestored) -ForegroundColor Green;return $cur}}else{$consecutiveRestored=0;$last=[string]$check.reason;if(($attempt % 10) -eq 0){Write-Host ('NETWORK ADAPTER RESTORE WAITING: attempts='+$attempt+' last_reason='+$last) -ForegroundColor Yellow}}}
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
foreach($p in @($CampaignRoot,$VmrunPath,$VMwareGuiPath,$WindowsVmxPath,$UbuntuVmxPath,(Join-Path $PackageRoot 'COMPAT_UBUNTU_PREFLIGHT.sh'),(Join-Path $PackageRoot 'UBUNTU_Compound_Trace.bt'))){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
Assert-VmxHardening 'Windows' $WindowsVmxPath;Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_PILOT';Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_PILOT'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$PilotRoot=Join-Path $CampaignRoot '05_UBUNTU\RANSOMWARE\compat_preflight'
New-Item -ItemType Directory -Path $PilotRoot -Force|Out-Null

# Frozen per-sample table (D-042 documented contract; sha/bytes/path from frozen manifest).
# L-R-01 (Gunra) EXCLUDED per USER decision 2026-11-09: "I don't want to do it manually. skip it and
# proceed for rest of samples run." The Gunra sample is not materialized and its contract is not frozen; the row
# must remain visible in the repo so a later re-inspection can re-enable it. Do NOT run orders 21/22 until D-042
# re-inspection freezes the Gunra contract.
$SampleRows=@(
 [ordered]@{run_id='COMPAT_UBU_02_A';execution_order=23;sample_run_id='L-R-02';family_stratum='Bert';split='TRAIN';repetition='A';scenario_run_id='L-R-02-A';fixture_seed='R02-UBU-A';sample_sha256='5bba035c4cb3c2e09a355d9356b3397184af4bf1ac1ff1df99ae9c15edee9f2b';sample_bytes='105320';sample_guest_path='/opt/RansomLab/MalwareStaging/P5G/R4/Samples/5bba035c4cb3c2e09a355d9356b3397184af4bf1ac1ff1df99ae9c15edee9f2b.sample';argv=@('--path','<CANARY>','--threads','1','--silent')},
 [ordered]@{run_id='COMPAT_UBU_04_A';execution_order=27;sample_run_id='L-R-04';family_stratum='BrainCipher';split='TRAIN';repetition='A';scenario_run_id='L-R-04-A';fixture_seed='R04-UBU-A';sample_sha256='ec890af6c136836ea262676aea35ebdd07a4546dda49f22a19de9f8623cc7217';sample_bytes='71784';sample_guest_path='/opt/RansomLab/MalwareStaging/P5G/R4/Samples/ec890af6c136836ea262676aea35ebdd07a4546dda49f22a19de9f8623cc7217.sample';argv=@('<CANARY>','-time','5')},
 [ordered]@{run_id='COMPAT_UBU_05_A';execution_order=29;sample_run_id='L-R-05';family_stratum='MarioLocker';split='VALIDATION';repetition='A';scenario_run_id='L-R-05-A';fixture_seed='R05-UBU-A';sample_sha256='0a77e537c64336f97a04020e59d17d09d459d1626a075878e2b796d1e1033038';sample_bytes='70296';sample_guest_path='/opt/RansomLab/MalwareStaging/P5G/R4/Samples/0a77e537c64336f97a04020e59d17d09d459d1626a075878e2b796d1e1033038.sample';argv=@('<CANARY>')},
 [ordered]@{run_id='COMPAT_UBU_07_A';execution_order=33;sample_run_id='L-R-07';family_stratum='INC/Lynx';split='TRAIN';repetition='A';scenario_run_id='L-R-07-A';fixture_seed='R07-UBU-A';sample_sha256='63e0d4e861048f581c9e5c64b28a053eb0023d58eebf2b943868d5f68a67a8b7';sample_bytes='84400';sample_guest_path='/opt/RansomLab/MalwareStaging/P5G/R4/Samples/63e0d4e861048f581c9e5c64b28a053eb0023d58eebf2b943868d5f68a67a8b7.sample';argv=@('--dir','<CANARY>/')},
 [ordered]@{run_id='COMPAT_UBU_09_A';execution_order=37;sample_run_id='L-R-09';family_stratum='Buhti';split='TRAIN';repetition='A';scenario_run_id='L-R-09-A';fixture_seed='R09-UBU-A';sample_sha256='01b09b554c30675cc83d4b087b31f980ba14e9143d387954df484894115f82d4';sample_bytes='1421208';sample_guest_path='/opt/RansomLab/MalwareStaging/P5G/R4/Samples/01b09b554c30675cc83d4b087b31f980ba14e9143d387954df484894115f82d4.sample';argv=@('<CANARY>')}
)

$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16)
$sampleResults=New-Object 'System.Collections.Generic.List[object]'
$haltPilot=$false
foreach($s in $SampleRows){
  if($haltPilot){Write-Host ('HALT: pilot stopped before '+$s.sample_run_id+' due to prior failure') -ForegroundColor Red;break}
  $Script:CurrentSampleRunID=[string]$s.run_id
  $Script:WatchdogArmed=$false;$Script:SampleExitCode=$null;$Script:ActualExecutionSeconds=$null
  $Script:TerminationMode=$null;$Script:ExitCodeSource=$null;$Script:WatchdogFired=$false;$Script:ProcessTreeKilled=$false
  $Script:WorkloadStatus=$null;$Script:CanaryMismatches=$null;$Script:CanaryModified=$null
  $sampleAttempt=[guid]::NewGuid().ToString('N').Substring(0,16)
  $rowStamp=Get-Date -Format 'yyyyMMdd_HHmmss'
  $Script:RunRoot=Join-Path $PilotRoot ($s.run_id+'_'+$sampleAttempt+'_'+$rowStamp)
  New-Item -ItemType Directory -Path $Script:RunRoot -Force|Out-Null;foreach($d in @('evidence','recovery')){New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot $d) -Force|Out-Null}
  $runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError='';$guestRunRoot=$null;$argvStr=''
  $Overall=[Diagnostics.Stopwatch]::StartNew()
  try{
   Stage ('PRESTATE_'+$s.sample_run_id) 'Verify exact snapshots, hardening, VM state, and VMware GUI entries';Ensure-GuiEntries;$Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $s.run_id;Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline
   Stage 'ISOLATION' 'Disable baseline physical adapters and require zero IPv4/IPv6 default routes';Disable-HostNetwork $Script:NetworkBaseline
   Stage 'VM_START' 'Power on Ubuntu by native VIX; Windows remains OFF';Start-UbuntuVM $VmrunPath $UbuntuVmxPath;Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_POWERED_ON_UNEXPECTEDLY';Ensure-GuiEntries
   $canary='/tmp/ransomware_compat/'+$s.run_id+'/'+$sampleAttempt+'/Canary'
   $argv=@($s.argv|ForEach-Object{$_ -replace '<CANARY>',$canary})
   $argvStr=($argv -join ' ')
   $guestHelper='/tmp/COMPAT_UBUNTU_PREFLIGHT_'+$sampleAttempt+'.sh';$guestTrace='/tmp/COMPAT_UBUNTU_TRACE_'+$sampleAttempt+'.bt';$guestCred='/tmp/COMPAT_UBUNTU_'+$sampleAttempt+'.sudo';$guestRunRoot='/tmp/ransomware_compat/'+$s.run_id+'/'+$sampleAttempt;$guestArchive='/tmp/COMPAT_UBUNTU_'+$s.run_id+'_'+$sampleAttempt+'.tar.gz'
   Stage 'HELPER_TRANSFER' 'Transfer compat executor, telemetry, and packer helpers by native VIX';Copy-ToUbuntuGuest (Join-Path $PackageRoot 'COMPAT_UBUNTU_PREFLIGHT.sh') $guestHelper;Copy-ToUbuntuGuest (Join-Path $PackageRoot 'UBUNTU_Compound_Trace.bt') $guestTrace;New-UbuntuSudoCredentialFile $guestCred|Out-Null
   Stage ('SAMPLE_PREPARE_'+$s.sample_run_id) ('CompatibilityPilot '+$s.run_id+' '+$s.sample_run_id+' '+$s.family_stratum+': stage sample read-only (root-owned 0400), stage canary corpus, verify isolation from inside guest as root')
   $rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper sample_prepare $sampleAttempt $guestRunRoot $([string]$s.sample_sha256) $([string]$s.sample_bytes) $([string]$s.sample_guest_path) 0400 $guestCred ubuntu $($s.sample_run_id) $($s.family_stratum) $($s.split) $($s.repetition) $($s.scenario_run_id) $($s.fixture_seed) RANSOMWARE MALICIOUS_PRIMARY_SUBJECT bpftrace+auditd tar.gz $($s.run_id) $($s.execution_order)" 300;Assert-True ($rc -eq 0) 'UBUNTU_SAMPLE_PREPARE_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/sample_prepare_receipt.json') (Join-Path $Script:RunRoot 'evidence\sample_prepare_receipt.json');$sp=Get-Content (Join-Path $Script:RunRoot 'evidence\sample_prepare_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$sp.status -ceq 'PASS') 'UBUNTU_SAMPLE_PREPARE_RECEIPT_FAIL';Assert-True ([bool]$sp.isolation_verified) 'ISOLATION_NOT_VERIFIED';Assert-True ([bool]$sp.canary_staged) 'CANARY_NOT_STAGED'
   Stage 'TELEMETRY_START' 'Start bpftrace process-tree/file telemetry plus auditd verification before sample launch';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper telemetry_start $sampleAttempt $guestRunRoot $guestTrace $guestCred ubuntu $($s.sample_run_id) $($s.family_stratum) $($s.split) $($s.repetition) $($s.scenario_run_id) $($s.fixture_seed) RANSOMWARE MALICIOUS_PRIMARY_SUBJECT bpftrace+auditd tar.gz $($s.run_id) $($s.execution_order)" 300;Assert-True ($rc -eq 0) 'UBUNTU_TELEMETRY_START_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/telemetry_prepare_receipt.json') (Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json');$tp=Get-Content (Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$tp.status -ceq 'PASS' -and [bool]$tp.telemetry_ready) 'UBUNTU_TELEMETRY_NOT_READY';Write-Host '*** TELEMETRY READY ***' -ForegroundColor Green;Start-Sleep -Seconds $PreRollSeconds
   Stage ('SAMPLE_RUN_'+$s.sample_run_id) ('Execute sample under frozen documented contract: '+$argvStr+'  | bounded observation: max '+$ObservationWindowSeconds+'s, watchdog '+$WatchdogSeconds+'s');$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper sample_execute $sampleAttempt $guestRunRoot $guestTrace $ObservationWindowSeconds $WatchdogSeconds $guestCred ubuntu $($s.sample_run_id) $([string]$s.sample_sha256) $([string]$s.sample_guest_path) $($s.split) $($s.repetition) bpftrace+auditd $($s.run_id) $($s.execution_order) RANSOMWARE MALICIOUS_PRIMARY_SUBJECT tar.gz $argvStr" ([int]($WatchdogSeconds+120));Assert-True ($rc -eq 0) 'UBUNTU_SAMPLE_EXECUTE_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/sample_execute_receipt.json') (Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json');$sr=Get-Content (Join-Path $Script:RunRoot 'evidence\sample_execute_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$sr.status -ceq 'PASS') 'UBUNTU_SAMPLE_EXECUTE_RECEIPT_FAIL';Assert-True ([bool]$sr.watchdog_armed) 'WATCHDOG_NOT_ARMED';$Script:WatchdogArmed=$true;$Script:SampleExitCode=[int]$sr.sample_exit_code;$Script:ActualExecutionSeconds=[double]$sr.actual_execution_seconds;$Script:ProcessTreeKilled=[bool]$sr.process_tree_killed;$Script:WatchdogFired=[bool]$sr.watchdog_fired;$Script:TerminationMode=$(if([bool]$sr.process_tree_killed -or [bool]$sr.watchdog_fired){'OBSERVATION_WINDOW_KILL'}else{'NATURAL_EXIT'});$Script:ExitCodeSource=$(if([bool]$sr.process_tree_killed){'WATCHDOG_KILL'}else{'PROCESS_EXITCODE'});Assert-True ([string]$sr.termination_mode -ceq $Script:TerminationMode) ('TERMINATION_MODE_MISMATCH:'+ [string]$sr.termination_mode+' vs '+$Script:TerminationMode);Assert-True ([string]$sr.exit_code_source -ceq $Script:ExitCodeSource) ('EXIT_CODE_SOURCE_MISMATCH:'+ [string]$sr.exit_code_source+' vs '+$Script:ExitCodeSource);Assert-True ([double]$sr.actual_execution_seconds -le ([double]$ObservationWindowSeconds + 5.0)) ('SAMPLE_EXCEEDED_OBSERVATION_WINDOW:'+ $sr.actual_execution_seconds+'s > '+$ObservationWindowSeconds+'s');Write-Host ('*** SAMPLE EXECUTED: mode='+$Script:TerminationMode+' exit='+$Script:SampleExitCode+' actual_s='+$Script:ActualExecutionSeconds) -ForegroundColor Green
   Stage 'TELEMETRY_TAIL' ('Fixed '+$PostTailSeconds+' s post-exit telemetry tail (applied inside the guest), then stop/finalize telemetry');$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper telemetry_finalize $sampleAttempt $guestRunRoot $PostTailSeconds $guestCred ubuntu $($s.sample_run_id) $Script:ActualExecutionSeconds $Script:SampleExitCode bpftrace+auditd $($s.run_id) $($s.execution_order)" 180;Assert-True ($rc -eq 0) 'UBUNTU_TELEMETRY_FINALIZE_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/telemetry_capture_receipt.json') (Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json');$tr=Get-Content (Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$tr.status -ceq 'PASS') 'UBUNTU_TELEMETRY_CAPTURE_FAIL';Assert-True ([int]$tr.event_loss_count -eq 0) ('TELEMETRY_EVENT_LOSS:'+ $tr.event_loss_count);Assert-True ([string]$tr.termination_mode -ceq $Script:TerminationMode) ('TELEMETRY_TERMINATION_MODE_MISMATCH:'+ [string]$tr.termination_mode+' vs '+$Script:TerminationMode);Assert-True ([int]$tr.exit_code -eq [int]$Script:SampleExitCode) ('TELEMETRY_EXIT_CODE_MISMATCH:'+ [string]$tr.exit_code+' vs '+[string]$Script:SampleExitCode);Assert-True ([string]$tr.exit_code_source -ceq $Script:ExitCodeSource) ('TELEMETRY_EXIT_CODE_SOURCE_MISMATCH:'+ [string]$tr.exit_code_source+' vs '+$Script:ExitCodeSource);Write-Host ('REAL TELEMETRY: ROWS='+$tr.telemetry_rows+' AUDIT_EXEC_BYTES='+$tr.audit_exec_bytes+' AUDIT_FILE_BYTES='+$tr.audit_file_bytes+' EVENT_LOSS='+$tr.event_loss_count) -ForegroundColor Green
   Stage 'CANARY_VERIFY' 'Re-check pre-hashed canary corpus integrity after sample execution';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper canary_verify $sampleAttempt $guestRunRoot $guestCred ubuntu $($s.sample_run_id) $($s.family_stratum)" 60;Assert-True ($rc -eq 0) 'UBUNTU_CANARY_VERIFY_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/canary_integrity_receipt.json') (Join-Path $Script:RunRoot 'evidence\canary_integrity_receipt.json');$cy=Get-Content (Join-Path $Script:RunRoot 'evidence\canary_integrity_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$cy.status -ceq 'PASS') 'UBUNTU_CANARY_RECEIPT_FAIL';$Script:CanaryMismatches=[int]$cy.canary_mismatches;$Script:CanaryModified=[bool]$cy.canary_modified
   if($Script:CanaryMismatches -gt 0){$Script:WorkloadStatus='WORKLOAD_PASS'}else{$Script:WorkloadStatus='WORKLOAD_FAIL';Write-Host ('*** WARNING: '+$s.sample_run_id+' executed but modified 0 canaries -> WORKLOAD_FAIL') -ForegroundColor Yellow}
   Stage 'GUEST_PACK' 'Hash and fast-compress bpftrace, auditd, sample-execute, canary and lifecycle evidence inside Ubuntu';$rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper pack $sampleAttempt $guestRunRoot $guestArchive $guestCred ubuntu $($s.sample_run_id) $($s.family_stratum) $($s.run_id)" 240;Assert-True ($rc -eq 0) 'UBUNTU_GUEST_PACK_FAILED';Copy-FromUbuntuGuest ($guestRunRoot+'/evidence/guest_pack_receipt.json') (Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json');$pr=Get-Content (Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json') -Raw|ConvertFrom-Json;Assert-True ([string]$pr.status -ceq 'PASS') 'UBUNTU_PACK_RECEIPT_FAIL';Assert-True ([bool]$pr.raw_bpftrace_preserved) 'RAW_BPFTRACE_NOT_PRESERVED';Assert-True (-not [bool]$pr.derived_full_csv_included) 'DERIVED_FULL_CSV_SHOULD_NOT_BE_PACKED'
   Stage 'ARCHIVE_TRANSFER' 'Transfer compressed archive only; no loose raw bulk telemetry crosses to host';$hostArchive=Join-Path $Script:RunRoot 'capture_archive.tar.gz';Copy-FromUbuntuGuest $guestArchive $hostArchive 600;Assert-True ((SHA $hostArchive) -ceq [string]$pr.archive_sha256) 'UBUNTU_ARCHIVE_SHA_MISMATCH';$listing=@(& tar -tzf $hostArchive 2>&1);Assert-True ($LASTEXITCODE -eq 0) 'UBUNTU_ARCHIVE_LIST_FAILED';foreach($n in @('evidence/bpftrace.csv','evidence/audit_exec.log','evidence/audit_file.log','evidence/sample_execute_receipt.json','evidence/telemetry_capture_receipt.json','evidence/canary_integrity_receipt.json','evidence/SHA256SUMS.txt')){Assert-True (@($listing|Where-Object{$_ -ceq $n}).Count -eq 1) ('UBUNTU_ARCHIVE_ENTRY_MISSING:'+ $n)}
   $runSucceeded=$true
   Stage 'CREDENTIAL_CLEANUP' 'Shred the transferred sudo credential inside the guest';try{$null=Invoke-UbuntuGuestProgram '/bin/bash' "$guestHelper cleanup $sampleAttempt $guestRunRoot $guestCred ubuntu" 60}catch{Write-Log 'WARN' ('CREDENTIAL_CLEANUP_ERROR: '+$_.Exception.Message)}
  }catch{
   $mainError=$_.Exception.Message;if($guestRunRoot){try{Save-UbuntuGuestDiagnostics $guestRunRoot}catch{}}
   Write-Host ('COMPAT PREFLIGHT '+$s.sample_run_id+' EXECUTION ERROR: '+$mainError) -ForegroundColor Red
  }finally{
   Stage 'RECOVERY' ('Stop Ubuntu, revert exact frozen snapshot, verify Windows unchanged, restore host network and VMware GUI entries — before next sample')
   try{try{Stop-UbuntuVM $VmrunPath $UbuntuVmxPath}catch{Write-Log 'WARN' ('Stop error: '+$_.Exception.Message)};Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $UbuntuSnapshot;Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_RUNNING_AFTER_RECOVERY';Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_RUNNING_AFTER_RECOVERY';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu';Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';if($Script:IsolationStarted){$null=Restore-HostNetwork $Script:NetworkBaseline};Ensure-GuiEntries;Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') ([ordered]@{status='PASS';ubuntu_off=$true;windows_off=$true;ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');network_restored=$true;gui_entries_restored=$true;timestamp=[DateTime]::UtcNow.ToString('o')});$recoverySucceeded=$true}catch{$recoveryError=$_.Exception.Message;Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red};$Script:IsolationStarted=$false;try{Close-UbuntuVix}catch{}
  }
  $Overall.Stop()
  if(-not$runSucceeded -or -not$recoverySucceeded){
   Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') ([ordered]@{status='FAIL';qualification_only=$true;official_run=$false;run_mode='CompatibilityPilot';official_campaign_slots_consumed=0;run_id=$s.run_id;execution_order=$s.execution_order;sample_run_id=$s.sample_run_id;family_stratum=$s.family_stratum;split=$s.split;repetition=$s.repetition;scenario_run_id=$s.scenario_run_id;fixture_seed=$s.fixture_seed;lead_application=$s.family_stratum;ground_truth='RANSOMWARE';process_density_role='MALICIOUS_PRIMARY_SUBJECT';termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;sample_argv=$argvStr;execution_error=$mainError;recovery_error=$recoveryError;run_root=$Script:RunRoot})
   $sampleResults.Add([pscustomobject]@{run_id=$s.run_id;sample_run_id=$s.sample_run_id;status='FAIL';workload='UNKNOWN';termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;run_root=$Script:RunRoot;error=$mainError})
   $haltPilot=$true
  }else{
   Stage ('PACKAGE_VERIFY_'+$s.sample_run_id) 'Create complete run manifest and verify all listed evidence hashes'
   Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') ([ordered]@{status=$(if($Script:WorkloadStatus -ceq 'WORKLOAD_PASS'){'PASS'}else{'WORKLOAD_FAIL'});qualification_only=$true;official_run=$false;run_mode='CompatibilityPilot';official_campaign_slots_consumed=0;run_id=$s.run_id;execution_order=$s.execution_order;sample_run_id=$s.sample_run_id;family_stratum=$s.family_stratum;split=$s.split;repetition=$s.repetition;scenario_run_id=$s.scenario_run_id;fixture_seed=$s.fixture_seed;lead_application=$s.family_stratum;ground_truth='RANSOMWARE';process_density_role='MALICIOUS_PRIMARY_SUBJECT';telemetry='bpftrace+auditd';evidence_archive_format='tar.gz';csv_materialization='DEFERRED_OFFLINE';compressed_only_bulk_telemetry_on_host=$true;recovery_verified=$true;watchdog_armed=$Script:WatchdogArmed;workload_status=$Script:WorkloadStatus;canary_mismatches=$Script:CanaryMismatches;canary_modified=$Script:CanaryModified;termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;exit_code_source=$Script:ExitCodeSource;watchdog_fired=$Script:WatchdogFired;process_tree_killed=$Script:ProcessTreeKilled;sample_exit_code=$Script:SampleExitCode;actual_execution_seconds=$Script:ActualExecutionSeconds;observation_window_seconds=$ObservationWindowSeconds;post_tail_seconds=$PostTailSeconds;watchdog_seconds=$WatchdogSeconds;workload=($s.sample_run_id+'_'+$s.family_stratum+'_COMPAT_PREFLIGHT_V1');sample_argv=$argvStr;telemetry_finalize_seconds=[Math]::Round($Overall.Elapsed.TotalSeconds,3);total_run_seconds=[Math]::Round($Overall.Elapsed.TotalSeconds,3);run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')})
   $manifest=New-RunManifest $Script:RunRoot;$rows=@(Import-Csv $manifest);$fail=0;foreach($row in $rows){$p=Join-Path $Script:RunRoot $row.relative_path;if((-not (Test-Path -LiteralPath $p -PathType Leaf)) -or ((SHA $p) -cne [string]$row.sha256)){$fail++}};Write-Json (Join-Path $Script:RunRoot 'RUN_FULL_VERIFICATION.json') ([ordered]@{status=$(if($fail-eq0){'PASS'}else{'FAIL'});fail=$fail;manifest_sha256=(SHA $manifest)})
   if($fail -ne 0){$sampleResults.Add([pscustomobject]@{run_id=$s.run_id;sample_run_id=$s.sample_run_id;status='FAIL';workload='UNKNOWN';termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;run_root=$Script:RunRoot;error=('PACKAGE_SELF_VERIFICATION_FAIL fail='+$fail)});$haltPilot=$true}
    elseif($Script:WorkloadStatus -ceq 'WORKLOAD_PASS'){$sampleResults.Add([pscustomobject]@{run_id=$s.run_id;sample_run_id=$s.sample_run_id;status='PASS';workload='WORKLOAD_PASS';termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;run_root=$Script:RunRoot;error=''})}
    else{$sampleResults.Add([pscustomobject]@{run_id=$s.run_id;sample_run_id=$s.sample_run_id;status='WORKLOAD_FAIL';workload='WORKLOAD_FAIL';termination_mode=$Script:TerminationMode;exit_code=$Script:SampleExitCode;run_root=$Script:RunRoot;error='SAMPLE_EXECUTED_BUT_0_CANARIES_MODIFIED'})}
  }
}
$aggStatus=if($sampleResults.Count -gt 0 -and @($sampleResults|Where-Object{$_.status -in @('FAIL','WORKLOAD_FAIL')}).Count -eq 0 -and @($sampleResults|Where-Object{$_.status -ceq 'PASS'}).Count -eq $SampleRows.Count){'PASS'}else{'FAIL'}
Write-Json (Join-Path $PilotRoot ('COMPAT_PREFLIGHT_AGGREGATE_'+$stamp+'_'+$Script:AttemptID+'.json')) ([ordered]@{status=$aggStatus;run_id='COMPAT_UBUNTU_PREFLIGHT';official_run=$false;official_campaign_slots_consumed=0;samples_total=$SampleRows.Count;samples_executed=$sampleResults.Count;samples_pass=@($sampleResults|Where-Object{$_.status -ceq 'PASS'}).Count;samples_fail=@($sampleResults|Where-Object{$_.status -ceq 'FAIL'}).Count;samples_workload_fail=@($sampleResults|Where-Object{$_.status -ceq 'WORKLOAD_FAIL'}).Count;halted_on_failure=$haltPilot;results=$sampleResults;pilot_root=$PilotRoot;timestamp=[DateTime]::UtcNow.ToString('o')})
Write-Host ('COMPAT PREFLIGHT AGGREGATE: '+$aggStatus+'  pass='+@($sampleResults|Where-Object{$_.status -ceq 'PASS'}).Count+' fail='+@($sampleResults|Where-Object{$_.status -ceq 'FAIL'}).Count+' workload_fail='+@($sampleResults|Where-Object{$_.status -ceq 'WORKLOAD_FAIL'}).Count+' of '+$SampleRows.Count) -ForegroundColor $(if($aggStatus -ceq 'PASS'){'Green'}else{'Red'})
if($aggStatus -ceq 'FAIL'){throw ('COMPAT_PREFLIGHT_FAIL: '+ (@($sampleResults|Where-Object{$_.status -in @('FAIL','WORKLOAD_FAIL')}|ForEach-Object{$_.run_id+'('+$_.sample_run_id+'):'+$_.error}) -join ' | '))}
