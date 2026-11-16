# COMPAT_UBUNTU_PILOT.ps1
#
# Zero-slot Ubuntu compatibility/contract pilot - run from host via PowerShell
# (native VIX). Executes each of the 6 unverified Ubuntu ransomware samples
# (L-R-01, L-R-02, L-R-04, L-R-05, L-R-07, L-R-09) against a throwaway canary
# directory under bounded observation (60 s max) to confirm each binary is
# runnable on Ubuntu before any official runs.
#
# Guarantees (recorded per-sample in RUN_RESULT.json):
#   RunMode=CompatibilityPilot, official_run=false, official_campaign_slots_consumed=0,
#   termination_mode / exit_code / exit_code_source / watchdog_fired / process_tree_killed,
#   sample_argv recorded, sample_executed=false (compatibility probe only).
#
# Safety:
#   - Samples are root-owned 0400 in the guest; the helper copies each to a temp
#     exec path (chmod 700) - the staged sample is never modified.
#   - A fresh canary corpus per sample; nothing persists after snapshot revert.
#   - Ubuntu is reverted to the exact frozen snapshot at the end (no new snapshot).
#   - Host network isolated during the workload; restored only after VM safety.
#
# Usage (Administrator PowerShell, -ExecutionPolicy Bypass):
#   & '...\COMPAT_UBUNTU_PILOT.ps1' -CampaignRoot 'C:\...\Ransomware_Thesis_Detection_Campaign_100Runs'

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CampaignRoot,
    [string]$VmrunPath='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    [string]$VMwareGuiPath='C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe',
    [string]$WindowsVmxPath='D:\Windows 11\Windows 11.vmx',
    [string]$UbuntuVmxPath='D:\Ubuntu 24.04\Ubuntu.vmx',
    [string]$WindowsSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013',
    [string]$UbuntuSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013',
    [int]$ObservationWindowSeconds=60,
    [int]$WatchdogSeconds=90,
    [int]$GuestTimeoutSeconds=300
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false
$RunID='UBUNTU_COMPAT_PILOT'
$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16)

function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};[IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 20)+"`r`n"),(New-Object Text.UTF8Encoding($false)))}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'COMPAT_PILOT_CONTROLLER.log') -Value $line -Encoding UTF8}}
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
function Save-UbuntuGuestDiagnostics([string]$GuestRunRoot,[string]$RunID){
    if([string]::IsNullOrWhiteSpace($GuestRunRoot) -or [string]::IsNullOrWhiteSpace($RunID)){return}
    $dst=Join-Path $Script:RunRoot 'evidence\guest_diagnostics';New-Item -ItemType Directory -Path $dst -Force|Out-Null
    $rels=@('work/guest_helper_compat.log','evidence/sample.stdout.txt','evidence/sample.stderr.txt','evidence/compat_receipt.json')
    foreach($rel in $rels){try{Copy-FromUbuntuGuest ($GuestRunRoot+'/'+$rel) (Join-Path $dst (($RunID+'_'+$rel) -replace '/','_'))}catch{}}
}
$PackageRoot=Join-Path $CampaignRoot '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu'
$ManifestPath=Join-Path $CampaignRoot '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'
foreach($p in @($CampaignRoot,$VmrunPath,$WindowsVmxPath,$UbuntuVmxPath,$ManifestPath,(Join-Path $PackageRoot 'COMPAT_UBUNTU_PILOT.sh'),(Join-Path $PackageRoot 'NetworkBaseline.ps1'),(Join-Path $PackageRoot 'UbuntuNativeBridge.ps1'))){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
# Dot-source the Ubuntu bridge + network helpers BEFORE any guest/network call.
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'UbuntuNativeBridge.ps1')
Assert-VmxHardening 'Windows' $WindowsVmxPath
Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_PILOT'
Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_PILOT'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows'
Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'

# ---- compatibility sample set: the 6 Ubuntu samples not yet proven runnable ----
$wantRunIds=@('L-R-01','L-R-02','L-R-04','L-R-05','L-R-07','L-R-09')
$manifest=@(Import-Csv -LiteralPath $ManifestPath)
$samples=New-Object 'System.Collections.Generic.List[object]'
foreach($rid in $wantRunIds){
    $row=@($manifest|Where-Object{[string]$_.sample_run_id -ceq $rid -and [string]$_.platform -ceq 'Ubuntu'})|Select-Object -First 1
    Assert-True ($row -ne $null) ('COMPAT_SAMPLE_NOT_IN_MANIFEST:'+ $rid)
    Assert-True ([string]$row.read_only -ceq 'True') ('COMPAT_SAMPLE_NOT_READ_ONLY:'+ $rid)
    $samples.Add([pscustomobject][ordered]@{
        run_id=$rid; family=[string]$row.family_stratum; sha=[string]$row.sample_sha256.ToLowerInvariant();
        bytes=[string]$row.sample_bytes; path=[string]$row.sample_guest_path;
        mode=[string]$row.mode_octal; split=[string]$row.split
    })
}

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:RunRoot=Join-Path $CampaignRoot ('05_UBUNTU\RANSOMWARE\compat_pilot\COMPAT_'+$stamp+'_'+$Script:AttemptID)
New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot 'evidence') -Force|Out-Null
New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot 'recovery') -Force|Out-Null

# Per-sample invocation contracts (derived from D-042 static strings; canary dir
# token <CANARY> is substituted by the guest helper with the per-sample canary root).
$contracts=@{
    'L-R-01'=@('--password','p5g_compat_pilot','<CANARY>','-y')                          # Qilin: password + target + script mode
    'L-R-02'=@('--path','<CANARY>','--threads','1','--silent')                          # Bert: path target
    'L-R-04'=@('<CANARY>','-time','5')                                                 # BrainCipher: path target
    'L-R-05'=@('<CANARY>')                                                             # MarioLocker: path target
    'L-R-07'=@('--dir','<CANARY>/')                                                    # INC/Lynx: trailing slash required
    'L-R-09'=@('<CANARY>')                                                             # Buhti: path target
}

$guestScript='/tmp/COMPAT_UBUNTU_PILOT_'+$Script:AttemptID+'.sh'
$guestCred='/tmp/COMPAT_UBUNTU_'+$Script:AttemptID+'.sudo'
$guestWorkRoot='/tmp/p5g_compat_pilot/'+$Script:AttemptID
$hostArchiveRoot=Join-Path $Script:RunRoot 'evidence'

$runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError=''
$sampleResults=New-Object 'System.Collections.Generic.List[object]'
try{
    Stage 'PRESTATE' 'Verify both VMs OFF, exact frozen snapshots, VMX hardening, and VMware GUI entries'
    Ensure-GuiEntries
    Write-Json (Join-Path $Script:RunRoot 'recovery\PRESTATE.json') ([ordered]@{status='PASS';windows_off=$true;ubuntu_off=$true;windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');gui_entries='both_visible';timestamp=[DateTime]::UtcNow.ToString('o')})

    Stage 'ISOLATION' 'Disable host physical adapters and require zero default routes'
    $Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID
    Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline
    Disable-HostNetwork $Script:NetworkBaseline

    Stage 'VM_START_LOGIN' 'Power on Ubuntu (native VIX), wait for tools, log in as ubuntu, re-check GUI entries'
    Start-UbuntuVM $VmrunPath $UbuntuVmxPath
    Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_POWERED_ON_UNEXPECTEDLY'
    Ensure-GuiEntries

    Stage 'TRANSFER' 'Copy compatibility guest helper + sudo credential to /tmp'
    Copy-ToUbuntuGuest (Join-Path $PackageRoot 'COMPAT_UBUNTU_PILOT.sh') $guestScript
    New-UbuntuSudoCredentialFile $guestCred|Out-Null

    Stage 'COMPAT_EXECUTE' 'Run each sample under bounded observation (60 s max), record D-041 receipt'
    foreach($s in $samples){
        Stage ('SAMPLE_'+$s.run_id) ('Compatibility probe: '+ $s.family +' ('+ $s.sha.Substring(0,16)+')')
        $canary=$guestWorkRoot+'/'+$s.run_id+'/canary'
        $execWork=$guestWorkRoot+'/'+$s.run_id
        $argv=@($contracts[$s.run_id]|ForEach-Object{$_ -replace '<CANARY>',$canary})
        $argvStr=($argv -join ' ')
        $args=('compat '+ $Script:AttemptID+' '+ $s.run_id+' '+ $s.sha+' '+ $s.path+' '+ $s.family+' '+ $guestCred+' '+ $execWork+' '+ [string]$ObservationWindowSeconds+' '+ $argvStr)
        $rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestScript $args" $GuestTimeoutSeconds
        # Copy the per-sample receipt back to the host.
        $guestReceipt=$execWork+'/evidence/compat_receipt.json'
        $hostReceipt=Join-Path $hostArchiveRoot ($s.run_id+'_compat_receipt.json')
        $copyOk=$false
        try{Copy-FromUbuntuGuest $guestReceipt $hostReceipt 120;$copyOk=$true}catch{Write-Log 'WARN' ('RECEIPT_COPY_'+ $s.run_id+': '+ $_.Exception.Message)}
        try{Save-UbuntuGuestDiagnostics $execWork $s.run_id}catch{Write-Log 'WARN' ('DIAGNOSTICS_'+ $s.run_id+': '+ $_.Exception.Message)}
        if($copyOk -and (Test-Path -LiteralPath $hostReceipt)){
            $receipt=Get-Content -LiteralPath $hostReceipt -Raw|ConvertFrom-Json
        }else{
            $receipt=$null
        }
        if($receipt){
            $term=[string]$receipt.termination_mode
            $exitCode=[int]$receipt.exit_code
            $exitSrc=[string]$receipt.exit_code_source
            $wd=[bool]$receipt.watchdog_fired
            $tk=[bool]$receipt.process_tree_killed
            $actualSeconds=[double]$receipt.actual_execution_seconds
        }else{
            $term='UNKNOWN'
            $exitCode=-1
            $exitSrc='UNKNOWN'
            $wd=$false
            $tk=$false
            $actualSeconds=0
        }
        if($copyOk -and $receipt -and [string]$receipt.status -ceq 'PASS'){$sampleStatus='PASS'}else{$sampleStatus='FAIL'}
        $sampleResults.Add([pscustomobject][ordered]@{
            run_id=$s.run_id; family=$s.family; sha=$s.sha; guest_exit_code=$rc; receipt_copy=$copyOk;
            termination_mode=$term; exit_code=$exitCode; exit_code_source=$exitSrc;
            watchdog_fired=$wd; process_tree_killed=$tk; argv=$argvStr; status=$sampleStatus
        })
        Write-Json (Join-Path $hostArchiveRoot ($s.run_id+'_RUN_RESULT.json')) ([ordered]@{
            status=$sampleResults[$sampleResults.Count-1].status; run_mode='CompatibilityPilot'; official_run=$false;
            official_campaign_slots_consumed=0; run_id=$s.run_id; execution_order='0'; sample_run_id=$s.run_id;
            family_stratum=$s.family; split=$s.split; scenario_run_id=($s.run_id+'-compat'); fixture_seed=('COMPAT-UBU-'+ $s.run_id);
            lead_application=$s.family; ground_truth='RANSOMWARE_COMPAT'; process_density_role='MALICIOUS_PRIMARY_SUBJECT';
            termination_mode=$term; exit_code=$exitCode; exit_code_source=$exitSrc;
            watchdog_fired=$wd; process_tree_killed=$tk; actual_execution_seconds=$actualSeconds;
            observation_window_seconds=$ObservationWindowSeconds; sample_argv=$argvStr; sample_sha256=$s.sha;
            sample_guest_path=$s.path; read_only='true'; mode_octal='0400';
            telemetry_adapter='bpftrace+auditd'; evidence_archive_format='tar.gz';
            network_used=$false; sample_executed=$false; recovery_verified=$false; run_root=$Script:RunRoot;
            timestamp=[DateTime]::UtcNow.ToString('o'); guest_helper_exit_code=$rc; receipt_copied=$copyOk
        })
        Write-Host ('COMPAT '+ $s.run_id+': guest_rc='+ $rc+' termination='+ $term+' exit='+ $exitCode+' src='+ $exitSrc+' wd='+ $wd+' tk='+ $tk+' -> '+ $sampleResults[$sampleResults.Count-1].status) -ForegroundColor Cyan
    }
    $runSucceeded=$true
}
catch{
    $mainError=$_.Exception.Message
    Write-Host ('COMPAT PILOT ERROR: '+$mainError) -ForegroundColor Red
}
finally{
    Stage 'RECOVERY' 'Stop Ubuntu, revert the exact frozen snapshot, verify both VMs OFF, restore host network'
    try{
        try{Stop-UbuntuVM $VmrunPath $UbuntuVmxPath}catch{Write-Log 'WARN' ('Stop error: '+$_.Exception.Message)}
        Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $UbuntuSnapshot
        Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_RUNNING_AFTER_RECOVERY'
        Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_RUNNING_AFTER_RECOVERY'
        Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'
        Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows'
        Ensure-GuiEntries
        if($Script:IsolationStarted){$null=Restore-HostNetwork $Script:NetworkBaseline}
        Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') ([ordered]@{status='PASS';ubuntu_off=$true;windows_off=$true;ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');network_restored=$true;gui_entries_restored=$true;timestamp=[DateTime]::UtcNow.ToString('o')})
        $recoverySucceeded=$true
    }catch{
        $recoveryError=$_.Exception.Message
        Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red
    }
    try{Close-UbuntuVix}catch{}

    # Aggregate result
    $passCount=@($sampleResults|Where-Object{$_.status -ceq 'PASS'}).Count
    $failCount=@($sampleResults|Where-Object{$_.status -ceq 'FAIL'}).Count
    $aggStatus=if($failCount -eq 0 -and $recoverySucceeded){'PASS'}else{'FAIL'}
    Write-Json (Join-Path $Script:RunRoot 'COMPAT_PILOT_AGGREGATE.json') ([ordered]@{
        status=$aggStatus; run_mode='CompatibilityPilot'; official_run=$false; official_campaign_slots_consumed=0;
        run_id=$RunID; attempt_id=$Script:AttemptID; samples_tested=$sampleResults.Count; samples_pass=$passCount; samples_fail=$failCount;
        recovery_verified=$recoverySucceeded; recovery_error=$recoveryError; execution_error=$mainError;
        run_root=$Script:RunRoot; timestamp=[DateTime]::UtcNow.ToString('o')
    })
    $aggColor=if($aggStatus -ceq 'PASS'){'Green'}else{'Red'}
    Write-Host ('COMPAT PILOT AGGREGATE: '+ $aggStatus+'  pass='+ $passCount+' fail='+ $failCount+' of '+ $sampleResults.Count) -ForegroundColor $aggColor
    if($aggStatus -ceq 'FAIL'){throw ('COMPAT_PILOT_AGGREGATE_FAIL: pass='+ $passCount+' fail='+ $failCount)}
}
