[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CampaignRoot,
    [Parameter(Mandatory=$true)][string]$VmrunPath,
    [Parameter(Mandatory=$true)][string]$VMwareGuiPath,
    [Parameter(Mandatory=$true)][string]$WindowsVmxPath,
    [Parameter(Mandatory=$true)][string]$UbuntuVmxPath,
    [string]$WindowsSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013',
    [string]$UbuntuSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013',
    [int]$PreRollSeconds=5,
    [int]$PostTailSeconds=10,
    [ValidateRange(30,300)][int]$ActiveWorkloadSeconds=60,
    [Parameter(Mandatory=$true)][ValidatePattern('^BEN_WIN_[0-9]{2}$')][string]$RunID,
    [Parameter(Mandatory=$true)][ValidateRange(1,30)][int]$GlobalOrder,
    [Parameter(Mandatory=$true)][ValidatePattern('^S(0[1-9]|1[0-5])$')][string]$ScenarioID,
    [Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Repetition,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-[0-9]{2}-[AB]$')][string]$ScenarioRunID,
    [Parameter(Mandatory=$true)][ValidatePattern('^S(0[1-9]|1[0-5])-WIN-[AB]$')][string]$FixtureSeed,
    [Parameter(Mandatory=$true)][ValidateSet('TRAIN','VALIDATION','TEST')][string]$Split,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Z0-9_]+$')][string]$ScenarioName,
    [Parameter(Mandatory=$true)][string]$LeadApplication
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false
function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Utf8NoBom([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};Write-Utf8NoBom $Path (($Object|ConvertTo-Json -Depth 20)+"`r`n")}
function Write-AtomicCreate([string]$Path,[object]$Object){if(Test-Path -LiteralPath $Path){throw ('EVIDENCE_ALREADY_EXISTS:'+ $Path)};Write-Json $Path $Object;return $Path}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'BENIGN_OFFICIAL_CONTROLLER.log') -Value $line -Encoding UTF8}}
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
    foreach($a in @($Baseline.PhysicalAdapters)){
        if([string]$a.InitialStatus -ceq 'Up'){
            Enable-NetAdapter -Name ([string]$a.Name) -Confirm:$false -ErrorAction Stop
        }
    }

    # DHCP and IPv6 router-advertisement convergence can exceed two minutes after
    # repeated disable/enable cycles. Keep the strict baseline comparison, but allow
    # a bounded five-minute convergence window and require three consecutive exact
    # samples before declaring recovery. No route, MAC, or adapter drift is waived.
    $deadline=[DateTime]::UtcNow.AddSeconds(300)
    $attempt=0
    $consecutiveExact=0
    $last='NOT_TESTED'
    do{
        Start-Sleep -Seconds 2
        $attempt++
        $cur=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID
        $check=Test-P5GNetworkRestored $Baseline $cur.PhysicalAdapters $cur.Routes ([pscustomobject]@{vms_safe=$true})
        if([bool]$check.restored){
            $consecutiveExact++
            if($consecutiveExact -ge 3){
                Write-Host ('NETWORK RESTORE CONFIRMED: attempts='+$attempt+' consecutive_exact='+$consecutiveExact) -ForegroundColor Green
                return $cur
            }
        } else {
            $consecutiveExact=0
            $last=[string]$check.reason
            if(($attempt % 10) -eq 0){
                Write-Host ('NETWORK RESTORE WAITING: attempts='+$attempt+' last_reason='+$last) -ForegroundColor Yellow
            }
        }
    }while([DateTime]::UtcNow -lt $deadline)
    throw ('NETWORK_RESTORE_NOT_CONFIRMED:attempts='+$attempt+':last_reason='+$last)
}
function Verify-Archive([string]$Zip,[object]$PackReceipt){Assert-True (Test-Path -LiteralPath $Zip -PathType Leaf) 'HOST_ARCHIVE_MISSING';$sha=SHA $Zip;Assert-True ($sha -ceq [string]$PackReceipt.archive_sha256) 'HOST_ARCHIVE_SHA_MISMATCH';Add-Type -AssemblyName System.IO.Compression.FileSystem;$z=[IO.Compression.ZipFile]::OpenRead($Zip);try{$names=@($z.Entries|ForEach-Object{$_.FullName});foreach($n in @('capture.pml','sysmon_process_tree.csv','telemetry_prepare_receipt.json','telemetry_capture_receipt.json','workload_prepare_receipt.json','workload_run_receipt.json','archive_manifest.json')){Assert-True ($names -contains $n) ('ARCHIVE_ENTRY_MISSING:'+ $n)}}finally{$z.Dispose()};[ordered]@{status='PASS';archive_sha256=$sha;archive_bytes=(Get-Item $Zip).Length;verified_utc=[DateTime]::UtcNow.ToString('o')}}
function New-RunManifest([string]$RunRoot){$rows=@();foreach($f in Get-ChildItem -LiteralPath $RunRoot -Recurse -File|Sort-Object FullName){if($f.Name -eq 'PACKAGE_MANIFEST.csv' -or $f.Name -eq 'RUN_FULL_VERIFICATION.json'){continue};$rows+=[pscustomobject]@{relative_path=$f.FullName.Substring($RunRoot.Length+1);bytes=$f.Length;sha256=(SHA $f.FullName)}};$path=Join-Path $RunRoot 'PACKAGE_MANIFEST.csv';$rows|Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8;return $path}

$PackageRoot=$PSScriptRoot
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
# Globals/functions above intentionally satisfy HCQNativeBridge's historical host contract.
. (Join-Path $PackageRoot 'HCQNativeBridge.ps1')

$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
foreach($p in @($CampaignRoot,$VmrunPath,$VMwareGuiPath,$WindowsVmxPath,$UbuntuVmxPath)){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
Assert-VmxHardening 'Windows' $WindowsVmxPath;Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_AT_START'
Assert-True (-not(Get-VmOn $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_AT_START'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows';Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'

$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16)
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:RunRoot=Join-Path $CampaignRoot ('02_WINDOWS\BENIGN\official_runs\'+$RunID+'_'+$Script:AttemptID+'_'+$stamp)
New-Item -ItemType Directory -Path $Script:RunRoot -Force|Out-Null
foreach($d in @('evidence','recovery')){New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot $d) -Force|Out-Null}
$OverallSw=[Diagnostics.Stopwatch]::StartNew()
$runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError=''
$workPrepareHost=Join-Path $Script:RunRoot 'evidence\workload_prepare_receipt.json'
$workRunHost=Join-Path $Script:RunRoot 'evidence\workload_run_receipt.json'
$telePrepHost=Join-Path $Script:RunRoot 'evidence\telemetry_prepare_receipt.json'
$teleCapHost=Join-Path $Script:RunRoot 'evidence\telemetry_capture_receipt.json'
$packHost=Join-Path $Script:RunRoot 'evidence\guest_pack_receipt.json'
$archiveHost=Join-Path $Script:RunRoot 'capture_archive.zip'

try{
    Stage 'PRESTATE' 'Verify frozen snapshots, hardening, and restore both VMware GUI entries without changing VM power state'
    $null=Invoke-HCQGuiAttachBoth
    $tabs=@(Get-HCQWorkstationTabNames);Assert-True ($tabs -contains 'Windows 11') 'WINDOWS_GUI_TAB_NOT_VISIBLE_PRE_RUN';Assert-True ($tabs -contains 'Ubuntu') 'UBUNTU_GUI_TAB_NOT_VISIBLE_PRE_RUN'
    $Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID
    Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline

    Stage 'ISOLATION' 'Disable baseline physical adapters and require zero IPv4/IPv6 default routes'
    Disable-HostNetwork $Script:NetworkBaseline

    Stage 'VM_START' 'Power on Windows by native VIX; Ubuntu remains OFF; restore visible VMware tabs'
    Start-VM $WindowsVmxPath 'Windows'
    Assert-True (-not(Get-VmOn $UbuntuVmxPath)) 'UBUNTU_POWERED_ON_UNEXPECTEDLY'
    $null=Invoke-HCQGuiAttachBoth

    $guestHelperRoot='C:\RansomLab\BenignOfficial\'+$RunID+'\Helpers\'+$Script:AttemptID
    $guestWork=(Join-Path $guestHelperRoot 'BENIGN_Guest_Workload.ps1')
    $guestTel=(Join-Path $guestHelperRoot 'Windows_GuestTelemetry.ps1')
    $guestPack=(Join-Path $guestHelperRoot 'BENIGN_Guest_Pack.ps1')
    Stage 'HELPER_TRANSFER' 'Transfer benign workload, generalized telemetry, and packer helpers via native VIX'
    Copy-ToGuest (Join-Path $PackageRoot 'BENIGN_Guest_Workload_Official.ps1') $guestWork
Copy-ToGuest (Join-Path $PackageRoot 'WINDOWS_BENIGN_SCENARIO_DISPATCHER_V1.ps1') (Join-Path $guestHelperRoot 'WINDOWS_BENIGN_SCENARIO_DISPATCHER_V1.ps1')
    Copy-ToGuest (Join-Path $PackageRoot 'P5G_R6_R8B_R4_R3_R7_Windows_GuestTelemetry.ps1') $guestTel
    Copy-ToGuest (Join-Path $PackageRoot 'BENIGN_Guest_Pack.ps1') $guestPack

    $guestWorkRoot='C:\RansomLab\BenignOfficial\'+$RunID+'\'+$Script:AttemptID+'\Workload'
    $guestWorkPrepare='C:\RansomLab\BenignOfficial\'+$RunID+'\'+$Script:AttemptID+'\workload_prepare_receipt.json'
    $guestWorkRun='C:\RansomLab\BenignOfficial\'+$RunID+'\'+$Script:AttemptID+'\workload_run_receipt.json'
    Stage 'WORKLOAD_PREPARE' ('Official '+$RunID+' '+$ScenarioID+' '+$ScenarioName+': all-15 toolcheck + deterministic scenario prepare before telemetry')
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestWork`" -Mode Prepare -AttemptID $($Script:AttemptID) -ReceiptPath `"$guestWorkPrepare`" -WorkRoot `"$guestWorkRoot`" -DurationSeconds $ActiveWorkloadSeconds -RunID `"$RunID`" -GlobalOrder $GlobalOrder -ScenarioID $ScenarioID -Repetition $Repetition -ScenarioRunID `"$ScenarioRunID`" -FixtureSeed `"$FixtureSeed`" -Split $Split -ScenarioName $ScenarioName -LeadApplication `"$LeadApplication`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('WORKLOAD_PREPARE_FAILED:'+ $r.Text)
    Copy-FromGuest $guestWorkPrepare $workPrepareHost
    $wp=Get-Content -LiteralPath $workPrepareHost -Raw|ConvertFrom-Json;Assert-True ([string]$wp.status -ceq 'PASS') 'WORKLOAD_PREPARE_RECEIPT_FAIL'

    $guestCapture='C:\RansomLab\TelemetryOutput\'+$RunID+'_'+$Script:AttemptID
    Stage 'TELEMETRY_START' 'Start real frozen Procmon telemetry in guest'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestTel`" -Mode Prepare -AttemptID $($Script:AttemptID) -RunID $RunID -GlobalOrder $GlobalOrder -OutputRoot `"$guestCapture`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('TELEMETRY_PREPARE_FAILED:'+ $r.Text)
    Copy-FromGuest ($guestCapture+'\prepare_receipt.json') $telePrepHost
    $tp=Get-Content -LiteralPath $telePrepHost -Raw|ConvertFrom-Json;Assert-True ([string]$tp.status -ceq 'PASS' -and [bool]$tp.telemetry_ready) 'TELEMETRY_NOT_READY'
    Write-Host '*** TELEMETRY READY ***' -ForegroundColor Green
    Start-Sleep -Seconds $PreRollSeconds

    Stage 'WORKLOAD_RUN' ('Execute 60-second compound hard-negative process tree: copy + rename/modify + compress + decompress + delete')
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestWork`" -Mode Run -AttemptID $($Script:AttemptID) -ReceiptPath `"$guestWorkRun`" -WorkRoot `"$guestWorkRoot`" -DurationSeconds $ActiveWorkloadSeconds -RunID `"$RunID`" -GlobalOrder $GlobalOrder -ScenarioID $ScenarioID -Repetition $Repetition -ScenarioRunID `"$ScenarioRunID`" -FixtureSeed `"$FixtureSeed`" -Split $Split -ScenarioName $ScenarioName -LeadApplication `"$LeadApplication`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('WORKLOAD_RUN_FAILED:'+ $r.Text)
    Copy-FromGuest $guestWorkRun $workRunHost
    $wr=Get-Content -LiteralPath $workRunHost -Raw|ConvertFrom-Json
    Assert-True ([string]$wr.status -ceq 'PASS') 'WORKLOAD_RECEIPT_FAIL';Assert-True ([int]$wr.process_exit_code -eq 0) 'WORKLOAD_EXIT_NONZERO';Assert-True ([bool]$wr.child_pid_absence_verified) 'WORKLOAD_CHILD_PID_NOT_ABSENT';Assert-True ([bool]$wr.execution_complete) 'WORKLOAD_INCOMPLETE';Assert-True ([double]$wr.active_duration_seconds -ge $ActiveWorkloadSeconds) 'WORKLOAD_DURATION_TOO_SHORT';Assert-True ([double]$wr.active_duration_seconds -le ($ActiveWorkloadSeconds+5.0)) 'WORKLOAD_DURATION_EXCESSIVE';Assert-True ([double]$wr.root_lifecycle_seconds -le ($ActiveWorkloadSeconds+10.0)) 'WORKLOAD_ROOT_LIFECYCLE_EXCESSIVE';Assert-True ([int]$wr.compound_task_count -ge 5) 'WORKLOAD_TASK_COUNT_TOO_LOW';Assert-True (@($wr.process_tree_edges).Count -ge 5) 'PROCESS_TREE_TOO_SMALL';Assert-True (@($wr.process_instances).Count -ge 6) 'PROCESS_INSTANCE_INVENTORY_TOO_SMALL'
    Write-Host ('WORKLOAD COMPLETE: SCENARIO='+$wr.scenario_id+' ROOT_PID='+$wr.root_pid+' ACTIVE_DURATION='+$wr.active_duration_seconds+'s ROOT_LIFECYCLE='+$wr.root_lifecycle_seconds+'s TASKS='+$wr.compound_task_count+' PIDS='+@($wr.target_pids).Count+' OPS='+(@($wr.operation_families)-join ',')) -ForegroundColor Green
    Start-Sleep -Seconds $PostTailSeconds

    Stage 'TELEMETRY_FINALIZE' 'Stop Procmon, preserve raw PML, and build compact Sysmon process-tree proof; defer full CSV materialization'
    $FinalizeHostSw=[Diagnostics.Stopwatch]::StartNew()
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestTel`" -Mode Finalize -AttemptID $($Script:AttemptID) -RunID $RunID -GlobalOrder $GlobalOrder -OutputRoot `"$guestCapture`" -TargetPID $($wr.root_pid) -ProcessName `"$($wr.root_process_name)`" -ProcessStartUtc `"$($wr.process_start_utc)`" -WorkloadReceiptPath `"$guestWorkRun`""
    $r=Invoke-GuestPowerShell $cmd 300;Assert-True ($r.ExitCode -eq 0) ('TELEMETRY_FINALIZE_FAILED:'+ $r.Text)
    $FinalizeHostSw.Stop()
    Copy-FromGuest ($guestCapture+'\capture_receipt.json') $teleCapHost
    $tc=Get-Content -LiteralPath $teleCapHost -Raw|ConvertFrom-Json
    Assert-True ([string]$tc.status -ceq 'PASS') 'TELEMETRY_CAPTURE_RECEIPT_FAIL'
    Assert-True ([int64]$tc.capture_pml_bytes -gt 0) 'PROCMON_PML_EMPTY'
    Assert-True (-not[bool]$tc.capture_csv_materialized) 'FULL_CSV_SHOULD_BE_DEFERRED'
    Assert-True ([int]$tc.sysmon_matched_start_count -ge 6) 'SYSMON_PROCESS_START_PROOF_INSUFFICIENT'
    Assert-True ([int]$tc.sysmon_matched_end_count -ge 6) 'SYSMON_PROCESS_END_PROOF_INSUFFICIENT'
    Assert-True ([int]$tc.sysmon_direct_task_edge_count -ge 5) 'SYSMON_DIRECT_TREE_EDGE_PROOF_INSUFFICIENT'
    Assert-True ([int]$tc.workload_process_tree_edge_count -ge 5) 'TELEMETRY_PROCESS_TREE_BINDING_MISSING'
    Assert-True ([double]$tc.workload_active_duration_seconds -ge $ActiveWorkloadSeconds) 'TELEMETRY_WORKLOAD_DURATION_TOO_SHORT'
    Assert-True ([double]$tc.workload_active_duration_seconds -le ($ActiveWorkloadSeconds+5.0)) 'TELEMETRY_WORKLOAD_DURATION_EXCESSIVE'
    Assert-True ([int]$tc.workload_process_instance_count -ge 6) 'TELEMETRY_PROCESS_INSTANCE_BINDING_MISSING'
    Write-Host ('REAL TELEMETRY: PML_BYTES='+$tc.capture_pml_bytes+' SYSMON_STARTS='+$tc.sysmon_matched_start_count+' SYSMON_ENDS='+$tc.sysmon_matched_end_count+' DIRECT_EDGES='+$tc.sysmon_direct_task_edge_count+' DURATION='+$tc.workload_active_duration_seconds+'s FINALIZE='+$FinalizeHostSw.Elapsed.TotalSeconds.ToString('F1')+'s') -ForegroundColor Green

    Stage 'GUEST_PACK' 'Hash and fast-compress raw Procmon PML + compact process-tree evidence and receipts inside guest'
    $PackHostSw=[Diagnostics.Stopwatch]::StartNew()
    $guestZip=$guestCapture+'\capture_archive.zip';$guestPackReceipt=$guestCapture+'\pack_receipt.json'
    $cmd="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$guestPack`" -CaptureDir `"$guestCapture`" -WorkloadPrepareReceipt `"$guestWorkPrepare`" -WorkloadRunReceipt `"$guestWorkRun`" -OutputZip `"$guestZip`" -PackReceiptPath `"$guestPackReceipt`" -AttemptID $($Script:AttemptID)"
    $r=Invoke-GuestPowerShell $cmd 600;Assert-True ($r.ExitCode -eq 0) ('GUEST_PACK_FAILED:'+ $r.Text)
    $PackHostSw.Stop()
    Copy-FromGuest $guestPackReceipt $packHost
    $pr=Get-Content -LiteralPath $packHost -Raw|ConvertFrom-Json
    Assert-True ([string]$pr.status -ceq 'PASS') 'PACK_RECEIPT_FAIL'
    Assert-True ([bool]$pr.raw_procmon_pml_preserved) 'RAW_PML_NOT_PRESERVED'
    Assert-True (-not[bool]$pr.derived_full_csv_included) 'DERIVED_FULL_CSV_SHOULD_NOT_BE_PACKED'
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
    Write-Host ('QUALIFICATION EXECUTION ERROR: '+$mainError) -ForegroundColor Red
}
finally{
    Stage 'RECOVERY' 'Stop Windows, revert exact frozen snapshot, verify Ubuntu unchanged, restore host network, restore VMware GUI entries'
    try{
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
        $rec=[ordered]@{status='PASS';windows_off=(-not(Get-VmOn $WindowsVmxPath));ubuntu_off=(-not(Get-VmOn $UbuntuVmxPath));windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot_expected=$WindowsSnapshot;ubuntu_snapshot_expected=$UbuntuSnapshot;network_exactly_restored=$true;ipv4_default_route_count=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '0.0.0.0/0'}).Count;ipv6_default_route_count=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -eq '::/0'}).Count;vmware_tab_names=$tabs;windows_gui_visible=$guiWin;ubuntu_gui_visible=$guiUbu;measured_utc=[DateTime]::UtcNow.ToString('o')}
        Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') $rec
        $recoverySucceeded=$true
    }catch{$recoveryError=$_.Exception.Message;Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red}
    try{Close-HCQVix}catch{}
}

if(-not $runSucceeded -or -not $recoverySucceeded){
    $result=[ordered]@{schema_version='1.0';gate='BENIGN_OFFICIAL_RUN';status='FAIL';AttemptID=$Script:AttemptID;qualification_only=$false;official_run=$true;official_campaign_slots_consumed=0;run_id=$RunID;global_order=$GlobalOrder;scenario_id=$ScenarioID;scenario_name=$ScenarioName;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunID;fixture_seed=$FixtureSeed;lead_application=$LeadApplication;execution_error=$mainError;recovery_error=$recoveryError;run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')};Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') $result;throw ('BENIGN_OFFICIAL_RUN_FAIL run_id='+$RunID+' execution='+$mainError+' recovery='+$recoveryError)
}
Stage 'PACKAGE_VERIFY' 'Create complete run manifest and verify all listed evidence hashes'
$OverallSw.Stop()
$result=[ordered]@{schema_version='1.0';gate='BENIGN_OFFICIAL_RUN';status='PASS';AttemptID=$Script:AttemptID;qualification_only=$false;official_run=$true;official_campaign_slots_consumed=1;run_id=$RunID;global_order=$GlobalOrder;scenario_id=$ScenarioID;scenario_name=$ScenarioName;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunID;fixture_seed=$FixtureSeed;lead_application=$LeadApplication;ground_truth='BENIGN';workload=($ScenarioID+'_'+$ScenarioName+'_SCENARIO_AWARE_V27');telemetry='Procmon_raw_PML_plus_Sysmon_process_tree_fast_finalize';csv_materialization='DEFERRED_OFFLINE';compressed_only_bulk_telemetry_on_host=$true;recovery_verified=$true;workload_duration_seconds=[double]$wr.active_duration_seconds;workload_root_lifecycle_seconds=[double]$wr.root_lifecycle_seconds;telemetry_finalize_seconds=[Math]::Round($FinalizeHostSw.Elapsed.TotalSeconds,3);pack_seconds=[Math]::Round($PackHostSw.Elapsed.TotalSeconds,3);archive_transfer_seconds=[Math]::Round($TransferSw.Elapsed.TotalSeconds,3);total_run_seconds=[Math]::Round($OverallSw.Elapsed.TotalSeconds,3);run_root=$Script:RunRoot;timestamp=[DateTime]::UtcNow.ToString('o')}
Write-Json (Join-Path $Script:RunRoot 'RUN_RESULT.json') $result
$manifest=New-RunManifest $Script:RunRoot
$rows=@(Import-Csv -LiteralPath $manifest);$pass=0;$fail=0;$details=@();foreach($row in $rows){$p=Join-Path $Script:RunRoot $row.relative_path;if((Test-Path -LiteralPath $p -PathType Leaf) -and ((Get-Item $p).Length -eq [int64]$row.bytes) -and ((SHA $p) -ceq [string]$row.sha256)){$pass++;$details+=[ordered]@{path=$row.relative_path;status='PASS'}}else{$fail++;$details+=[ordered]@{path=$row.relative_path;status='FAIL'}}};$full=[ordered]@{status=$(if($fail-eq0){'PASS'}else{'FAIL'});manifest_path=$manifest;manifest_sha256=(SHA $manifest);pass=$pass;fail=$fail;details=$details;timestamp=[DateTime]::UtcNow.ToString('o')};Write-Json (Join-Path $Script:RunRoot 'RUN_FULL_VERIFICATION.json') $full;Assert-True ($fail -eq 0) 'RUN_PACKAGE_SELF_VERIFICATION_FAILED'
Write-Host '';Write-Host ('FINAL WINDOWS OFFICIAL BENIGN RUN PASS: '+$RunID) -ForegroundColor Green;Write-Host ('Evidence package: '+$Script:RunRoot) -ForegroundColor Green;Write-Host ('Official benign campaign slot completed: '+$GlobalOrder+'/30 Windows; run_id='+$RunID) -ForegroundColor Yellow;Write-Host ('TOTAL OFFICIAL RUN SECONDS: '+$OverallSw.Elapsed.TotalSeconds.ToString('F1')) -ForegroundColor Green
$Script:RunRoot
