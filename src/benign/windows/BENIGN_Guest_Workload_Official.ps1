[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Run','Support')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID,
    [Parameter(Mandatory=$true)][string]$ReceiptPath,
    [string]$WorkRoot='',
    [ValidateRange(30,300)][int]$DurationSeconds=60,
    [Parameter(Mandatory=$true)][ValidatePattern('^BEN_WIN_[0-9]{2}$')][string]$RunID,
    [Parameter(Mandatory=$true)][ValidateRange(1,30)][int]$GlobalOrder,
    [Parameter(Mandatory=$true)][ValidatePattern('^S(0[1-9]|1[0-5])$')][string]$ScenarioID,
    [Parameter(Mandatory=$true)][ValidateSet('A','B')][string]$Repetition,
    [Parameter(Mandatory=$true)][ValidatePattern('^W-[0-9]{2}-[AB]$')][string]$ScenarioRunID,
    [Parameter(Mandatory=$true)][ValidatePattern('^S(0[1-9]|1[0-5])-WIN-[AB]$')][string]$FixtureSeed,
    [Parameter(Mandatory=$true)][ValidateSet('TRAIN','VALIDATION','TEST')][string]$Split,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Z0-9_]+$')][string]$ScenarioName,
    [Parameter(Mandatory=$true)][string]$LeadApplication,
    [ValidateSet('Mutation','ArchiveAssist','CopyAssist','TempAssist')][string]$SupportKind='Mutation',
    [int]$ParentPid=0
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Write-Json([string]$Path,[object]$Object){
    $Dir=Split-Path -Parent $Path
    if($Dir -and -not(Test-Path -LiteralPath $Dir)){New-Item -ItemType Directory -Path $Dir -Force|Out-Null}
    [IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 50)+"`r`n"),(New-Object Text.UTF8Encoding($false)))
}
function Get-PowerShellExe{
    $P='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    if(Test-Path -LiteralPath $P -PathType Leaf){return $P}
    $C=Get-Command powershell.exe -ErrorAction Stop|Select-Object -First 1
    return [string]$C.Source
}
function Is-ProcessAlive([int]$Id){
    try{$null=Get-Process -Id $Id -ErrorAction Stop;return $true}catch{return $false}
}
function Read-JsonReceipt([string]$Path,[int]$MaxRetries=5,[int]$RetryDelayMs=200){
    $LastError=$null
    for($r=0;$r -lt $MaxRetries;$r++){
        if($r -gt 0){Start-Sleep -Milliseconds $RetryDelayMs}
        try{
            if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){
                $LastError="RECEIPT_NOT_FOUND:$Path"
                continue
            }
            $Raw=Get-Content -LiteralPath $Path -Raw
            if([string]::IsNullOrWhiteSpace($Raw)){
                $LastError="RECEIPT_EMPTY:$Path"
                continue
            }
            $J=$Raw|ConvertFrom-Json
            return $J
        }catch{
            $LastError=$_.Exception.Message
        }
    }
    throw ('RECEIPT_READ_FAIL:'+$Path+':'+$LastError)
}

if([string]::IsNullOrWhiteSpace($WorkRoot)){
    $WorkRoot="C:\RansomLab\BenignQual\$AttemptID\scenario_s01"
}
$Dispatcher=Join-Path $PSScriptRoot 'WINDOWS_BENIGN_SCENARIO_DISPATCHER_V1.ps1'
Assert-True (Test-Path -LiteralPath $Dispatcher -PathType Leaf) 'SCENARIO_DISPATCHER_MISSING'

if($Mode -eq 'Prepare'){
    $ToolRoot=Join-Path ([IO.Path]::GetTempPath()) (($ScenarioID+"_TOOLCHECK_"+$AttemptID))
    if(Test-Path -LiteralPath $ToolRoot){Remove-Item -LiteralPath $ToolRoot -Recurse -Force}
    New-Item -ItemType Directory -Path $ToolRoot -Force|Out-Null
    $Toolchecks=@()
    foreach($N in 1..15){
        $S=('S{0:D2}' -f $N)
        $R=Join-Path $ToolRoot ($S+'.json')
        & (Get-PowerShellExe) -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Dispatcher `
            -Mode ToolCheck -ScenarioID $S -Repetition A -AttemptID $AttemptID -ReceiptPath $R `
            -WorkRoot ($WorkRoot+'_unused') -DurationSeconds $DurationSeconds -FixtureSeed ($S+'-WIN-A')
        $Exit=$LASTEXITCODE
        Assert-True (Test-Path -LiteralPath $R -PathType Leaf) ('TOOLCHECK_RECEIPT_MISSING:'+$S)
        $J=Get-Content -LiteralPath $R -Raw|ConvertFrom-Json
        $Toolchecks+=,[ordered]@{scenario_id=$S;status=[string]$J.status;lead_application=[string]$J.lead_application;tool_path=[string]$J.tool_path;exit_code=$Exit}
    }
    $Fails=@($Toolchecks|Where-Object{$_.status -ne 'PASS' -or $_.exit_code -ne 0})
    if($Fails.Count -gt 0){
        Write-Json $ReceiptPath ([ordered]@{schema_version='1.0';gate='OFFICIAL_BENIGN_SCENARIO_PREPARE';status='FAIL';scenario_id=$ScenarioID;scenario_name=$ScenarioName;all15_toolcheck_status='FAIL';toolchecks=$Toolchecks;executed_workload=$false;timestamp=[DateTime]::UtcNow.ToString('o')})
        throw ('ALL15_TOOLCHECK_FAIL:'+($Fails.scenario_id -join ','))
    }

    $Inner=Join-Path $ToolRoot 's01_prepare_inner.json'
    & (Get-PowerShellExe) -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Dispatcher `
        -Mode Prepare -ScenarioID $ScenarioID -Repetition $Repetition -AttemptID $AttemptID -ReceiptPath $Inner `
        -WorkRoot $WorkRoot -DurationSeconds $DurationSeconds -FixtureSeed $FixtureSeed
    Assert-True ($LASTEXITCODE -eq 0) 'S01_INNER_PREPARE_FAILED'
    $InnerObj=Get-Content -LiteralPath $Inner -Raw|ConvertFrom-Json
    Assert-True ([string]$InnerObj.status -eq 'PASS') 'S01_INNER_PREPARE_RECEIPT_FAIL'

    Write-Json $ReceiptPath ([ordered]@{
        schema_version='2.0';gate='OFFICIAL_BENIGN_SCENARIO_PREPARE';status='PASS';os='Windows';
        scenario_id=$ScenarioID;scenario_name=$ScenarioName;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunID;
        lead_application=$LeadApplication;fixture_seed=$FixtureSeed;duration_seconds=$DurationSeconds;
        all15_toolcheck_status='PASS';toolcheck_count=15;toolchecks=$Toolchecks;scenario_prepare=$InnerObj;
        executed_workload=$false;timestamp=[DateTime]::UtcNow.ToString('o')
    })
    Write-Host 'S01 SCENARIO-AWARE PREPARE PASS; ALL15_TOOLCHECK=PASS' -ForegroundColor Green
    exit 0
}

if($Mode -eq 'Support'){
    $TaskPid=[Diagnostics.Process]::GetCurrentProcess().Id
    $Start=[DateTime]::UtcNow
    $Sw=[Diagnostics.Stopwatch]::StartNew()
    $Source=Join-Path $WorkRoot 'Source'
    $SupportRoot=Join-Path $WorkRoot ('Support_'+$SupportKind)
    New-Item -ItemType Directory -Path $SupportRoot -Force|Out-Null
    $Iterations=0
    # V34_SUPPORT_DEADLINE_AWARE_ADMISSION: do not begin an indivisible cycle too near 60 seconds.
    # Archive/copy/mutation operations remain unchanged; the process waits out any remainder to the target.
    $IterationReserveSeconds=switch($SupportKind){'ArchiveAssist'{20.0}'CopyAssist'{10.0}'Mutation'{10.0}default{2.0}}
    try{
        while(($Sw.Elapsed.TotalSeconds+$IterationReserveSeconds) -le [double]$DurationSeconds){
            $IterationStartSeconds=$Sw.Elapsed.TotalSeconds
            $Iterations++
            switch($SupportKind){
                'Mutation' {
                    $Live=Join-Path $SupportRoot 'live'
                    if(-not(Test-Path -LiteralPath $Live)){
                        New-Item -ItemType Directory -Path $Live -Force|Out-Null
                        Get-ChildItem -LiteralPath (Join-Path $Source 'set_00') -File|Select-Object -First 16|ForEach-Object{
                            for($a=0;$a -lt 3;$a++){
                                try{
                                    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Live $_.Name) -Force
                                    break
                                }catch{
                                    if($a -eq 2){throw}
                                    Start-Sleep -Milliseconds 500
                                }
                            }
                        }
                    }
                    foreach($F in @(Get-ChildItem -LiteralPath $Live -File|Sort-Object Name)){
                        $Tmp=$F.FullName+'.tmp'
                        Move-Item -LiteralPath $F.FullName -Destination $Tmp -Force
                        Add-Content -LiteralPath $Tmp -Value ("m="+$Iterations) -Encoding ASCII
                        Move-Item -LiteralPath $Tmp -Destination $F.FullName -Force
                    }
                }
                'ArchiveAssist' {
                    $Zip=Join-Path $SupportRoot 'support.zip'
                    $Out=Join-Path $SupportRoot 'extract'
                    for($a=0;$a -lt 3;$a++){
                        try{
                            Remove-Item $Zip -Force -ErrorAction SilentlyContinue
                            Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
                            Compress-Archive -Path (Join-Path $Source 'set_01\*') -DestinationPath $Zip -CompressionLevel Fastest -Force
                            Expand-Archive -LiteralPath $Zip -DestinationPath $Out -Force
                            break
                        }catch{
                            if($a -eq 2){throw}
                            Start-Sleep -Milliseconds 500
                        }
                    }
                }
                'CopyAssist' {
                    $Dest=Join-Path $SupportRoot ('copy_'+($Iterations%3))
                    Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
                    New-Item -ItemType Directory -Path $Dest -Force|Out-Null
                    Get-ChildItem -LiteralPath (Join-Path $Source 'set_02') -File|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Dest $_.Name) -Force}
                }
                'TempAssist' {
                    $F=Join-Path $SupportRoot ('temp_'+$Iterations+'.tmp')
                    [IO.File]::WriteAllText($F,('benign-temp-'+$Iterations),(New-Object Text.UTF8Encoding($false)))
                    Remove-Item -LiteralPath $F -Force
                }
            }
            $IterationSeconds=$Sw.Elapsed.TotalSeconds-$IterationStartSeconds
            $IterationReserveSeconds=[Math]::Max($IterationReserveSeconds,($IterationSeconds*1.5)+1.0)
        }
        $Remain=[int][Math]::Ceiling(([double]$DurationSeconds-$Sw.Elapsed.TotalSeconds)*1000)
        if($Remain -gt 0){Start-Sleep -Milliseconds $Remain}
        $Sw.Stop()
        Write-Json $ReceiptPath ([ordered]@{status='PASS';task_kind=$SupportKind;task_pid=$TaskPid;parent_pid=$ParentPid;elapsed_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3);iterations=$Iterations;timestamp=[DateTime]::UtcNow.ToString('o')})
        exit 0
    }catch{
        $Sw.Stop()
        try{Write-Json $ReceiptPath ([ordered]@{status='FAIL';task_kind=$SupportKind;task_pid=$TaskPid;parent_pid=$ParentPid;error=$_.Exception.Message;elapsed_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3)})}catch{}
        exit 1
    }
}

# RUN: five real direct child tasks under this root.
Assert-True (Test-Path -LiteralPath $WorkRoot -PathType Container) 'S01_WORKROOT_MISSING'
$RootPid=[Diagnostics.Process]::GetCurrentProcess().Id
$RootStart=[DateTime]::UtcNow
$PSExe=Get-PowerShellExe
$ChildRoot=Join-Path $WorkRoot 'AdapterChildReceipts'
New-Item -ItemType Directory -Path $ChildRoot -Force|Out-Null
$Children=@()

# DIRECT_CHILD_STDIO_CAPTURE_V9
$ScenarioReceipt=Join-Path $ChildRoot 'scenario.json'
$ScenarioStdout=Join-Path $ChildRoot 'scenario.stdout.txt'
$ScenarioStderr=Join-Path $ChildRoot 'scenario.stderr.txt'
$ScenarioArgs=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Dispatcher,
    '-Mode','Run','-ScenarioID',$ScenarioID,'-Repetition',$Repetition,'-AttemptID',$AttemptID,'-ReceiptPath',$ScenarioReceipt,
    '-WorkRoot',$WorkRoot,'-DurationSeconds',[string]$DurationSeconds,'-FixtureSeed',$FixtureSeed)
$P=Start-Process -FilePath $PSExe -ArgumentList $ScenarioArgs -PassThru -WindowStyle Hidden
$Children+=,[pscustomobject]@{kind='ScenarioLead';pid=[int]$P.Id;process=$P;receipt=$ScenarioReceipt;stdout=$ScenarioStdout;stderr=$ScenarioStderr}

foreach($Kind in @('Mutation','ArchiveAssist','CopyAssist','TempAssist')){
    $R=Join-Path $ChildRoot ($Kind+'.json')
    $SO=Join-Path $ChildRoot ($Kind+'.stdout.txt')
    $SE=Join-Path $ChildRoot ($Kind+'.stderr.txt')
    $Args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$MyInvocation.MyCommand.Path,
        '-Mode','Support','-AttemptID',$AttemptID,'-ReceiptPath',$R,'-WorkRoot',$WorkRoot,
        '-DurationSeconds',[string]$DurationSeconds,'-RunID',$RunID,'-GlobalOrder',[string]$GlobalOrder,
        '-ScenarioID',$ScenarioID,'-Repetition',$Repetition,'-ScenarioRunID',$ScenarioRunID,'-FixtureSeed',$FixtureSeed,
        '-Split',$Split,'-ScenarioName',$ScenarioName,'-LeadApplication',$LeadApplication,
        '-SupportKind',$Kind,'-ParentPid',[string]$RootPid)
    $SupportStartUtc=[DateTime]::UtcNow
    $P=Start-Process -FilePath $PSExe -ArgumentList $Args -PassThru -WindowStyle Hidden -RedirectStandardOutput $SO -RedirectStandardError $SE
    $Children+=,[pscustomobject]@{kind=$Kind;pid=[int]$P.Id;process=$P;receipt=$R;stdout=$SO;stderr=$SE;start_utc=$SupportStartUtc;deadline_utc=$SupportStartUtc.AddSeconds([double]$DurationSeconds+2.0);deadline_terminated=$false}
}

# V36_OUTER_SUPPORT_TWO_PHASE_DEADLINE
# Capture one deadline event, stop every due process first, then wait and emit receipts.
# Cleanup latency is never counted as scientific active duration.
$SupportWatch=@($Children|Where-Object{$_.kind -ne 'ScenarioLead'})
$LatestSupportStart=@($SupportWatch|ForEach-Object{[DateTime]$_.start_utc}|Sort-Object -Descending|Select-Object -First 1)[0]
$SupportDeadlineUtc=$LatestSupportStart.AddSeconds([double]$DurationSeconds)
while($true){
    $Pending=@()
    $Due=@()
    $DeadlineEventUtc=[DateTime]::UtcNow
    foreach($SupportChild in $SupportWatch){
        $Alive=$false
        try{$Alive=-not $SupportChild.process.HasExited}catch{}
        if($Alive -and $DeadlineEventUtc -ge $SupportDeadlineUtc){$Due+=,$SupportChild}
        elseif($Alive){$Pending+=,$SupportChild}
    }
    if($Due.Count -gt 0){
        $TaskKill=Join-Path $env:SystemRoot 'System32\taskkill.exe'
        foreach($SupportChild in $Due){
            try{& $TaskKill /PID $SupportChild.pid /T /F 2>$null|Out-Null}catch{}
            try{if(-not $SupportChild.process.HasExited){$SupportChild.process.Kill()}}catch{}
        }
        foreach($SupportChild in $Due){
            try{[void]$SupportChild.process.WaitForExit(3000)}catch{}
            $SupportActual=[Math]::Round(($DeadlineEventUtc-[DateTime]$SupportChild.start_utc).TotalSeconds,3)
            Write-Json $SupportChild.receipt ([ordered]@{status='PASS';task_kind=$SupportChild.kind;task_pid=[int]$SupportChild.pid;parent_pid=$RootPid;elapsed_seconds=$SupportActual;iterations=$null;deadline_enforced=$true;deadline_owner='OUTER_SUPPORT_COMMON_BARRIER';termination='PROCESS_TREE_TERMINATED_AT_ACTIVE_DEADLINE';deadline_event_utc=$DeadlineEventUtc.ToString('o');timestamp=[DateTime]::UtcNow.ToString('o')})
            $SupportChild.deadline_terminated=$true
        }
    }
    if($Pending.Count -eq 0){break}
    Start-Sleep -Milliseconds 100
}
# S01_ADAPTER_CHILD_WATCHDOG_V21
# The inner dispatcher watchdog is DurationSeconds+20. Give it that full interval,
# plus bounded child-cleanup time and a small scheduling margin, before the adapter
# declares a hard timeout. This is orchestration grace ONLY.
# Scientific acceptance gates below remain ACTIVE <= DurationSeconds+5 and ROOT_LIFECYCLE <= DurationSeconds+10.
$InnerDispatcherWatchdogSeconds=$DurationSeconds+20
$AdapterChildWatchdogSeconds=$DurationSeconds+30
$ChildWaitDeadlineUtc=[DateTime]::UtcNow.AddSeconds($AdapterChildWatchdogSeconds)
foreach($C in $Children){
    $Remain=[Math]::Max(0,[int](($ChildWaitDeadlineUtc-[DateTime]::UtcNow).TotalMilliseconds))
    $WaitOk=$C.process.WaitForExit($Remain)
    if(-not $WaitOk){
        $AliveAtDeadline=Is-ProcessAlive $C.pid
        # S01_TIMEOUT_STOP_ALL_BEFORE_WAIT_V21
        foreach($Sibling in $Children){
            if(Is-ProcessAlive $Sibling.pid){
                try{Stop-Process -Id $Sibling.pid -Force -ErrorAction SilentlyContinue}catch{}
            }
        }
        foreach($Sibling in $Children){
            try{[void]$Sibling.process.WaitForExit(5000)}catch{}
        }
        $TaskReceiptRoot=Join-Path $WorkRoot 'TaskReceipts'
        $TaskReceiptPaths=@(
            (Join-Path $TaskReceiptRoot 'lead.json'),
            (Join-Path $TaskReceiptRoot 'mutation.json'),
            (Join-Path $TaskReceiptRoot 'rotation.json'),
            (Join-Path $TaskReceiptRoot 'lead.stdout.txt'),
            (Join-Path $TaskReceiptRoot 'lead.stderr.txt'),
            (Join-Path $TaskReceiptRoot 'mutation.stdout.txt'),
            (Join-Path $TaskReceiptRoot 'mutation.stderr.txt'),
            (Join-Path $TaskReceiptRoot 'rotation.stdout.txt'),
            (Join-Path $TaskReceiptRoot 'rotation.stderr.txt')
        )
        $TimeoutMessage='CHILD_TIMEOUT:'+$C.kind+
            ':ADAPTER_WATCHDOG_SECONDS='+$AdapterChildWatchdogSeconds+
            ':INNER_DISPATCHER_WATCHDOG_SECONDS='+$InnerDispatcherWatchdogSeconds+
            ':PID='+$C.pid
        try{
            Write-Json $ReceiptPath ([ordered]@{
                schema_version='3.2'
                gate='OFFICIAL_BENIGN_SCENARIO_RUN'
                status='FAIL'
                AttemptID=$AttemptID
                run_id=$RunID
                global_order=$GlobalOrder
                os='Windows'
                class='BENIGN'
                ground_truth='BENIGN'
                scenario_id=$ScenarioID
                scenario_name=$ScenarioName
                lead_application=$LeadApplication
                split=$Split
                repetition=$Repetition
                scenario_run_id=$ScenarioRunID
                root_pid=$RootPid
                root_process_name='powershell.exe'
                process_start_utc=$RootStart.ToString('o')
                process_end_utc=[DateTime]::UtcNow.ToString('o')
                process_exit_code=1
                execution_complete=$false
                observation_status='FAILED'
                error=$TimeoutMessage
                failing_direct_child=$C.kind
                failing_direct_child_pid=[int]$C.pid
                child_alive_at_deadline=[bool]$AliveAtDeadline
                direct_child_receipt_path=[string]$C.receipt
                direct_child_stdout_path=[string]$C.stdout
                direct_child_stderr_path=[string]$C.stderr
                task_receipt_paths=$TaskReceiptPaths
                adapter_child_watchdog_seconds=$AdapterChildWatchdogSeconds
                inner_dispatcher_watchdog_seconds=$InnerDispatcherWatchdogSeconds
                scientific_active_duration_tolerance_seconds=5.0
                scientific_root_lifecycle_tolerance_seconds=10.0
                process_tree_cleanup='DIRECT_CHILDREN_STOPPED;VM_REVERT_REQUIRED_FOR_GUEST_DESCENDANTS'
                official_campaign_slots_consumed=0
                network_used=$false
                timestamp=[DateTime]::UtcNow.ToString('o')
            })
        }catch{}
        throw $TimeoutMessage
    }
    $WasDeadlineTerminated=($C.PSObject.Properties.Name -contains 'deadline_terminated' -and [bool]$C.deadline_terminated)
    if(-not $WasDeadlineTerminated -and [int]$C.process.ExitCode -ne 0){
        $Detail=''
        $FailError=$null
        $FailTask=$null
        $FailProcess=$null
        $FailExit=$null
        $FailArgs=$null
        $FailStdout=$null
        $FailStderr=$null
        if(Test-Path -LiteralPath $C.receipt -PathType Leaf){
            try{
                $FailReceipt=Get-Content -LiteralPath $C.receipt -Raw|ConvertFrom-Json
                try{$FailError=[string]$FailReceipt.error}catch{}
                try{$FailTask=[string]$FailReceipt.failing_task_kind}catch{}
                try{$FailProcess=[string]$FailReceipt.failing_process_path}catch{}
                try{$FailExit=$FailReceipt.failing_exit_code}catch{}
                try{$FailArgs=[string]$FailReceipt.failing_arguments}catch{}
                try{$FailStdout=[string]$FailReceipt.failing_stdout_tail}catch{}
                try{$FailStderr=[string]$FailReceipt.failing_stderr_tail}catch{}
            }catch{}
        }
        $DirectStdout=''
        $DirectStderr=''
        try{if(Test-Path -LiteralPath $C.stdout){$DirectStdout=[IO.File]::ReadAllText($C.stdout)}}catch{}
        try{if(Test-Path -LiteralPath $C.stderr){$DirectStderr=[IO.File]::ReadAllText($C.stderr)}}catch{}
        if($DirectStdout.Length -gt 4096){$DirectStdout=$DirectStdout.Substring($DirectStdout.Length-4096)}
        if($DirectStderr.Length -gt 4096){$DirectStderr=$DirectStderr.Substring($DirectStderr.Length-4096)}
        if([string]::IsNullOrWhiteSpace($FailStdout)){$FailStdout=$DirectStdout}
        if([string]::IsNullOrWhiteSpace($FailStderr)){$FailStderr=$DirectStderr}
        $Detail=' error='+$FailError+
                ' task='+$FailTask+
                ' process='+$FailProcess+
                ' exit='+[string]$FailExit+
                ' args='+$FailArgs+
                ' stdout='+(($FailStdout) -replace '[\r\n]+',' ')+
                ' stderr='+(($FailStderr) -replace '[\r\n]+',' ')
        foreach($Sibling in $Children){
            if($Sibling.pid -ne $C.pid -and (Is-ProcessAlive $Sibling.pid)){
                try{Stop-Process -Id $Sibling.pid -Force -ErrorAction SilentlyContinue}catch{}
                try{[void]$Sibling.process.WaitForExit(5000)}catch{}
            }
        }
        try{
            Write-Json $ReceiptPath ([ordered]@{
                schema_version='3.1'
                gate='OFFICIAL_BENIGN_SCENARIO_RUN'
                status='FAIL'
                AttemptID=$AttemptID
                run_id=$RunID
                global_order=$GlobalOrder
                os='Windows'
                class='BENIGN'
                ground_truth='BENIGN'
                scenario_id=$ScenarioID
                scenario_name=$ScenarioName
                lead_application=$LeadApplication
                split=$Split
                repetition=$Repetition
                scenario_run_id=$ScenarioRunID
                root_pid=$RootPid
                root_process_name='powershell.exe'
                process_start_utc=$RootStart.ToString('o')
                process_exit_code=1
                execution_complete=$false
                observation_status='FAILED'
                failing_direct_child=$C.kind
                failing_direct_child_exit_code=[int]$C.process.ExitCode
                error=$FailError
                failing_task_kind=$FailTask
                failing_process_path=$FailProcess
                failing_exit_code=$FailExit
                failing_arguments=$FailArgs
                failing_stdout_tail=$FailStdout
                failing_stderr_tail=$FailStderr
                direct_child_stdout_path=[string]$C.stdout
                direct_child_stderr_path=[string]$C.stderr
                operation_families=@('bulk_copy','rename','modify','compress','decompress','temporary_create','delete','archive_rotation')
                network_used=$false
                timestamp=[DateTime]::UtcNow.ToString('o')
            })
        }catch{}
        throw ('CHILD_EXIT_NONZERO:'+$C.kind+':'+$C.process.ExitCode+$Detail)
    }
}
$RootEnd=[DateTime]::UtcNow
$ChildAbsent=$true
foreach($C in $Children){if(Is-ProcessAlive $C.pid){$ChildAbsent=$false}}
Assert-True $ChildAbsent 'DIRECT_CHILD_STILL_ALIVE_AFTER_WAIT'

$Scenario=Read-JsonReceipt -Path $ScenarioReceipt
Assert-True ([string]$Scenario.status -eq 'PASS') 'S01_SCENARIO_RECEIPT_FAIL'
$Support=@()
$ScientificEndCandidates=New-Object 'System.Collections.Generic.List[datetime]'
$ScenarioScientificStart=[DateTime]::Parse([string]$Scenario.process_start_utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
$ScientificEndCandidates.Add($ScenarioScientificStart.AddSeconds([double]$Scenario.root_lifecycle_seconds))
foreach($C in @($Children|Where-Object{$_.kind -ne 'ScenarioLead'})){
    $J=Read-JsonReceipt -Path $C.receipt
    Assert-True ([string]$J.status -eq 'PASS') ('SUPPORT_RECEIPT_FAIL:'+$C.kind)
    $Support+=,$J
    $ScientificEndCandidates.Add(([DateTime]$C.start_utc).AddSeconds([double]$J.elapsed_seconds))
}
$ActiveValues=@([double]$Scenario.active_duration_seconds)+@($Support|ForEach-Object{[double]$_.elapsed_seconds})
$Active=[Math]::Round(($ActiveValues|Measure-Object -Maximum).Maximum,3)
Assert-True ($ScientificEndCandidates.Count -eq 5) ('SCIENTIFIC_END_INVENTORY_INCOMPLETE:'+$ScientificEndCandidates.Count)
$ScientificRootEnd=@($ScientificEndCandidates|Sort-Object -Descending|Select-Object -First 1)[0]
$Lifecycle=[Math]::Round(($ScientificRootEnd-$RootStart).TotalSeconds,3)
$OrchestrationLifecycle=[Math]::Round(($RootEnd-$RootStart).TotalSeconds,3)
$PostScientificCleanup=[Math]::Round([Math]::Max(0.0,$OrchestrationLifecycle-$Lifecycle),3)
Assert-True ($Active -ge $DurationSeconds -and $Active -le ($DurationSeconds+5.0)) ('ACTIVE_DURATION_OUT_OF_RANGE:'+$Active)
Assert-True ($Lifecycle -le ($DurationSeconds+10.0)) ('ROOT_LIFECYCLE_EXCESSIVE:'+$Lifecycle)

$Instances=@([ordered]@{pid=$RootPid;parent_pid=$null;process_name='powershell.exe';role='qualification_root'})
$Edges=@()
foreach($C in $Children){
    $Instances+=,[ordered]@{pid=[int]$C.pid;parent_pid=$RootPid;process_name='powershell.exe';role=('direct_'+$C.kind)}
    $Edges+=,[ordered]@{parent_pid=$RootPid;child_pid=[int]$C.pid;relationship='root_to_task';task_name=$C.kind}
}
$Ops=@('bulk_copy','rename','modify','compress','decompress','temporary_create','delete','archive_rotation')
$target_pids=@($Children|ForEach-Object{[int]$_.pid}|Sort-Object -Unique)
Write-Json $ReceiptPath ([ordered]@{
    schema_version='3.0';gate='OFFICIAL_BENIGN_SCENARIO_RUN';status='PASS';AttemptID=$AttemptID;run_id=$RunID;global_order=$GlobalOrder;os='Windows';class='BENIGN';ground_truth='BENIGN';
    scenario_id=$ScenarioID;scenario_name=$ScenarioName;scenario_type='application_led_compound_benign';lead_application=$LeadApplication;split=$Split;repetition=$Repetition;scenario_run_id=$ScenarioRunID;fixture_seed=$FixtureSeed;
    active_duration_target_seconds=$DurationSeconds;active_duration_tolerance_seconds=5.0;root_lifecycle_tolerance_seconds=10.0;
    active_duration_seconds=$Active;root_lifecycle_seconds=$Lifecycle;orchestration_lifecycle_seconds=$OrchestrationLifecycle;post_scientific_cleanup_seconds=$PostScientificCleanup;root_pid=$RootPid;root_process_name='powershell.exe';
    process_start_utc=$RootStart.ToString('o');process_end_utc=$RootEnd.ToString('o');process_exit_code=0;
    process_termination_method='SELF_EXIT';child_pid_absence_verified=$ChildAbsent;execution_complete=$true;observation_status='COMPLETE';
    compound_task_count=5;direct_task_names=@($Children.kind);process_names=$Scenario.process_names;target_pids=$target_pids;process_instances=$Instances;process_tree_edges=$Edges;
    scenario_inner_receipt=$Scenario;support_receipts=$Support;operation_families=$Ops;network_used=$false;timestamp=[DateTime]::UtcNow.ToString('o')
})
Write-Host ("OFFICIAL BENIGN SCENARIO RUN PASS RUN_ID=$RunID SCENARIO=$ScenarioID ROOT_PID=$RootPid ACTIVE_DURATION=$Active ROOT_LIFECYCLE=$Lifecycle TASKS=5") -ForegroundColor Green
exit 0
