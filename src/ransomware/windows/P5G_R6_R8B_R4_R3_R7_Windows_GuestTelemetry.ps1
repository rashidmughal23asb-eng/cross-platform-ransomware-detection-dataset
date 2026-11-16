<#+
P5G_R6_R8B_R4_R3_R7_Windows_GuestTelemetry.ps1 (DEFECT 10 FIX)
R3_R7 generalized Windows guest telemetry helper.
NOT T003-specific: no [ValidateSet('W-R-01')], no hard-coded RunID.
Explicit transaction parameters: AttemptID, RunID, GlobalOrder, CaptureRoot, Mode.
Supported lifecycle: Prepare, Finalize.
Prepare produces a structured receipt proving telemetry readiness (includes workload_started=false).
Finalize produces: finalized PML, finalized CSV, capture receipt, event metadata, relevant hashes.
All receipt identities are transaction-bound. TargetPID/ProcessName/ProcessStartUtc bind telemetry to workload.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('Prepare','Finalize')][string]$Mode,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID,
 [Parameter(Mandatory=$true)][string]$RunID,
 [Parameter(Mandatory=$true)][int]$GlobalOrder,
 [Parameter(Mandatory=$true)][string]$OutputRoot,
 [int]$TargetPID,
 [string]$ProcessName,
 [string]$ProcessStartUtc,
 [string]$WorkloadReceiptPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Get-SHA256([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Utf8NoBom([string]$Path,[string]$Text){$E=New-Object Text.UTF8Encoding($false);[IO.File]::WriteAllText($Path,$Text,$E)}
function Write-JsonExclusive([string]$Path,[object]$Object){
    $Text=($Object|ConvertTo-Json -Depth 16)+"`n"
    if(Test-Path -LiteralPath $Path){
        $Old=Get-Content -LiteralPath $Path -Raw
        if($Old-ceq$Text){return}
        throw "CONFLICTING_RECEIPT_EXISTS:$Path"
    }
    $Tmp="$Path.tmp.$([guid]::NewGuid().ToString('N'))"
    Write-Utf8NoBom $Tmp $Text
    [IO.File]::Move($Tmp,$Path)
}
$Pml=Join-Path $OutputRoot 'capture.pml'
$PrepareReceipt=Join-Path $OutputRoot 'prepare_receipt.json'
$FinalizeReceipt=Join-Path $OutputRoot 'capture_receipt.json'
$ProcmonExe=$null
try{
    $Admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Assert-True $Admin 'ADMINISTRATOR_CONTEXT_REQUIRED'
    $C1='C:\RansomLab\Evidence\Phase15\PostPanel\Gate7B2C1W_R2_TelemetryBaselineSuccessor\gate7_b2_c1w_r2_first_engineering_unit_contract_v1.1.json'
    Assert-True (Test-Path -LiteralPath $C1 -PathType Leaf) "FROZEN_PROCMON_AUTHORITY_MISSING:$C1"
    $A=Get-Content -LiteralPath $C1 -Raw|ConvertFrom-Json
    $ProcmonExe=[string]$A.source_authorities.procmon_path
    $ExpectedProcmonSHA=([string]$A.source_authorities.procmon_sha256).ToLowerInvariant()
    Assert-True (Test-Path -LiteralPath $ProcmonExe -PathType Leaf) 'FROZEN_PROCMON_BINARY_MISSING'
    Assert-True ((Get-SHA256 $ProcmonExe)-ceq$ExpectedProcmonSHA) 'FROZEN_PROCMON_SHA256_DRIFT'
    if($Mode-eq'Prepare'){
        Assert-True (-not(Test-Path -LiteralPath $OutputRoot)) 'ATTEMPT_CAPTURE_NAMESPACE_ALREADY_EXISTS'
        Assert-True (@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-eq0) 'PROCMON_ALREADY_RUNNING'
        New-Item -ItemType Directory -Path $OutputRoot|Out-Null
        $StartedUtc=[DateTime]::UtcNow.ToString('o')
        $P=Start-Process -FilePath $ProcmonExe -ArgumentList @('/AcceptEula','/Quiet','/Minimized','/BackingFile',$Pml) -PassThru -ErrorAction Stop
        $Ready=$false
        for($i=0;$i-lt40;$i++){if(@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-gt0){$Ready=$true;break};Start-Sleep -Milliseconds 250}
        Assert-True $Ready 'PROCMON_DID_NOT_ENTER_RUNNING_STATE'
        # DEFECT 10 FIX: Prepare writes workload_started so Finalize can evaluate it safely under StrictMode
        $R=[ordered]@{schema_version='1.0';gate='P5G_R6_R8B_R4_R3_R7_GUEST_PREPARE';status='PASS';AttemptID=$AttemptID;RunID=$RunID;GlobalOrder=$GlobalOrder;receipt_type='TELEMETRY_PREPARE';telemetry_ready=$true;telemetry_helper_prepared=$true;workload_started=$false;workload_bound_pid=$TargetPID;workload_bound_process_name=$ProcessName;workload_bound_process_start_utc=$ProcessStartUtc;capture_start_utc=$StartedUtc;procmon_authority_receipt=$C1;procmon_path=$ProcmonExe;procmon_sha256=(Get-SHA256 $ProcmonExe);capture_pml_path=$Pml;network_used=$false;ransomware_executed=$false;timestamp=[DateTime]::UtcNow.ToString('o')}
        Write-JsonExclusive $PrepareReceipt $R
        Write-Host 'P5G_R6_R8B_R4_R3_R7_GUEST_PREPARE_STATUS=PASS';exit 0
    }
    # Finalize mode (V4 optimized): preserve raw Procmon PML, use compact Sysmon process-tree proof,
    # and defer expensive full PML->CSV materialization to offline normalization.
    Assert-True (Test-Path -LiteralPath $PrepareReceipt -PathType Leaf) 'GUEST_PREPARE_RECEIPT_MISSING'
    $Prep=Get-Content -LiteralPath $PrepareReceipt -Raw|ConvertFrom-Json
    Assert-True ([string]$Prep.status-ceq'PASS' -and [string]$Prep.AttemptID-ceq$AttemptID -and [string]$Prep.RunID-ceq$RunID) 'GUEST_PREPARE_RECEIPT_IDENTITY_DRIFT'
    Assert-True ([bool]$Prep.telemetry_ready -and -not[bool]$Prep.workload_started) 'GUEST_PREPARE_STATE_DRIFT'
    Assert-True (@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-gt0) 'PROCMON_NOT_RUNNING_AT_FINALIZE'

    $FinalizeSw=[Diagnostics.Stopwatch]::StartNew()
    $CaptureStopUtc=[DateTime]::UtcNow.ToString('o')
    $Stop=Start-Process -FilePath $ProcmonExe -ArgumentList @('/Terminate','/Quiet') -Wait -PassThru -ErrorAction Stop
    Assert-True ($Stop.ExitCode-eq0) "PROCMON_TERMINATE_EXIT_CODE:$($Stop.ExitCode)"
    for($i=0;$i-lt40;$i++){if(@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-eq0){break};Start-Sleep -Milliseconds 250}
    Assert-True (@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-eq0) 'PROCMON_DID_NOT_TERMINATE'
    Assert-True (Test-Path -LiteralPath $Pml -PathType Leaf) 'CAPTURE_PML_MISSING'
    $PmlInfo=Get-Item -LiteralPath $Pml
    Assert-True ($PmlInfo.Length-gt0) 'CAPTURE_PML_EMPTY'

    $WorkloadRows=@();$BoundPids=@();$BoundNames=@();$TreeEdges=0;$ActiveDuration=0.0;$ScenarioId=''
    $SysmonCsv=Join-Path $OutputRoot 'sysmon_process_tree.csv'
    $SysmonStartMatches=0;$SysmonEndMatches=0;$SysmonDirectEdges=0;$SysmonNativeStarts=0
    $PidNameMap=@{};$ExpectedKeys=@{};$DirectTaskPids=@{};$NativePids=@{}
    $TopProcessInstanceCount=0;$NestedProcessInstanceCount=0;$NestedNativeProcessCount=0

    if(-not[string]::IsNullOrWhiteSpace($WorkloadReceiptPath)){
        Assert-True (Test-Path -LiteralPath $WorkloadReceiptPath -PathType Leaf) 'WORKLOAD_RECEIPT_NOT_FOUND_AT_FINALIZE'
        $WR=Get-Content -LiteralPath $WorkloadReceiptPath -Raw|ConvertFrom-Json
        Assert-True ([string]$WR.status -ceq 'PASS' -and [string]$WR.AttemptID -ceq $AttemptID) 'WORKLOAD_RECEIPT_IDENTITY_DRIFT'
        $BoundPids=@($WR.target_pids|ForEach-Object{[string][int]$_})
        $BoundNames=@($WR.process_names|ForEach-Object{([string]$_).Trim().ToLowerInvariant()}|Sort-Object -Unique)
        $TreeEdges=@($WR.process_tree_edges).Count
        $ActiveDuration=[double]$WR.active_duration_seconds
        $ScenarioId=[string]$WR.scenario_id

        # V23_NESTED_SCENARIO_PROCESS_BINDING
        # The outer adapter inventory contains the qualification root plus five direct tasks.
        # Native xcopy children are recorded by the successful nested scenario receipt.
        foreach($I in @($WR.process_instances)){
            if($null-ne$I -and [int]$I.pid -gt 0){
                $TopProcessInstanceCount++
                $ExpectedPid=[int]$I.pid
                $name=([string]$I.process_name).Trim().ToLowerInvariant()
                $PidNameMap[[string]$ExpectedPid]=$name
                $ExpectedKeys[([string]$ExpectedPid+'|'+$name)]=$true
                if(([string]$I.role) -like 'native_*'){$NativePids[[string]$ExpectedPid]=$true}
            }
        }
        foreach($E in @($WR.process_tree_edges)){
            if([string]$E.relationship -ceq 'root_to_task'){$DirectTaskPids[[string][int]$E.child_pid]=$true}
        }

        Assert-True ($WR.PSObject.Properties.Name -contains 'scenario_inner_receipt') 'WORKLOAD_NESTED_SCENARIO_RECEIPT_MISSING'
        $Inner=$WR.scenario_inner_receipt
        Assert-True ($null-ne$Inner -and [string]$Inner.status -ceq 'PASS') 'WORKLOAD_NESTED_SCENARIO_RECEIPT_NOT_PASS'
        Assert-True ($DirectTaskPids.ContainsKey([string][int]$Inner.root_pid)) 'WORKLOAD_NESTED_SCENARIO_ROOT_NOT_DIRECT_TASK'
        foreach($I in @($Inner.process_instances)){
            if($null-ne$I -and [int]$I.pid -gt 0){
                $NestedProcessInstanceCount++
                $ExpectedPid=[int]$I.pid
                $name=([string]$I.process_name).Trim().ToLowerInvariant()
                $PidNameMap[[string]$ExpectedPid]=$name
                $ExpectedKeys[([string]$ExpectedPid+'|'+$name)]=$true
                if(([string]$I.role) -like 'native_*'){
                    $NativePids[[string]$ExpectedPid]=$true
                    $NestedNativeProcessCount++
                }
            }
        }
        Assert-True ($NestedNativeProcessCount -ge 1) 'WORKLOAD_NESTED_NATIVE_INVENTORY_MISSING'

        $SysmonLog='Microsoft-Windows-Sysmon/Operational'
        $null=Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
        $WorkStart=[DateTime]::Parse([string]$WR.process_start_utc).ToUniversalTime()
        $WorkEnd=[DateTime]::Parse([string]$WR.process_end_utc).ToUniversalTime()
        $QueryStart=$WorkStart.ToLocalTime().AddSeconds(-3)
        $QueryEnd=$WorkEnd.ToLocalTime().AddSeconds(5)
        $Events=@(Get-WinEvent -FilterHashtable @{LogName=$SysmonLog;Id=@(1,5);StartTime=$QueryStart;EndTime=$QueryEnd} -ErrorAction Stop)
        $Matched=New-Object System.Collections.Generic.List[object]

        foreach($Ev in $Events){
            [xml]$Xml=$Ev.ToXml()
            $D=@{}
            foreach($Node in @($Xml.Event.EventData.Data)){$D[[string]$Node.Name]=[string]$Node.InnerText}
            $PidText=[string]$D['ProcessId']
            if([string]::IsNullOrWhiteSpace($PidText)){continue}
            try{
                if($PidText.StartsWith('0x')){$EventPid=[Convert]::ToInt32($PidText,16)}else{$EventPid=[int]$PidText}
            }catch{continue}
            $Image=[string]$D['Image']
            $Name=([IO.Path]::GetFileName($Image)).ToLowerInvariant()
            $Key=([string]$EventPid+'|'+$Name)
            if(-not$ExpectedKeys.ContainsKey($Key)){continue}
            $ParentPid=0
            if(-not[string]::IsNullOrWhiteSpace([string]$D['ParentProcessId'])){
                try{
                    $ParentText=[string]$D['ParentProcessId']
                    if($ParentText.StartsWith('0x')){$ParentPid=[Convert]::ToInt32($ParentText,16)}else{$ParentPid=[int]$ParentText}
                }catch{$ParentPid=0}
            }
            $Row=[pscustomobject][ordered]@{
                EventId=[int]$Ev.Id
                RecordId=[int64]$Ev.RecordId
                UtcTime=[string]$D['UtcTime']
                ProcessGuid=[string]$D['ProcessGuid']
                ProcessId=$EventPid
                ProcessName=$Name
                Image=$Image
                ParentProcessGuid=[string]$D['ParentProcessGuid']
                ParentProcessId=$ParentPid
                ParentImage=[string]$D['ParentImage']
            }
            $Matched.Add($Row)
            if([int]$Ev.Id -eq 1){
                $SysmonStartMatches++
                if($DirectTaskPids.ContainsKey([string]$EventPid) -and $ParentPid -eq [int]$WR.root_pid){$SysmonDirectEdges++}
                if($NativePids.ContainsKey([string]$EventPid)){$SysmonNativeStarts++}
            }elseif([int]$Ev.Id -eq 5){
                $SysmonEndMatches++
            }
        }

        Assert-True ($Matched.Count-gt0) 'SYSMON_PROCESS_TREE_EVIDENCE_EMPTY'
        $Matched | Sort-Object UtcTime,RecordId | Export-Csv -LiteralPath $SysmonCsv -NoTypeInformation -Encoding UTF8
        Assert-True (Test-Path -LiteralPath $SysmonCsv -PathType Leaf) 'SYSMON_PROCESS_TREE_CSV_MISSING'
        Assert-True ($SysmonStartMatches -ge 6) ('SYSMON_PROCESS_START_MATCHES_INSUFFICIENT:'+ $SysmonStartMatches)
        Assert-True ($SysmonEndMatches -ge 6) ('SYSMON_PROCESS_END_MATCHES_INSUFFICIENT:'+ $SysmonEndMatches)
        Assert-True ($SysmonDirectEdges -ge 5) ('SYSMON_DIRECT_TREE_EDGES_INSUFFICIENT:'+ $SysmonDirectEdges)
        Assert-True ($SysmonNativeStarts -ge 1) 'SYSMON_NATIVE_CHILD_EVIDENCE_MISSING'
    }else{
        throw 'WORKLOAD_RECEIPT_REQUIRED_FOR_V4_PROCESS_TREE_BINDING'
    }

    $FinalizeSw.Stop()
    $Final=[ordered]@{
        schema_version='3.0';gate='P5G_R6_R8B_R4_R3_R7_GUEST_CAPTURE';status='PASS'
        AttemptID=$AttemptID;RunID=$RunID;GlobalOrder=$GlobalOrder;receipt_type='TELEMETRY_CAPTURE'
        telemetry_ready_before_workload=$true;telemetry_helper_finalized=$true
        workload_bound_pid=$TargetPID;workload_bound_process_name=$ProcessName;workload_bound_process_start_utc=$ProcessStartUtc
        workload_receipt_path=$WorkloadReceiptPath;workload_scenario_id=$ScenarioId;workload_active_duration_seconds=$ActiveDuration
        workload_bound_pids=$BoundPids;workload_bound_process_names=$BoundNames;workload_process_tree_edge_count=$TreeEdges
        workload_process_instance_count=$PidNameMap.Count
        workload_top_process_instance_count=$TopProcessInstanceCount
        workload_nested_process_instance_count=$NestedProcessInstanceCount
        workload_nested_native_process_count=$NestedNativeProcessCount
        sysmon_matched_start_count=$SysmonStartMatches;sysmon_matched_end_count=$SysmonEndMatches
        sysmon_direct_task_edge_count=$SysmonDirectEdges;sysmon_native_child_start_count=$SysmonNativeStarts
        sysmon_process_tree_csv_path=$SysmonCsv;sysmon_process_tree_csv_sha256=(Get-SHA256 $SysmonCsv)
        capture_start_utc=[string]$Prep.capture_start_utc;capture_stop_utc=$CaptureStopUtc
        procmon_authority_receipt=$C1;procmon_path=$ProcmonExe;procmon_sha256=(Get-SHA256 $ProcmonExe)
        capture_pml_path=$Pml;capture_pml_sha256=(Get-SHA256 $Pml);capture_pml_bytes=[int64]$PmlInfo.Length
        capture_csv_materialized=$false;csv_materialization_stage='DEFERRED_TO_OFFLINE_NORMALIZATION'
        finalize_elapsed_seconds=[Math]::Round($FinalizeSw.Elapsed.TotalSeconds,3)
        model_loaded=$false;scoring_performed=$false;containment_performed=$false
        timestamp=[DateTime]::UtcNow.ToString('o')
    }
    Write-JsonExclusive $FinalizeReceipt $Final
    Write-Host ('P5G_R6_R8B_R4_R3_R7_GUEST_CAPTURE_STATUS=PASS PML_BYTES='+$PmlInfo.Length+' SYSMON_STARTS='+$SysmonStartMatches+' DIRECT_EDGES='+$SysmonDirectEdges+' FINALIZE_SECONDS='+$Final.finalize_elapsed_seconds)
    exit 0
}catch{
    if($null-ne$ProcmonExe -and @(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count-gt0){try{Start-Process -FilePath $ProcmonExe -ArgumentList @('/Terminate','/Quiet') -Wait -ErrorAction SilentlyContinue|Out-Null}catch{}}
    Write-Error $_.Exception.Message
    exit 1
}
