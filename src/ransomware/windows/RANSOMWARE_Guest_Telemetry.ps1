<#
RANSOMWARE_Guest_Telemetry.ps1
Windows ransomware guest telemetry helper (Sysmon + Procmon), D-039.

Prepare  — start frozen Procmon to a raw PML, write prepare receipt.
Finalize — D-156: the capture is ALREADY CLOSED at this point. The bounded post-workload
           telemetry tail and the Procmon termination are performed by the guest executor
           (RANSOMWARE_Guest_Execute_Official.ps1, Mode=Run) inside the guest, immediately
           after the sample's exit. Finalize therefore does NOT stop Procmon: it ASSERTS
           that Procmon is no longer running (the proof that the capture is closed and that
           no lab restore can have happened inside the capture), then verifies the raw PML
           and builds the compact Sysmon process-tree CSV bound to the sample root PID.

Full Procmon PML -> CSV materialization stays DEFERRED_OFFLINE (Q1: raw PML is
the immutable file-telemetry authority; no derived full CSV crosses the host).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Finalize')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID,
    [Parameter(Mandatory=$true)][string]$RunID,
    [Parameter(Mandatory=$true)][int]$GlobalOrder,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$WorkloadReceiptPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Write-JsonExclusive([string]$Path,[object]$Object){
    $Dir=Split-Path -Parent $Path
    if(-not(Test-Path $Dir)){New-Item -ItemType Directory -Path $Dir -Force|Out-Null}
    $Text=(($Object|ConvertTo-Json -Depth 16)+"`r`n")
    if(Test-Path $Path){ if((Get-Content $Path -Raw) -ceq $Text){return}; throw "CONFLICTING_RECEIPT:$Path" }
    $Tmp="$Path.tmp.$([guid]::NewGuid().ToString('N'))"
    [IO.File]::WriteAllText($Tmp,$Text,(New-Object Text.UTF8Encoding($false)))
    [IO.File]::Move($Tmp,$Path)
}
function To-IntOrZero([string]$Text){
    if([string]::IsNullOrWhiteSpace($Text)){return 0}
    try{
        if($Text.StartsWith('0x')){return [Convert]::ToInt32($Text,16)}
        return [int]$Text
    }catch{return 0}
}
function Parse-Utc([string]$Text){
    return [DateTime]::Parse($Text,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

$Pml=Join-Path $OutputRoot 'capture.pml'
$PrepareReceipt=Join-Path $OutputRoot 'prepare_receipt.json'
$FinalizeReceipt=Join-Path $OutputRoot 'capture_receipt.json'
$SysmonCsv=Join-Path $OutputRoot 'sysmon_process_tree.csv'
$ProcmonExe=$null

try {
    $Admin=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Assert-True $Admin 'ADMINISTRATOR_REQUIRED'

    # Frozen Procmon authority (same contract the benign telemetry helper uses).
    $C1='C:\RansomLab\Evidence\Phase15\PostPanel\Gate7B2C1W_R2_TelemetryBaselineSuccessor\gate7_b2_c1w_r2_first_engineering_unit_contract_v1.1.json'
    Assert-True (Test-Path $C1 -PathType Leaf) "FROZEN_PROCMON_AUTHORITY_MISSING:$C1"
    $A=Get-Content $C1 -Raw|ConvertFrom-Json
    $ProcmonExe=[string]$A.source_authorities.procmon_path
    $ExpectedProcmonSHA=[string]$A.source_authorities.procmon_sha256
    Assert-True (Test-Path $ProcmonExe -PathType Leaf) 'FROZEN_PROCMON_BINARY_MISSING'
    Assert-True ((Get-FileHash $ProcmonExe -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $ExpectedProcmonSHA.ToLowerInvariant()) 'FROZEN_PROCMON_SHA256_DRIFT'

    if($Mode -eq 'Prepare'){
        Assert-True (-not (Test-Path $OutputRoot)) 'ATTEMPT_CAPTURE_NAMESPACE_ALREADY_EXISTS'
        $StartedUtc=[DateTime]::UtcNow.ToString('o')
        New-Item -ItemType Directory -Path $OutputRoot -Force|Out-Null
        $null=Start-Process -FilePath $ProcmonExe -ArgumentList @('/AcceptEula','/Quiet','/Minimized','/BackingFile',$Pml) -PassThru -ErrorAction Stop
        $Ready=$false
        for($i=0;$i -lt 40;$i++){
            if(@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count -gt 0){$Ready=$true;break}
            Start-Sleep -Milliseconds 250
        }
        Assert-True $Ready 'PROCMON_DID_NOT_ENTER_RUNNING_STATE'
        $R=[ordered]@{
            schema_version='1.0';gate='RANSOMWARE_GUEST_PREPARE';status='PASS';AttemptID=$AttemptID;RunID=$RunID;GlobalOrder=$GlobalOrder
            receipt_type='TELEMETRY_PREPARE';telemetry_ready=$true;capture_start_utc=$StartedUtc
            procmon_path=$ProcmonExe;procmon_sha256=(Get-FileHash $ProcmonExe -Algorithm SHA256).Hash.ToLowerInvariant()
            capture_pml_path=$Pml;network_used=$false;ransomware_executed=$false;timestamp=[DateTime]::UtcNow.ToString('o')
        }
        Write-JsonExclusive $PrepareReceipt $R
        Write-Host 'RANSOMWARE_GUEST_TELEMETRY_PREPARE=PASS'
        exit 0
    }

    # ---------------- Finalize ----------------
    Assert-True (Test-Path $PrepareReceipt -PathType Leaf) 'GUEST_PREPARE_RECEIPT_MISSING'
    $Prep=Get-Content $PrepareReceipt -Raw|ConvertFrom-Json
    Assert-True ([string]$Prep.status -ceq 'PASS' -and [string]$Prep.AttemptID -ceq $AttemptID -and [string]$Prep.RunID -ceq $RunID) 'PREPARE_IDENTITY_DRIFT'
    # D-156: THE CAPTURE MUST ALREADY BE CLOSED. This is the structural proof that no lab
    # restore, no canary verification, no packing and no transfer happened inside the capture:
    # the executor stopped Procmon in the guest before it returned to the host.
    Assert-True (@(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count -eq 0) 'PROCMON_STILL_RUNNING_AT_FINALIZE_CAPTURE_NOT_CLOSED'
    # D-156: the capture-stop receipt is the authority for the capture boundary.
    $CaptureStopReceipt=Join-Path $OutputRoot 'capture_stop_receipt.json'
    Assert-True (Test-Path $CaptureStopReceipt -PathType Leaf) 'CAPTURE_STOP_RECEIPT_MISSING'
    $StopR=Get-Content $CaptureStopReceipt -Raw|ConvertFrom-Json
    Assert-True ([string]$StopR.status -ceq 'PASS') 'CAPTURE_STOP_RECEIPT_NOT_PASS'
    Assert-True ([bool]$StopR.capture_closed) 'CAPTURE_NOT_CLOSED_IN_THE_STOP_RECEIPT'
    Assert-True ([string]$StopR.AttemptID -ceq $AttemptID -and [string]$StopR.RunID -ceq $RunID) 'CAPTURE_STOP_RECEIPT_IDENTITY_DRIFT'
    $CaptureStopUtc=[string]$StopR.capture_stop_utc

    $FinalizeSw=[Diagnostics.Stopwatch]::StartNew()
    Assert-True (Test-Path $Pml -PathType Leaf) 'CAPTURE_PML_MISSING'
    $PmlInfo=Get-Item $Pml
    Assert-True ($PmlInfo.Length -gt 0) 'CAPTURE_PML_EMPTY'
    # D-156: the PML length recorded at the capture stop must agree with the PML now on disk.
    Assert-True ([int64]$PmlInfo.Length -eq [int64]$StopR.capture_pml_bytes) ('CAPTURE_PML_BYTES_CHANGED_AFTER_THE_CAPTURE_STOP:'+ $PmlInfo.Length +' vs '+ $StopR.capture_pml_bytes)

    # ---- Sysmon compact process tree bound to the sample root ----
    $SysmonLog='Microsoft-Windows-Sysmon/Operational'
    $null=Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop

    Assert-True (-not [string]::IsNullOrWhiteSpace($WorkloadReceiptPath)) 'WORKLOAD_RECEIPT_REQUIRED'
    Assert-True (Test-Path $WorkloadReceiptPath -PathType Leaf) ('WORKLOAD_RECEIPT_MISSING:'+$WorkloadReceiptPath)
    $WR=Get-Content $WorkloadReceiptPath -Raw|ConvertFrom-Json
    Assert-True ([string]$WR.status -ceq 'PASS') 'WORKLOAD_RECEIPT_NOT_PASS'
    $RootPid=[int]$WR.root_pid
    Assert-True ($RootPid -gt 0) 'WORKLOAD_ROOT_PID_INVALID'
    $WorkStart=Parse-Utc ([string]$WR.start_utc)
    $WorkStop=Parse-Utc ([string]$WR.stop_utc)

    $QueryStart=$WorkStart.ToLocalTime().AddSeconds(-5)
    # D-156: the Sysmon window ends with the CAPTURE, not with "now" - the finalisation runs
    # after the capture is closed and must not pull in the post-capture lab activity.
    $QueryEnd=(Parse-Utc $CaptureStopUtc).ToLocalTime().AddSeconds(5)
    if($QueryEnd -lt $QueryStart){$QueryEnd=$QueryStart.AddSeconds(10)}
    $Events=@(Get-WinEvent -FilterHashtable @{LogName=$SysmonLog;Id=@(1,5);StartTime=$QueryStart;EndTime=$QueryEnd} -ErrorAction SilentlyContinue)

    $Starts=New-Object System.Collections.Generic.List[object]
    $Ends=New-Object System.Collections.Generic.List[object]
    foreach($Ev in $Events){
        [xml]$Xml=$Ev.ToXml()
        $D=@{}
        foreach($Node in @($Xml.Event.EventData.Data)){$D[[string]$Node.Name]=[string]$Node.InnerText}
        $Row=[pscustomobject][ordered]@{
            EventId=[int]$Ev.Id
            RecordId=[int64]$Ev.RecordId
            UtcTime=[string]$D['UtcTime']
            ProcessGuid=[string]$D['ProcessGuid']
            ProcessId=(To-IntOrZero ([string]$D['ProcessId']))
            ProcessName=([IO.Path]::GetFileName([string]$D['Image'])).ToLowerInvariant()
            Image=[string]$D['Image']
            CommandLine=[string]$D['CommandLine']
            User=[string]$D['User']
            ParentProcessGuid=[string]$D['ParentProcessGuid']
            ParentProcessId=(To-IntOrZero ([string]$D['ParentProcessId']))
            ParentImage=[string]$D['ParentImage']
        }
        if([int]$Ev.Id -eq 1){$Starts.Add($Row)}else{$Ends.Add($Row)}
    }

    # Root binding: earliest Id-1 event whose PID equals the recorded sample root PID.
    $RootCandidates=@($Starts | Where-Object { $_.ProcessId -eq $RootPid } | Sort-Object UtcTime,RecordId)
    $TreeBinding='PID_GUID_DESCENDANTS'
    $Guids=New-Object 'System.Collections.Generic.HashSet[string]'
    $Pids=New-Object 'System.Collections.Generic.HashSet[int]'
    if($RootCandidates.Count -gt 0){
        $Root=$RootCandidates[0]
        if(-not [string]::IsNullOrWhiteSpace($Root.ProcessGuid)){[void]$Guids.Add($Root.ProcessGuid)}
        [void]$Pids.Add($RootPid)
        $changed=$true
        while($changed){
            $changed=$false
            foreach($S in $Starts){
                if($Pids.Contains([int]$S.ProcessId)){continue}
                $parentGuidOk=(-not [string]::IsNullOrWhiteSpace($S.ParentProcessGuid)) -and $Guids.Contains([string]$S.ParentProcessGuid)
                $parentPidOk=$Pids.Contains([int]$S.ParentProcessId)
                if($parentGuidOk -or $parentPidOk){
                    if(-not [string]::IsNullOrWhiteSpace($S.ProcessGuid)){[void]$Guids.Add($S.ProcessGuid)}
                    [void]$Pids.Add([int]$S.ProcessId)
                    $changed=$true
                }
            }
        }
    }else{
        $TreeBinding='WINDOW_FALLBACK_ROOT_NOT_OBSERVED'
    }

    if($TreeBinding -eq 'WINDOW_FALLBACK_ROOT_NOT_OBSERVED'){
        $Matched=@($Starts)+@($Ends)
    }else{
        $Matched=@($Starts | Where-Object {
            $Pids.Contains([int]$_.ProcessId) -or ($Guids.Count -gt 0 -and $Guids.Contains([string]$_.ProcessGuid))
        })
        $Matched+=@($Ends | Where-Object {
            $Pids.Contains([int]$_.ProcessId) -or ($Guids.Count -gt 0 -and $Guids.Contains([string]$_.ProcessGuid))
        })
    }

    # Always materialize a header + rows file so the packer has a non-empty artefact.
    if(@($Matched).Count -eq 0){
        $Matched=@($Starts)+@($Ends)
        $TreeBinding='WINDOW_FALLBACK_NO_TREE_ROWS'
    }
    @($Matched) | Sort-Object UtcTime,RecordId | Export-Csv -LiteralPath $SysmonCsv -NoTypeInformation -Encoding UTF8
    Assert-True (Test-Path $SysmonCsv -PathType Leaf) 'SYSMON_PROCESS_TREE_CSV_MISSING'
    $SysmonInfo=Get-Item $SysmonCsv
    Assert-True ($SysmonInfo.Length -gt 0) 'SYSMON_PROCESS_TREE_CSV_EMPTY'

    $SysmonStarts=@($Starts | Where-Object { $Pids.Contains([int]$_.ProcessId) }).Count
    $SysmonEnds=@($Ends | Where-Object { $Pids.Contains([int]$_.ProcessId) }).Count
    if($TreeBinding -ne 'PID_GUID_DESCENDANTS'){$SysmonStarts=@($Starts).Count;$SysmonEnds=@($Ends).Count}

    $FinalizeSw.Stop()
    # D-156: the capture window is measured from the telemetry prepare to the capture stop, and
    # it is reported SEPARATELY from the scientific runtime and from the finalisation time.
    $CaptureStartUtc=[string]$Prep.capture_start_utc
    $CaptureWindowSeconds=0.0
    try { $CaptureWindowSeconds=[Math]::Round(((Parse-Utc $CaptureStopUtc)-(Parse-Utc $CaptureStartUtc)).TotalSeconds,3) } catch { $CaptureWindowSeconds=-1 }
    $Final=[ordered]@{
        schema_version='4.0';gate='RANSOMWARE_GUEST_CAPTURE';status='PASS';AttemptID=$AttemptID;RunID=$RunID;GlobalOrder=$GlobalOrder
        receipt_type='TELEMETRY_CAPTURE';telemetry_ready_before_sample=$true;telemetry_helper_finalized=$true
        capture_start_utc=$CaptureStartUtc;capture_stop_utc=$CaptureStopUtc
        capture_closed_before_finalize=$true;capture_closed_by='GUEST_EXECUTOR_RUN_MODE'
        lab_restore_inside_capture=$false
        capture_window_seconds=$CaptureWindowSeconds
        sample_stop_utc=[string]$StopR.sample_stop_utc;post_tail_seconds=[int]$StopR.post_tail_seconds
        post_workload_capture_seconds=[double]$StopR.post_workload_capture_seconds
        capture_stop_overhead_seconds=[double]$StopR.capture_stop_overhead_seconds
        capture_pml_path=$Pml;capture_pml_sha256=(Get-FileHash $Pml -Algorithm SHA256).Hash.ToLowerInvariant();capture_pml_bytes=[int64]$PmlInfo.Length
        capture_csv_materialized=$false;csv_materialization_stage='DEFERRED_TO_OFFLINE_NORMALIZATION'
        sysmon_process_tree_csv_path=$SysmonCsv;sysmon_process_tree_csv_sha256=(Get-FileHash $SysmonCsv -Algorithm SHA256).Hash.ToLowerInvariant()
        sysmon_process_tree_csv_bytes=[int64]$SysmonInfo.Length;sysmon_tree_binding=$TreeBinding
        sysmon_root_pid=$RootPid;sysmon_matched_start_count=$SysmonStarts;sysmon_matched_end_count=$SysmonEnds
        sysmon_tree_distinct_pids=$Pids.Count
        sysmon_query_start=$QueryStart.ToString('o');sysmon_query_end=$QueryEnd.ToString('o')
        termination_mode=[string]$WR.termination_mode;exit_code=[int]$WR.exit_code;exit_code_source=[string]$WR.exit_code_source
        scientific_runtime_seconds=[double]$WR.scientific_runtime_seconds;termination_overhead_seconds=[double]$WR.termination_overhead_seconds
        event_loss_count=0;model_loaded=$false;scoring_performed=$false;containment_performed=$false
        finalize_elapsed_seconds=[Math]::Round($FinalizeSw.Elapsed.TotalSeconds,3)
        timestamp=[DateTime]::UtcNow.ToString('o')
    }
    Write-JsonExclusive $FinalizeReceipt $Final
    Write-Host ('RANSOMWARE_GUEST_TELEMETRY_FINALIZE=PASS PML_BYTES='+$PmlInfo.Length+' SYSMON_ROWS='+@($Matched).Count+' TREE_PIDS='+$Pids.Count+' BINDING='+$TreeBinding+' FINALIZE_SECONDS='+$Final.finalize_elapsed_seconds+' CAPTURE_WINDOW_SECONDS='+$CaptureWindowSeconds+' CAPTURE_CLOSED_BEFORE_FINALIZE=True')
    exit 0
}
catch {
    if($null -ne $ProcmonExe -and @(Get-Process -Name Procmon,Procmon64 -ErrorAction SilentlyContinue).Count -gt 0){
        try{Start-Process -FilePath $ProcmonExe -ArgumentList @('/Terminate','/Quiet') -Wait -ErrorAction SilentlyContinue|Out-Null}catch{}
    }
    Write-Error $_.Exception.Message
    exit 1
}
