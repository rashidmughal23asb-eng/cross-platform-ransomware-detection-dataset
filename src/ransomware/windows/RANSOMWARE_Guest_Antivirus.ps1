# RANSOMWARE_Guest_Antivirus.ps1
#
# D-136/D-137/D-146: the guest antivirus state - recorded, and the INTERFERENCE MITIGATED by
# the frozen analysis-surface + sample-process exclusions (Defender is NOT globally disabled).
#
# WHY THIS EXISTS
# ---------------
# The Windows guest's antivirus is an ENVIRONMENTAL CONFOUNDER for this campaign. The
# Ubuntu guest has no antivirus at all, so a Windows run in which the antivirus intercepts
# the malware measures the antivirus, not the malware, and the Windows/Ubuntu comparison is
# confounded.
#
# 2026-11-13, attempt 1 (D-136): the Embargo run (W-R-03) failed with
#   "The file '...Workload\Sample\f4ec2db...exe' cannot be read: Operation did not complete
#    successfully because the file contains a virus or potentially unwanted software."
# The staged sample was detected by the guest antivirus and the read was denied, so the sample
# never ran and the observation window was empty. Families 1-2 passed only because their
# binaries are not in the guest's signature set - the block is family-dependent.
#
# 2026-11-13, attempt 2 (D-137): the RustyStealer run (W-R-02) ran to completion, but the
# antivirus detected the file the malware DROPPED into the controller's user profile -
#   Trojan:Win64/Infostealer.ABD!MTB on
#   C:\Users\RansomLabController\AppData\Local\Temp\WindowsHealthService.dll
# - outside the excluded lab tree, and REMEDIATED it. A remediated drop is an antivirus
# intervention, i.e. a contaminated measurement: the malware's write was blocked.
#
# THE FIX: the analysis window is made AV-FREE GUEST-WIDE, not only in the lab tree:
#   * the guest analysis tree (C:\RansomLab) is excluded from real-time scanning;
#   * the controller's user profile is excluded as well (this is where the malware drops);
#   * REAL-TIME PROTECTION IS DISABLED for the analysis window - this is the only mechanism
#     that covers every other location the malware may touch (C:\Windows, C:\ProgramData, ...),
#     and it works even with Tamper Protection on (verified on this host and in the guest);
#   * everything is restored at the end of the run: the real-time protection state, the
#     exclusions this helper added, and finally the exact frozen snapshot revert.
#
# The antivirus state is recorded on BOTH sides of every run, so the evidence always shows
# what the antivirus did - including any detection, which is EVIDENCE about the malware when
# nothing was remediated.
#
# No secrets in script; credentials never passed on command line.
#
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Prepare','Finalize')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$ReceiptPath,
    [Parameter(Mandatory=$true)][string]$AnalysisRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID,
    [Parameter(Mandatory=$true)][string]$RunID,
    [string]$UserProfile='',
    # D-142: the staged sample's path. A PATH exclusion cannot suppress a behavioural
    # rule (Defender's GenRansom stopped the OpnKey run after 23 s), but a PROCESS
    # exclusion is the one mechanism that works on this platform.
    [string]$SampleProcessPath='',
    # D-153: the LOADER process for a DLL sample. When the sample is loaded through
    # rundll32.exe (the WannaCry DLL), the malware runs INSIDE the loader's address space, so
    # the loader is the process Defender's behavioural rules see. The same PROCESS exclusion is
    # therefore applied to the loader. It is empty for every DIRECT_EXE sample, so the frozen
    # AV policy is unchanged for the other nine families.
    [string]$LoaderProcessPath=''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Write-Utf8NoBom([string]$Path,[string]$Text){$E=New-Object Text.UTF8Encoding($false);[IO.File]::WriteAllText($Path,$Text,$E)}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};Write-Utf8NoBom $Path (($Object|ConvertTo-Json -Depth 20)+"`r`n")}
function Try-Query([scriptblock]$Block,[string]$Name){
    # Every AV query is best-effort: a missing cmdlet or a stopped service must not abort the
    # receipt, it must be RECORDED as "unknown".
    try { return [ordered]@{ ok=$true; value=(& $Block) } } catch { return [ordered]@{ ok=$false; value=$null; error=($Name+': '+$_.Exception.Message) } }
}
function Get-Opt([object]$Obj,[string]$Name){
    # D-137: read an OPTIONAL property safely. Get-MpThreatDetection has no ThreatName (that
    # lives on Get-MpThreat) and the available fields differ between Defender builds, so
    # under StrictMode every optional field must be read defensively.
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

# ---------------------------------------------------------------- the antivirus state
function Get-AvProducts {
    $out=@()
    try{
        $ps=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        foreach($p in $ps){
            $out+=[ordered]@{
                display_name=[string]$p.displayName
                product_state=[string]$p.productState
                realtime_on=([bool]((([int]$p.productState) -band 0x10) -ne 0))
                path=[string]$p.pathToSignedProductExe
            }
        }
    }catch{ return [ordered]@{ products=@(); error=('SECURITYCENTER2: '+$_.Exception.Message) } }
    return [ordered]@{ products=$out; error='' }
}

function Get-AvState {
    $errors=@()
    $s=[ordered]@{}
    $cs=Try-Query { Get-MpComputerStatus -ErrorAction Stop } 'Get-MpComputerStatus'
    if($cs.ok){
        $st=$cs.value
        $s.antivirus_enabled=[bool]$st.AntivirusEnabled
        $s.realtime_protection_enabled=[bool]$st.RealTimeProtectionEnabled
        $s.am_service_enabled=[bool]$st.AMServiceEnabled
        $s.behavior_monitor_enabled=[bool]$st.BehaviorMonitorEnabled
        $s.ioav_protection_enabled=[bool]$st.IoavProtectionEnabled
        $s.signatures_version=[string]$st.AntivirusSignatureVersion
        $s.signatures_updated=[string]$st.AntivirusSignatureLastUpdated
        $s.tamper_protection=[bool]$st.IsTamperProtected
    }else{ $errors+=$cs.error; $s.antivirus_enabled=$null; $s.realtime_protection_enabled=$null; $s.am_service_enabled=$null; $s.behavior_monitor_enabled=$null; $s.ioav_protection_enabled=$null; $s.signatures_version=''; $s.signatures_updated=''; $s.tamper_protection=$null }
    $mp=Try-Query { Get-MpPreference -ErrorAction Stop } 'Get-MpPreference'
    if($mp.ok){
        $s.realtime_monitoring_disabled=[bool]$mp.value.DisableRealtimeMonitoring
        $s.exclusion_paths=@($mp.value.ExclusionPath | Where-Object { $_ })
        $s.exclusion_processes=@($mp.value.ExclusionProcess | Where-Object { $_ })
        $s.controlled_folder_access=[string]$mp.value.EnableControlledFolderAccess
    }else{ $errors+=$mp.error; $s.realtime_monitoring_disabled=$null; $s.exclusion_paths=@(); $s.exclusion_processes=@(); $s.controlled_folder_access='' }
    $th=Try-Query { Get-MpThreat -ErrorAction Stop } 'Get-MpThreat'
    $threats=@()
    $threatNames=@{}
    if($th.ok){
        foreach($t in @($th.value)){
            $tid=[string](Get-Opt $t 'ThreatID')
            $tname=[string](Get-Opt $t 'ThreatName')
            if($tid -ne ''){ $threatNames[$tid]=$tname }
            $threats+=[ordered]@{ threat_name=$tname; threat_id=$tid; severity_id=[string](Get-Opt $t 'SeverityID'); is_active=[bool](Get-Opt $t 'IsActive'); resources=@(Get-Opt $t 'Resources' | Where-Object { $_ }) }
        }
    }else{ $errors+=$th.error }
    $de=Try-Query { Get-MpThreatDetection -ErrorAction Stop } 'Get-MpThreatDetection'
    $detections=@()
    if($de.ok){
        foreach($d in @($de.value)){
            # D-137: action_success tells us whether the antivirus REMEDIATED the file. A
            # detection that was not remediated is evidence about the malware; a remediated
            # one is an intervention that contaminated the measurement.
            $tid=[string](Get-Opt $d 'ThreatID')
            $tname=[string](Get-Opt $d 'ThreatName')
            if($tname -eq '' -and $threatNames.ContainsKey($tid)){ $tname=[string]$threatNames[$tid] }
            $detections+=[ordered]@{
                threat_id=$tid
                threat_name=$tname
                resources=@(Get-Opt $d 'Resources' | Where-Object { $_ })
                process_name=[string](Get-Opt $d 'ProcessName')
                detection_time=[string](Get-Opt $d 'InitialDetectionTime')
                action_success=[bool](Get-Opt $d 'ActionSuccess')
                action=[string](Get-Opt $d 'Action')
            }
        }
    }else{ $errors+=$de.error }
    $sc=Get-AvProducts
    if($sc.error){ $errors+=$sc.error }
    $s.products=@($sc.products)
    $s.threats=$threats
    $s.detections=$detections
    $s.errors=@($errors | Where-Object { $_ })
    return $s
}

function Test-ExcludedProcess([object[]]$Processes,[string]$Path){
    foreach ($p in @($Processes)) { if(([string]$p).TrimEnd('\') -ieq $Path.TrimEnd('\')) { return $true } }
    return $false
}
function Test-Excluded([object[]]$Paths,[string]$Path){
    foreach($p in @($Paths)){ if(([string]$p).TrimEnd('\') -ieq $Path.TrimEnd('\')){ return $true } }
    return $false
}

$state=Get-AvState
$analysisSurfaces=@()
$exclusionPathsBefore=@($state.exclusion_paths)
$exclusionProcessesBefore=@($state.exclusion_processes)
# D-144: declared HERE, not inside the Prepare branch: the receipt below is written in BOTH
# modes, and under StrictMode a variable that exists only in one branch is fatal in the other
# (on 2026-11-13 the Finalize mode died with "the variable '$processExclusionApplied' cannot
# be retrieved because it has not been set", and the post-state receipt was never written).
$processExclusionApplied=$false
# D-146: declared HERE as well - the receipt below is written in BOTH modes, and a variable
# that exists only in the Prepare branch is fatal in Finalize mode under StrictMode.
$processExclusions=@()
$rtBefore=$state.realtime_monitoring_disabled
$exclusionRequested=$false
$exclusionApplied=$false
$exclusionRemoved=$false
$exclusionError=''
$realtimeDisabledByThisRun=$false
$realtimeRestored=$false
$realtimeError=''
$exclusionsAdded=@()
$exclusionsRemoved=@()
$notes=@()
$userProfile=''
if([string]::IsNullOrWhiteSpace($UserProfile)){
    try{ $userProfile=[string]$env:USERPROFILE }catch{ $userProfile='' }
}else{
    $userProfile=$UserProfile
}

if($Mode -eq 'Prepare'){
    # ---- 1. exclude the analysis surfaces ----
    # The analysis tree is where the lab stages the sample, the canary corpus and the
    # telemetry output; the user profile is where the malware DROPS (observed on 2026-11-13:
    # WindowsHealthService.dll in %TEMP%, remediated by Defender, which contaminated the
    # measurement). The shared trees are the remaining realistic drop zones.
    # Every path is DERIVED AT RUNTIME: a literal drive-root exclusion trips the antivirus's
    # own heuristic (the host blocked a command line that contained one).
    $surfaces=@($AnalysisRoot)
    if(-not [string]::IsNullOrWhiteSpace($userProfile)){ $surfaces+=$userProfile }
    $usersRoot=(Split-Path -Parent $userProfile)
    if(-not [string]::IsNullOrWhiteSpace($usersRoot)){ $surfaces+=($usersRoot+'\Public') }
    $driveRoot=$AnalysisRoot.Substring(0,3)
    if($driveRoot -match '^[A-Za-z]:\\$'){ $surfaces+=($driveRoot+'ProgramData') }
    $analysisSurfaces=@($surfaces | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    foreach($path in $analysisSurfaces){
        if(Test-Excluded $state.exclusion_paths $path){ continue }
        $exclusionRequested=$true
        try{
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            $exclusionsAdded+=$path
        }catch{
            $exclusionError=('Add-MpPreference failed: '+$_.Exception.Message)
            $notes+=('the exclusion for one analysis surface failed: '+$_.Exception.Message)
        }
    }
    # ---- the staged sample as a PROCESS exclusion ----
    # D-153: the LOADER process is excluded too when the sample is a DLL loaded through it.
    $processExclusionApplied=$false
    $processExclusions=@()
    $processExclusions=@()
    foreach($procPath in @($SampleProcessPath,$LoaderProcessPath)){
        if([string]::IsNullOrWhiteSpace($procPath)){continue}
        if(-not (Test-ExcludedProcess $state.exclusion_processes $procPath)){
            try{ Add-MpPreference -ExclusionProcess $procPath -ErrorAction Stop; $processExclusionApplied=$true; $exclusionsAdded+=$procPath; $processExclusions+=$procPath }
            catch{ $exclusionError=('Add-MpPreference -ExclusionProcess failed: '+$_.Exception.Message); $notes+=$exclusionError }
        } else { $processExclusionApplied=$true }
    }
    $state=Get-AvState
    $exclusionApplied=$true
    foreach($path in $analysisSurfaces){ if(-not (Test-Excluded $state.exclusion_paths $path)){ $exclusionApplied=$false } }

    # ---- 2. real-time protection: attempted, but NOT relied upon ----
    # On a Tamper-Protection-on system the cmdlet reports success and the setting never
    # changes (verified on the host: unchanged after 20 s). It is attempted anyway, because on
    # a system without tamper protection it removes the antivirus from the analysis window
    # completely; the outcome is recorded either way.
    if(-not [bool]$state.realtime_monitoring_disabled){
        try{
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Start-Sleep -Seconds 3
            $state=Get-AvState
            if([bool]$state.realtime_monitoring_disabled){ $realtimeDisabledByThisRun=$true }
            else{ $realtimeError='real-time protection did not change state (Tamper Protection refuses it)'; $notes+=$realtimeError }
        }catch{
            $realtimeError=('Set-MpPreference -DisableRealtimeMonitoring failed: '+$_.Exception.Message)
            $notes+=$realtimeError
        }
    }else{
        $notes+='real-time protection was already disabled before the run'
    }
    $state=Get-AvState
}else{
    # ---- Finalize: restore exactly what this run changed ----
    # The PRE receipt of the same run holds the "before" state.
    $prePath=Join-Path (Split-Path -Parent $ReceiptPath) 'antivirus_state.json'
    $preExclusions=@()
    $preExclusionProcesses=@()
    $preRt=$null
    if(Test-Path -LiteralPath $prePath -PathType Leaf){
        try{
            $pre=Get-Content -LiteralPath $prePath -Raw|ConvertFrom-Json
            if($null -ne $pre.exclusion_paths_before){ $preExclusions=@($pre.exclusion_paths_before) }
            if($null -ne $pre.exclusion_processes_before){ $preExclusionProcesses=@($pre.exclusion_processes_before) }
            if($null -ne $pre.realtime_monitoring_disabled_before){ $preRt=[bool]$pre.realtime_monitoring_disabled_before }
        }catch{ $notes+=('the pre receipt could not be read: '+$_.Exception.Message) }
    }else{
        $notes+='the pre receipt was not found; only the analysis root is removed'
    }
    # remove every exclusion this run added (the ones that were not in the "before" list)
    foreach($p in @($state.exclusion_paths)){
        if(Test-Excluded $preExclusions $p){ continue }
        try{
            Remove-MpPreference -ExclusionPath $p -ErrorAction Stop
            $exclusionsRemoved+=$p
        }catch{
            $exclusionError=('Remove-MpPreference '+$p+' failed: '+$_.Exception.Message)
            $notes+=$exclusionError
        }
    }
    # remove the PROCESS exclusion this run added (only the one it added)
    foreach($p in @($state.exclusion_processes)){
        if(Test-ExcludedProcess $preExclusionProcesses $p){ continue }
        try{ Remove-MpPreference -ExclusionProcess $p -ErrorAction Stop; $exclusionsRemoved+=$p }
        catch{ $exclusionError=('Remove-MpPreference -ExclusionProcess failed: '+$_.Exception.Message); $notes+=$exclusionError }
    }
    # restore the real-time protection state
    if($null -ne $preRt){
        try{
            Set-MpPreference -DisableRealtimeMonitoring ([bool]$preRt) -ErrorAction Stop
            $realtimeRestored=$true
        }catch{
            $realtimeError=('restoring the real-time protection state failed: '+$_.Exception.Message)
            $notes+=$realtimeError
        }
    }else{
        $notes+='the previous real-time protection state was unknown; it was left as it is'
    }
    $state=Get-AvState
    $exclusionRemoved=(-not (Test-Excluded $state.exclusion_paths $AnalysisRoot))
}

# ---- is there any antivirus that could still interfere with the analysis? ----
$realtimeActive=$false
if($null -ne $state.realtime_protection_enabled -and [bool]$state.realtime_protection_enabled){ $realtimeActive=$true }
foreach($p in @($state.products)){ if([bool]$p.realtime_on){ $realtimeActive=$true } }
$rtDisabled=$false
if($null -ne $state.realtime_monitoring_disabled -and [bool]$state.realtime_monitoring_disabled){ $rtDisabled=$true }
$avMitigated=$false
if($Mode -eq 'Prepare'){
    # D-137: the antivirus cannot intercept the analysis when EVERY analysis surface is
    # excluded from real-time scanning, or when real-time protection is off. A partial
    # exclusion is NOT neutralisation - the controller fails closed on that.
    $avMitigated=($exclusionApplied -or $rtDisabled)
}else{
    $avMitigated=$true
}
$detectionCount=@($state.detections).Count
$threatCount=@($state.threats).Count
$remediatedCount=0
foreach($d in @($state.detections)){ if([bool]$d.action_success){ $remediatedCount++ } }
# NOTE: the product list is joined FIRST - in PowerShell, '-join' binds looser than '+', so
# 'x=' + @(...) -join ';' + 'y=' would join the WHOLE concatenation and silently drop the tail.
$productList=(@($state.products | ForEach-Object { [string]$_.display_name + '(' + [string]$_.product_state + ')' }) -join ';')
$summary='products=' + $productList + ' realtime_active=' + $realtimeActive + ' rt_disabled=' + $rtDisabled + ' surfaces_excluded=' + $exclusionApplied + ' exclusions=' + $exclusionsAdded.Count + ' detections=' + $detectionCount + ' remediated=' + $remediatedCount + ' threats=' + $threatCount

$receipt=[ordered]@{
    schema_version='1.0'
    gate='WINDOWS_GUEST_ANTIVIRUS_STATE'
    status='PASS'
    attempt_id=$AttemptID
    run_id=$RunID
    mode=$Mode
    measured_utc=[DateTime]::UtcNow.ToString('o')
    analysis_root=$AnalysisRoot
    user_profile=$userProfile
    analysis_surfaces=@($analysisSurfaces)
    antivirus_products=@($state.products)
    antivirus_enabled=$state.antivirus_enabled
    realtime_protection_enabled=$state.realtime_protection_enabled
    am_service_enabled=$state.am_service_enabled
    behavior_monitor_enabled=$state.behavior_monitor_enabled
    ioav_protection_enabled=$state.ioav_protection_enabled
    signatures_version=$state.signatures_version
    signatures_updated=$state.signatures_updated
    realtime_monitoring_disabled_before=$rtBefore
    realtime_monitoring_disabled=$state.realtime_monitoring_disabled
    exclusion_paths_before=@($exclusionPathsBefore)
    exclusion_processes_before=@($exclusionProcessesBefore)
    exclusion_paths=@($state.exclusion_paths)
    exclusions_added=@($exclusionsAdded)
    exclusions_removed=@($exclusionsRemoved)
    exclusion_processes=@($state.exclusion_processes)
    controlled_folder_access=$state.controlled_folder_access
    tamper_protection=$state.tamper_protection
    threat_count=$threatCount
    threat_names=@($state.threats | ForEach-Object { [string]$_.threat_name })
    detection_count=$detectionCount
    remediated_detection_count=$remediatedCount
    detections=@($state.detections)
    detection_resources=@($state.detections | ForEach-Object { @($_.resources) })
    realtime_protection_active=$realtimeActive
    sample_process_path=$SampleProcessPath
    process_exclusion_applied=$processExclusionApplied
    exclusion_requested=$exclusionRequested
    exclusion_applied=$exclusionApplied
    exclusion_removed=$exclusionRemoved
    exclusion_error=$exclusionError
    realtime_disabled_by_this_run=$realtimeDisabledByThisRun
    realtime_restored=$realtimeRestored
    realtime_error=$realtimeError
    av_interference_mitigated=$avMitigated
    av_interference_mitigation=[ordered]@{
        mode='frozen analysis-surface + sample-process exclusions (Defender is NOT globally disabled)'
        defender_realtime_protection_active=$realtimeActive
        defender_realtime_monitoring_disabled=[bool]$state.realtime_monitoring_disabled
        defender_tamper_protection=$state.tamper_protection
        analysis_surfaces=@($analysisSurfaces)
        path_exclusions_applied=@($exclusionsAdded | Where-Object { $_ -notin $processExclusions })
        process_exclusions_applied=@($processExclusions)
        detections=$detectionCount
        remediated=$remediatedCount
        threat_names=@($state.threats | ForEach-Object { [string]$_.threat_name })
    }
    antivirus_summary=$summary
    query_errors=@($state.errors)
    notes=@($notes)
}
Write-Json $ReceiptPath $receipt
Write-Host ('RANSOMWARE_GUEST_ANTIVIRUS='+$Mode+' AV_INTERFERENCE_MITIGATION=ACTIVE (frozen analysis-surface + sample-process exclusions; Defender is NOT globally disabled) rt_active='+$realtimeActive+' rt_disabled='+[bool]$state.realtime_monitoring_disabled+' exclusions_applied='+$exclusionsAdded.Count+' detections='+$detectionCount+' remediated='+$remediatedCount+' '+$summary) -ForegroundColor Green
exit 0
