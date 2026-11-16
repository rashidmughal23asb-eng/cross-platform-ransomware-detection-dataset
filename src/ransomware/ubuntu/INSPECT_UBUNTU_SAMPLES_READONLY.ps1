# INSPECT_UBUNTU_SAMPLES_READONLY.ps1
#
# Zero-slot read-only static inspection of the 10 frozen Linux ransomware samples
# (DECISIONS.md D-042). Purpose: derive each sample's invocation contract (usage
# text, required arguments, target semantics) WITHOUT executing it.
#
# What it does
#   1. Fail-closed prestate: both VMs OFF, exact frozen snapshots current, VMX hardening.
#   2. Disable host physical network adapters (same isolation as the run controllers).
#   3. Power on Ubuntu only, transfer a read-only inspection helper + the sample list
#      derived from the frozen 40-row manifest, and run file/readelf/strings as root.
#   4. Copy back a tar.gz of DERIVED TEXT ONLY (no sample bytes), with SHA256SUMS.
#   5. Stop Ubuntu, revert the exact frozen snapshot, verify both VMs OFF and the
#      snapshot re-bound, restore host networking.
#
# Guarantees (recorded in INSPECTION_RESULT.json)
#   sample_executed=false, telemetry_started=false, network_used=false,
#   host_raw_sample_bytes=false, official_run=false,
#   official_campaign_slots_consumed=0.
#
# Output root: 05_UBUNTU\RANSOMWARE\inspection\INSPECT_<timestamp>_<attempt>
#
# Usage (Administrator PowerShell):
#   & '...\01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\INSPECT_UBUNTU_SAMPLES_READONLY.ps1' `
#       -CampaignRoot 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs'
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CampaignRoot,
    [string]$VmrunPath='C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    [string]$WindowsVmxPath='D:\Windows 11\Windows 11.vmx',
    [string]$UbuntuVmxPath='D:\Ubuntu 24.04\Ubuntu.vmx',
    [string]$WindowsSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013',
    [string]$UbuntuSnapshot='P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013',
    [int]$InspectTimeoutSeconds=900,
    [int]$CopyTimeoutSeconds=600
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Script:Stage='INIT';$Script:RunRoot=$null;$Script:NetworkBaseline=$null;$Script:IsolationStarted=$false
$RunID='UBUNTU_READONLY_INSPECTION'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw ('SAFETY_FAILURE:'+ $Message)}}
function SHA([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Object){$d=Split-Path -Parent $Path;if(-not(Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null};[IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 20)+"`r`n"),(New-Object Text.UTF8Encoding($false)))}
function Write-Log([string]$Level,[string]$Message){$line='{0} [{1}] [{2}] {3}' -f [DateTime]::UtcNow.ToString('o'),$Level,$Script:Stage,$Message;Write-Host $line;if($Script:RunRoot){Add-Content -LiteralPath (Join-Path $Script:RunRoot 'INSPECTION_CONTROLLER.log') -Value $line -Encoding UTF8}}
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

$PackageRoot=Join-Path $CampaignRoot '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu'
$ManifestPath=Join-Path $CampaignRoot '01_SHARED\manifests\RANSOMWARE_40_RUN_MANIFEST.csv'
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'UbuntuNativeBridge.ps1')

$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMINISTRATOR_POWERSHELL_REQUIRED'
foreach($p in @($CampaignRoot,$VmrunPath,$WindowsVmxPath,$UbuntuVmxPath,$ManifestPath,(Join-Path $PackageRoot 'INSPECT_UBUNTU_SAMPLES_READONLY.sh'))){Assert-True (Test-Path -LiteralPath $p) ('REQUIRED_PATH_MISSING:'+ $p)}
Assert-VmxHardening 'Windows' $WindowsVmxPath
Assert-VmxHardening 'Ubuntu' $UbuntuVmxPath
Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_MUST_BE_OFF_PRE_INSPECTION'
Assert-True (-not(Get-VmOn $VmrunPath $UbuntuVmxPath)) 'UBUNTU_MUST_BE_OFF_PRE_INSPECTION'
Assert-CurrentSnapshot $WindowsVmxPath $WindowsSnapshot 'Windows'
Assert-CurrentSnapshot $UbuntuVmxPath $UbuntuSnapshot 'Ubuntu'

# ---- frozen sample list from the 40-row manifest (10 unique Linux samples) ----
$manifest=@(Import-Csv -LiteralPath $ManifestPath)
Assert-True ($manifest.Count -eq 40) ('MANIFEST_ROW_COUNT:'+ $manifest.Count)
$linuxRows=@($manifest|Where-Object{[string]$_.platform -ceq 'Ubuntu'})
Assert-True ($linuxRows.Count -eq 20) ('LINUX_MANIFEST_ROWS:'+ $linuxRows.Count)
$groups=@($linuxRows|Group-Object -Property sample_run_id|Sort-Object Name)
Assert-True ($groups.Count -eq 10) ('LINUX_UNIQUE_SAMPLE_COUNT:'+ $groups.Count)
$samples=New-Object 'System.Collections.Generic.List[object]'
foreach($g in $groups){
    $a=$g.Group[0];$b=$g.Group[$g.Count-1]
    foreach($col in @('sample_sha256','sample_bytes','sample_guest_path','mode_octal','family_stratum')){
        Assert-True ([string]$a.$col -ceq [string]$b.$col) ('MANIFEST_GROUP_DRIFT:'+ $g.Name + ':' + $col)
    }
    Assert-True (([string]$a.read_only).ToLowerInvariant() -ceq 'true') ('MANIFEST_SAMPLE_NOT_READ_ONLY:'+ $g.Name)
    Assert-True ([string]$a.sample_sha256 -match '^[0-9a-f]{64}$') ('MANIFEST_SAMPLE_SHA_INVALID:'+ $g.Name)
    Assert-True ([string]$a.sample_bytes -match '^[0-9]+$') ('MANIFEST_SAMPLE_BYTES_INVALID:'+ $g.Name)
    Assert-True ([string]$a.mode_octal -match '^[0-7]{4}$') ('MANIFEST_SAMPLE_MODE_INVALID:'+ $g.Name)
    $samples.Add([pscustomobject][ordered]@{run_id=[string]$a.sample_run_id;family=[string]$a.family_stratum;sha=[string]$a.sample_sha256;bytes=[string]$a.sample_bytes;path=[string]$a.sample_guest_path;mode=[string]$a.mode_octal})
}

$Script:AttemptID=[guid]::NewGuid().ToString('N').Substring(0,16)
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:RunRoot=Join-Path $CampaignRoot ('05_UBUNTU\RANSOMWARE\inspection\INSPECT_'+$stamp+'_'+$Script:AttemptID)
New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot 'evidence') -Force|Out-Null
New-Item -ItemType Directory -Path (Join-Path $Script:RunRoot 'recovery') -Force|Out-Null

$listPath=Join-Path $Script:RunRoot 'evidence\inspection_sample_list.tsv'
$listLines=@($samples|ForEach-Object{ "{0}`t{1}`t{2}`t{3}`t{4}" -f $_.run_id,$_.sha,$_.bytes,$_.path,$_.mode })
[IO.File]::WriteAllText($listPath,(($listLines -join "`n")+"`n"),(New-Object Text.UTF8Encoding($false)))
Write-Host ('Sample list: '+$listPath+' ('+$samples.Count+' samples, sha256 '+ (SHA $listPath) +')') -ForegroundColor Cyan

$guestScript='/tmp/INSPECT_UBUNTU_SAMPLES_'+$Script:AttemptID+'.sh'
$guestList='/tmp/INSPECT_UBUNTU_SAMPLES_'+$Script:AttemptID+'.tsv'
$guestCred='/tmp/INSPECT_UBUNTU_'+$Script:AttemptID+'.sudo'
$guestOut='/tmp/ransomware_inspection/'+$Script:AttemptID
$guestArchive='/tmp/INSPECT_UBUNTU_SAMPLES_'+$Script:AttemptID+'.tar.gz'
$hostArchive=Join-Path $Script:RunRoot 'evidence\inspection_archive.tar.gz'

$runSucceeded=$false;$recoverySucceeded=$false;$mainError='';$recoveryError=''
$archiveSha=$null;$archiveBytes=$null
try{
    Stage 'PRESTATE' 'Verify both VMs OFF, exact frozen snapshots, and VMX hardening'
    Write-Json (Join-Path $Script:RunRoot 'recovery\PRESTATE.json') ([ordered]@{status='PASS';windows_off=$true;ubuntu_off=$true;windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');timestamp=[DateTime]::UtcNow.ToString('o')})

    Stage 'ISOLATION' 'Disable host physical adapters and require zero default routes'
    $Script:NetworkBaseline=Get-P5GNetworkBaseline -AttemptID $Script:AttemptID -RunID $RunID
    Write-Json (Join-Path $Script:RunRoot 'recovery\network_baseline.json') $Script:NetworkBaseline
    Disable-HostNetwork $Script:NetworkBaseline

    Stage 'VM_START' 'Power on Ubuntu by native VIX; Windows remains OFF'
    Start-UbuntuVM $VmrunPath $UbuntuVmxPath
    Assert-True (-not(Get-VmOn $VmrunPath $WindowsVmxPath)) 'WINDOWS_POWERED_ON_UNEXPECTEDLY'

    Stage 'TRANSFER' 'Transfer read-only inspection helper, frozen sample list, and sudo credential'
    Copy-ToUbuntuGuest (Join-Path $PackageRoot 'INSPECT_UBUNTU_SAMPLES_READONLY.sh') $guestScript
    Copy-ToUbuntuGuest $listPath $guestList
    New-UbuntuSudoCredentialFile $guestCred|Out-Null

    Stage 'INSPECT' 'Run file/readelf/strings as root over the 10 frozen samples (no execution)'
    $rc=Invoke-UbuntuGuestProgram '/bin/bash' "$guestScript inspect $guestOut $guestCred $guestList $guestArchive" $InspectTimeoutSeconds
    Assert-True ($rc -eq 0) ('INSPECTION_GUEST_FAILED:'+ $rc)
    try{Copy-FromUbuntuGuest ($guestOut+'/work/inspection.log') (Join-Path $Script:RunRoot 'evidence\guest_inspection.log') 120}catch{Write-Log 'WARN' ('GUEST_LOG_COPY: '+$_.Exception.Message)}

    Stage 'COLLECT' 'Copy back the derived-text archive only and verify its contents'
    Copy-FromUbuntuGuest $guestArchive $hostArchive $CopyTimeoutSeconds
    Assert-True (Test-Path -LiteralPath $hostArchive -PathType Leaf) 'INSPECTION_ARCHIVE_MISSING'
    $archiveSha=SHA $hostArchive
    $archiveBytes=(Get-Item -LiteralPath $hostArchive).Length
    Assert-True ($archiveBytes -gt 0) 'INSPECTION_ARCHIVE_EMPTY'
    $listing=@(& tar -tzf $hostArchive 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) 'INSPECTION_ARCHIVE_LIST_FAILED'
    Assert-True (@($listing|Where-Object{$_ -match '^(\./)?evidence/inspection_receipt\.json$'}).Count -eq 1) 'INSPECTION_AGGREGATE_RECEIPT_MISSING'
    foreach($s in $samples){
        foreach($n in @('inspection_receipt.json','strings.txt','usage_hits.txt','binary_metadata.txt')){
            $want='evidence/'+$s.run_id+'/'+$n
            Assert-True (@($listing|Where-Object{$_ -ceq $want}).Count -eq 1) ('INSPECTION_ARCHIVE_ENTRY_MISSING:'+ $want)
        }
    }
    Assert-True (@($listing|Where-Object{$_ -match '^(\./)?evidence/SHA256SUMS\.txt$'}).Count -eq 1) 'INSPECTION_SHA256SUMS_MISSING'
    $runSucceeded=$true
}
catch{
    $mainError=$_.Exception.Message
    Write-Host ('INSPECTION ERROR: '+$mainError) -ForegroundColor Red
    try{if($guestOut){Copy-FromUbuntuGuest ($guestOut+'/work/inspection.log') (Join-Path $Script:RunRoot 'evidence\guest_inspection.log') 120}}catch{}
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
        if($Script:IsolationStarted){$null=Restore-HostNetwork $Script:NetworkBaseline}
        Write-Json (Join-Path $Script:RunRoot 'recovery\POST_RECOVERY_VERIFICATION.json') ([ordered]@{status='PASS';ubuntu_off=$true;windows_off=$true;ubuntu_snapshot=(Get-CurrentSnapshotName $UbuntuVmxPath 'Ubuntu');windows_snapshot=(Get-CurrentSnapshotName $WindowsVmxPath 'Windows');network_restored=$true;timestamp=[DateTime]::UtcNow.ToString('o')})
        $recoverySucceeded=$true
    }catch{
        $recoveryError=$_.Exception.Message
        Write-Host ('RECOVERY ERROR: '+$recoveryError) -ForegroundColor Red
    }
    try{Close-UbuntuVix}catch{}

    # D-042 evidence integrity: the result JSON is written only after recovery has been verified,
    # so a PASS can never exist for an inspection whose snapshot/network recovery failed.
    Stage 'RESULT' 'Record zero-slot read-only inspection result after verified recovery'
    $finalStatus=$(if($runSucceeded -and $recoverySucceeded){'PASS'}else{'FAIL'})
    Write-Json (Join-Path $Script:RunRoot 'INSPECTION_RESULT.json') ([ordered]@{
        schema_version='1.0'
        gate='RANSOMWARE_INVOCATION_INSPECTION'
        status=$finalStatus
        operation='READ_ONLY_STATIC_INSPECTION'
        decision='DECISIONS.md D-042'
        attempt_id=$Script:AttemptID
        run_id=$RunID
        official_run=$false
        official_campaign_slots_consumed=0
        sample_executed=$false
        telemetry_started=$false
        network_used=$false
        host_raw_sample_bytes=$false
        samples_inspected=$samples.Count
        sample_ids=@($samples|ForEach-Object{$_.run_id})
        manifest_path=$ManifestPath
        manifest_sha256=(SHA $ManifestPath)
        sample_list_path=$listPath
        sample_list_sha256=(SHA $listPath)
        archive_path=$hostArchive
        archive_sha256=$archiveSha
        archive_bytes=$archiveBytes
        snapshot_baseline=$UbuntuSnapshot
        recovery_verified=$recoverySucceeded
        execution_error=$mainError
        recovery_error=$recoveryError
        run_root=$Script:RunRoot
        timestamp=[DateTime]::UtcNow.ToString('o')
    })
    if($finalStatus -eq 'PASS'){
        Write-Host '';Write-Host ('READ-ONLY INSPECTION PASS: '+$Script:RunRoot) -ForegroundColor Green
        Write-Host ('Samples: '+$samples.Count+'  Archive: '+$archiveBytes+' bytes  sha256 '+$archiveSha) -ForegroundColor Green
        Write-Host 'No sample was executed. Campaign slots consumed: 0.' -ForegroundColor Yellow
    }
}

if(-not $runSucceeded -or -not $recoverySucceeded){
    throw ('RANSOMWARE_INVOCATION_INSPECTION_FAIL execution='+$mainError+' recovery='+$recoveryError)
}
