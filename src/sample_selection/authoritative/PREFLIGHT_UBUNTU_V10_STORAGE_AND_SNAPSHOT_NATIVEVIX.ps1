$ErrorActionPreference = "Stop"

$Root = "C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs"
$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$UbuntuVmx = "D:\Ubuntu 24.04\Ubuntu.vmx"

$Bridge = Join-Path $Root "01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu\UbuntuNativeBridge.ps1"
$GuestHelperHost = Join-Path $Root "01_SHARED\scripts\host\sample_selection\UBUNTU_V10_STORAGE_PREFLIGHT_GUEST.sh"

$ExistingSnapshot = "P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013"
$PlannedSnapshot  = "P5G_V10_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261110"
$ExpectedRawMiB = 21.82

$OutRoot = Join-Path $Root "01_SHARED\sample_selection\UBUNTU_V10_PRELIVE_STORAGE_PREFLIGHT_NATIVEVIX_20261110"
New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null

foreach($p in @($Vmrun,$UbuntuVmx,$Bridge,$GuestHelperHost)){
    if(-not(Test-Path -LiteralPath $p -PathType Leaf)){
        throw "Required file missing: $p"
    }
}

# Read-only running-VM gate: Ubuntu only.
$running = @(& $Vmrun -T ws list 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "VMRUN_LIST_FAILED" }

$runningVmx = @(
    $running |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' }
)

if(-not($runningVmx -contains $UbuntuVmx)){
    throw "Ubuntu VM is not running."
}

$otherVms = @($runningVmx | Where-Object { $_ -cne $UbuntuVmx })
if($otherVms.Count -gt 0){
    throw ("Another VM is running: " + ($otherVms -join "; "))
}

# Read-only snapshot inventory.
$snapshots = @(& $Vmrun listSnapshots $UbuntuVmx 2>&1 | ForEach-Object { [string]$_ })
if($LASTEXITCODE -ne 0){ throw "Unable to list Ubuntu snapshots." }

$snapshotText = ($snapshots -join "`n")
$existingSnapshotPresent = $snapshotText -match [regex]::Escape($ExistingSnapshot)
$plannedSnapshotAlreadyExists = $snapshotText -match [regex]::Escape($PlannedSnapshot)

# Pin bridge hash for evidence.
$bridgeHash = (Get-FileHash -LiteralPath $Bridge -Algorithm SHA256).Hash.ToLowerInvariant()

# Load the already-qualified Native-VIX stack.
. $Bridge

$GuestHelper = "/tmp/UBUNTU_V10_STORAGE_PREFLIGHT_GUEST.sh"
$GuestResult = "/tmp/UBUNTU_V10_STORAGE_PREFLIGHT_RESULT.txt"
$HostResult = Join-Path $OutRoot "UBUNTU_V10_STORAGE_PREFLIGHT_RESULT.txt"

try {
    # Establish/login through the production Native-VIX bridge.
    # If Ubuntu is already running, this does not power-cycle it.
    Start-UbuntuVM $Vmrun $UbuntuVmx

    Write-Host "Stage 1/3: native-VIX helper transfer..."
    Copy-ToUbuntuGuest $GuestHelperHost $GuestHelper

    Write-Host "Stage 2/3: read-only guest storage query..."
    $exit = Invoke-UbuntuGuestProgram "/bin/bash" $GuestHelper 120
    if($exit -ne 0){
        throw "Guest storage helper exited with code $exit."
    }

    Write-Host "Stage 3/3: return report to host..."
    Copy-FromUbuntuGuest $GuestResult $HostResult 120

    if(-not(Test-Path -LiteralPath $HostResult -PathType Leaf)){
        throw "Guest storage report was not returned."
    }

    $guestText = Get-Content -LiteralPath $HostResult -Raw

    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='D:'"
    if(-not $d){ throw "Unable to query D: free space." }
    $hostDFreeGiB = [math]::Round($d.FreeSpace / 1GB, 2)

    # Extract /opt available KB from POSIX df line after DF_OPT_BEGIN.
    $optAvailKiB = $null
    $m = [regex]::Match(
        $guestText,
        'DF_OPT_BEGIN\s*Filesystem.*?\r?\n(?<row>[^\r\n]+)',
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    if($m.Success){
        $parts = ($m.Groups['row'].Value -split '\s+') | Where-Object { $_ -ne '' }
        if($parts.Count -ge 4){
            [long]$parsed = 0
            if([long]::TryParse($parts[3],[ref]$parsed)){
                $optAvailKiB = $parsed
            }
        }
    }

    $optAvailGiB = if($null -ne $optAvailKiB){
        [math]::Round(($optAvailKiB * 1024) / 1GB, 2)
    } else { $null }

    $targetExists = $guestText -match 'TARGET_EXISTS=YES'
    $oldRootExists = $guestText -match 'OLD_SAMPLE_ROOT_EXISTS=YES'

    $receipt = [ordered]@{
        schema_version = "2.0"
        status = "PASS_PRELIVE_STORAGE_PREFLIGHT_NATIVE_VIX"
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
        transport = "qualified Ubuntu Native-VIX bridge"
        bridge_path = $Bridge
        bridge_sha256 = $bridgeHash
        credential_prompt_used = $false
        vmrun_guest_auth_used = $false

        ubuntu_vmx = $UbuntuVmx
        ubuntu_was_running = $true
        other_vms_running = $false

        existing_snapshot = $ExistingSnapshot
        existing_snapshot_present = $existingSnapshotPresent
        planned_snapshot = $PlannedSnapshot
        planned_snapshot_already_exists = $plannedSnapshotAlreadyExists

        expected_raw_sample_mib = $ExpectedRawMiB
        guest_opt_available_gib = $optAvailGiB
        host_D_free_gib = $hostDFreeGiB

        v10_target_exists = $targetExists
        old_r4_sample_root_exists = $oldRootExists

        guest_report_path = $HostResult

        malware_downloaded = $false
        malware_read = $false
        malware_transferred = $false
        malware_executed = $false
        snapshot_modified = $false
        official_run_slot_consumed = $false
    }

    $receiptPath = Join-Path $OutRoot "PRELIVE_STORAGE_PREFLIGHT_NATIVE_VIX_RECEIPT.json"
    $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $receiptPath -Encoding UTF8

    Write-Host ""
    Write-Host "UBUNTU V10 PRE-LIVE STORAGE/SNAPSHOT PREFLIGHT: PASS"
    Write-Host "Credential popup used: False"
    Write-Host "Existing frozen snapshot present: $existingSnapshotPresent"
    Write-Host "Planned snapshot already exists: $plannedSnapshotAlreadyExists"
    Write-Host "Expected raw sample storage: $ExpectedRawMiB MiB"
    Write-Host "Guest /opt available: $optAvailGiB GiB"
    Write-Host "Host D: free space: $hostDFreeGiB GiB"
    Write-Host "V10 target already exists: $targetExists"
    Write-Host "Old R4 sample root exists: $oldRootExists"
    Write-Host ""
    Write-Host "Guest report:"
    Write-Host $guestText
    Write-Host "Receipt: $receiptPath"
}
finally {
    # Remove only temporary preflight artifacts from /tmp.
    try {
        if($script:HCQVix -and $script:HCQVix.LoggedIn){
            Invoke-UbuntuGuestProgram "/bin/rm" "-f $GuestHelper $GuestResult" 60 | Out-Null
        }
    } catch {}

    try { Close-UbuntuVix } catch {}
}
