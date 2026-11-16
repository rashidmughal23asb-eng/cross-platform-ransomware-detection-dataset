<#
    RESET_AFTER_INTERRUPTED_OFFICIAL_RUN.ps1
    ==========================================
    D-130: the reset the owner asked for after interrupting the (wrongly) agent-launched
    official run:

      1. power the Ubuntu guest off cleanly (the interrupted run left it SUSPENDED with an
         8 GiB memory image on D:, which is why the free space collapsed from 10.65 to
         2.65 GiB);
      2. REVERT the guest to the V11 baseline, discarding the interrupted run's disk delta;
      3. leave the host network and the VMware GUI entries as they were.

    It touches no manifest, no sample and no evidence - the interrupted run's package is
    removed separately, with a deletion manifest.
#>
[CmdletBinding()]
param(
    [string]$CampaignRoot = 'C:\Users\Cyber-01\Documents\Default Project\Ransomware_Thesis_Detection_Campaign_100Runs'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PackageRoot = Join-Path $CampaignRoot '01_SHARED\scripts\host\RANSOMWARE_CAMPAIGN_PRODUCTION_V1\ubuntu'
. (Join-Path $PackageRoot 'NetworkBaseline.ps1')
. (Join-Path $PackageRoot 'UbuntuNativeBridge.ps1')

$VmrunPath = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$UbuntuVmxPath = 'D:\Ubuntu 24.04\Ubuntu.vmx'
$WindowsVmxPath = 'D:\Windows 11\Windows 11.vmx'
$UbuntuSnapshot = 'P5G_V11_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261112'

function Free-GiB { [math]::Round((Get-PSDrive -Name D).Free / 1GB, 2) }
function Get-VmOn([string]$Vmrun, [string]$Vmx) {
    $out = & $Vmrun list 2>$null
    return (@($out | Where-Object { $_ -and ([string]$_).Trim().ToLowerInvariant() -eq $Vmx.ToLowerInvariant() }).Count -gt 0)
}
function Get-SnapshotName([string]$Vmx) {
    $a = @(Get-ChildItem -LiteralPath (Split-Path -Parent $Vmx) -Filter '*.vmsd' -File)
    $lines = [IO.File]::ReadAllLines($a[0].FullName)
    $cur = ''; $uidToIndex = @{}; $indexToName = @{}
    foreach ($l in $lines) {
        $m = [regex]::Match($l, '^\s*snapshot\.current\s*=\s*"([^"]*)"'); if ($m.Success) { $cur = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.uid\s*=\s*"([^"]*)"'); if ($m.Success) { $uidToIndex[$m.Groups[2].Value] = $m.Groups[1].Value }
        $m = [regex]::Match($l, '^\s*snapshot(\d+)\.displayName\s*=\s*"([^"]*)"'); if ($m.Success) { $indexToName[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    if ($uidToIndex.ContainsKey($cur) -and $indexToName.ContainsKey($uidToIndex[$cur])) { return $indexToName[$uidToIndex[$cur]] }
    return ''
}

$before = Free-GiB
Write-Host ('RESET: D: free before = {0} GiB' -f $before)
Write-Host ('RESET: the guest is running = {0}' -f (Get-VmOn $VmrunPath $UbuntuVmxPath))
Write-Host ('RESET: the current snapshot = {0}' -f (Get-SnapshotName $UbuntuVmxPath))

Write-Host 'RESET: powering the Ubuntu guest off (this releases the suspended memory image)'
try { Stop-UbuntuVM $VmrunPath $UbuntuVmxPath; Write-Host 'RESET: power off OK' }
catch { Write-Host ('RESET: power off reported: ' + $_.Exception.Message) }
Start-Sleep -Seconds 3
Write-Host ('RESET: D: free after the power off = {0} GiB' -f (Free-GiB))

Write-Host 'RESET: reverting the guest to the V11 baseline (discards the interrupted run delta)'
Revert-UbuntuExactSnapshot $VmrunPath $UbuntuVmxPath $UbuntuSnapshot
Start-Sleep -Seconds 3

$after = Free-GiB
Write-Host ''
Write-Host ('RESET: D: free after the revert = {0} GiB (was {1} GiB before the reset)' -f $after, $before)
Write-Host ('RESET: the Ubuntu guest is running = {0}' -f (Get-VmOn $VmrunPath $UbuntuVmxPath))
Write-Host ('RESET: the Windows guest is running = {0}' -f (Get-VmOn $VmrunPath $WindowsVmxPath))
Write-Host ('RESET: the current Ubuntu snapshot = {0}' -f (Get-SnapshotName $UbuntuVmxPath))
$w = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Wi-Fi' }
Write-Host ('RESET: the Wi-Fi adapter: Status={0} AdminStatus={1}' -f $w.Status, $w.AdminStatus)
