<#
.SYNOPSIS
  Shared Workstation lock guard for the Ubuntu V10 workflow.

.DESCRIPTION
  Settles the two problems that keep breaking the workflow:

  1. "The Ubuntu tab disappears from VMware Workstation."
     Native-VIX power-on runs the VM in a headless Workstation process. A GUI that
     is already showing that VM drops its tab because it no longer owns it.

  2. "VIX ERROR CODE: 15" on power-on.
     A Workstation GUI (or a killed/left-behind process) leaves <vmx>.lck behind and
     VIX refuses to open a VM whose lock directory exists.

  This guard asserts that no VM is running, closes the Workstation GUI, waits for a
  natural release, and - only when nothing is running and no Workstation process is
  alive - removes the orphaned <vmx>.lck directory.

  It only ever touches the lock path of the VM passed in. Other VMs' locks are left
  alone.

.PARAMETER VmrunPath
  Path to vmrun.exe.

.PARAMETER Vmx
  Full path of the .vmx whose lock must be clear.

.PARAMETER WaitSeconds
  How long to wait for a natural lock release before treating it as stale (default 30).

.OUTPUTS
  [pscustomobject] with gui_processes_closed, stale_lock_removed, lock_path.
#>

Set-StrictMode -Version Latest

function Clear-UbuntuWorkstationLock {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$Vmx,
        [int]$WaitSeconds = 30
    )

    function Get-RunningVmxLocal {
        $out = @(& $VmrunPath -T ws list 2>&1 | ForEach-Object { [string]$_ })
        if ($LASTEXITCODE -ne 0) { throw 'VMRUN_LIST_FAILED' }
        return @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' })
    }

    $lockPath = $Vmx + '.lck'

    $running = @(Get-RunningVmxLocal)
    if ($running.Count -gt 0) { throw ("OTHER_VM_RUNNING: " + ($running -join '; ')) }

    # --- 1. Close the GUI so it cannot drop its tab or hold the lock ---
    $gui = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)
    if ($gui.Count -eq 0) {
        Write-Host "workstation GUI : not running"
    }
    else {
        Write-Host ("workstation GUI : closing {0} process(es) (it would drop the tab and hold the vmx lock)" -f $gui.Count) -ForegroundColor Yellow
        $gui | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # --- 2. Give Workstation a chance to release the lock naturally ---
    $alive = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Seconds 1
        $alive = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)
    } while ((($alive.Count -gt 0) -or (Test-Path -LiteralPath $lockPath)) -and ((Get-Date) -lt $deadline))

    if ($alive.Count -gt 0) { throw 'WORKSTATION_GUI_DID_NOT_CLOSE' }

    # --- 3. A headless vmware-vmx left over from an earlier run can hold it too ---
    $staleRemoved = $false
    if (Test-Path -LiteralPath $lockPath) {
        $vmxProc = @(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue)
        if ($vmxProc.Count -gt 0) {
            $running2 = @(Get-RunningVmxLocal)
            if ($running2.Count -gt 0) { throw ("OTHER_VM_RUNNING: " + ($running2 -join '; ')) }
            Write-Host ("stale vmware-vmx : closing {0} process(es)" -f $vmxProc.Count) -ForegroundColor Yellow
            $vmxProc | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }

    # --- 4. Nothing is running: an existing lock directory is orphaned, clear it ---
    if (Test-Path -LiteralPath $lockPath) {
        $running3 = @(Get-RunningVmxLocal)
        if ($running3.Count -gt 0) { throw ("OTHER_VM_RUNNING: " + ($running3 -join '; ')) }

        $holder = @(Get-Process -Name 'vmware', 'vmware-vmx' -ErrorAction SilentlyContinue)
        if ($holder.Count -gt 0) {
            throw ("VM_LOCK_HELD_BY_RUNNING_PROCESS: " + (($holder | ForEach-Object { $_.ProcessName + ':' + $_.Id }) -join '; '))
        }

        Write-Host ("stale lock      : removing " + $lockPath + " (0 VMs running, no Workstation process alive)") -ForegroundColor Yellow
        try { Remove-Item -LiteralPath $lockPath -Recurse -Force -ErrorAction Stop }
        catch { throw ("STALE_LOCK_REMOVE_FAILED: " + $lockPath + " :: " + $_.Exception.Message) }
        Start-Sleep -Seconds 1
        $staleRemoved = $true
    }

    if (Test-Path -LiteralPath $lockPath) { throw ("VM_LOCK_STILL_PRESENT: " + $lockPath) }

    Write-Host "workstation lock: clear"
    return [pscustomobject]@{
        gui_processes_closed = $gui.Count
        stale_lock_removed   = $staleRemoved
        lock_path            = $lockPath
    }
}
