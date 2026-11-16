# R1 correction-candidate native transport + GUI visibility hooks.
#
# Replaces the frozen R7 vmrun-based guest transport, which placed the guest
# password in process arguments and could not open an encrypted VM.
#
# Reused, hash-pinned, read-only:
#   HCQNativeBase.ps1  (SHA-256 f327b8e8d6049958ba9ddbbaadd6bdf3176fcb729300b8ef83e5b0c4d7bb353a)
#   -> native VIX encrypted-VM open, guest login, file transfer, program exec
#   -> credential transport resolved from the frozen orchestrator
#      (SHA-256 15a9406d90a7ceacfb483c545923b4799454b5a1c2d8b39e2cfeb1ff19593546)
#
# GUI visibility hooks reuse the previously qualified bounded pattern and were
# re-verified by the standalone VISQ1 harness (lifecycle-only, no workload):
#   Open-VMwareGuiTab          -> vmware.exe "<VMX>"   (BOTH VMs, stable checkpoints)
#   Single-shot Windows restore-> vmware.exe -t "<VMX>" (exactly once, Windows only)
#
# Constraints honoured:
#   * no continuous GUI pin loop; the restore is issued at most once per trigger
#   * no VMX key changes
#   * no credential value printed, logged, or placed on a command line
#   * the GUI restore never powers a VM on or off (runtime state asserted)
#   * the restore is issued only when the Windows 11 tab is actually absent

. (Join-Path $PSScriptRoot 'HCQNativeBase.ps1')

$script:HCQVix = $null
$script:HCQGuiRestoreCount = 0

# ---------------------------------------------------------------------------
# GUI tab observation (host side, read only).
# A tab counts as represented only if a CNoFlickerButton with that exact name
# exists inside the vmware.TabStrip pane. Window title alone is NOT proof.
# ---------------------------------------------------------------------------
# UIAutomation assemblies are not loaded by default in Windows PowerShell 5.1.
try {
    Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
    Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop
} catch {
    throw ('UIAutomation assemblies unavailable; GUI visibility check cannot run: ' + $_.Exception.Message)
}

function Get-HCQVmwareLockOwnerPid {
    # The Workstation instance that owns a VM's lock is the CANONICAL instance:
    # it holds the VMX lock file and is the one whose tab strip matters. Any
    # other vmware.exe process is a stray spawned by a GUI restore attempt and
    # must never be mistaken for the authoritative window.
    $owners = New-Object 'Collections.Generic.List[int]'
    foreach ($v in @($WindowsVmxPath, $UbuntuVmxPath)) {
        $lck = $v + '.lck'
        if (-not (Test-Path -LiteralPath $lck -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $lck -File -ErrorAction SilentlyContinue)) {
            $txt = ''
            try { $txt = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue } catch { }
            if ([string]::IsNullOrWhiteSpace($txt)) { continue }
            $m = [regex]::Match([string]$txt, '(\d{3,6})-\d+\(vmware\.exe\)')
            if ($m.Success) {
                $pid2 = [int]$m.Groups[1].Value
                if (-not $owners.Contains($pid2)) { $owners.Add($pid2) }
            }
        }
    }
    return @($owners.ToArray())
}

function Get-HCQWorkstationTabNames {
    # Prefer the canonical lock-owning instance. When several vmware.exe
    # processes exist, reading the tab strip of a stray instance would report
    # the wrong state, so the canonical instance is selected first and the
    # others are used only as a fallback.
    $procs = @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
    if ($procs.Count -eq 0) { return @() }
    $owners = @(Get-HCQVmwareLockOwnerPid)
    $ordered = @()
    foreach ($o in $owners) { $ordered += @($procs | Where-Object { $_.Id -eq $o }) }
    $ordered += @($procs | Where-Object { $owners -notcontains $_.Id })
    foreach ($proc in $ordered) {
        $root = $null
        try { $root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle) } catch { }
        if ($null -eq $root) { continue }
        $walker = [System.Windows.Automation.TreeWalker]::RawViewWalker
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)
        $found = New-Object 'Collections.Generic.List[string]'
        $guard = 0
        while ($stack.Count -gt 0 -and $guard -lt 3000) {
            $guard++
            $e = $stack.Pop()
            $cls = ''
            try { $cls = [string]$e.Current.ClassName } catch { }
            if ($cls -ceq 'vmware.TabStrip') {
                $ch = $walker.GetFirstChild($e)
                while ($null -ne $ch) {
                    $ccls = ''
                    try { $ccls = [string]$ch.Current.ClassName } catch { }
                    if ($ccls -ceq 'CNoFlickerButton') {
                        $nm = ''
                        try { $nm = [string]$ch.Current.Name } catch { }
                        if (-not [string]::IsNullOrWhiteSpace($nm)) { $found.Add($nm) }
                    }
                    $ch = $walker.GetNextSibling($ch)
                }
            }
            $kid = $walker.GetFirstChild($e)
            while ($null -ne $kid) { $stack.Push($kid); $kid = $walker.GetNextSibling($kid) }
        }
        if ($found.Count -gt 0) { return @($found.ToArray() | Sort-Object -Unique) }
    }
    return @()
}

function Remove-HCQRogueVmwareInstances {
    # A GUI restore issued while Workstation is already running can leave a
    # SECOND vmware.exe process behind. That stray instance cannot take
    # ownership of the VMX already locked by the canonical instance, so it
    # raises modal ownership dialogs. It is terminated here, which also
    # dismisses any dialog it owned. The canonical instance is never touched.
    $owners = @(Get-HCQVmwareLockOwnerPid)
    $killed = @()
    foreach ($proc in @(Get-Process -Name 'vmware' -ErrorAction SilentlyContinue)) {
        if ($owners -contains $proc.Id) { continue }
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        $killed += $proc.Id
    }
    if ($killed.Count -gt 0) {
        Start-Sleep -Milliseconds 800
        Write-Log 'INFO' ("removed rogue vmware.exe instance(s): " + ($killed -join ','))
    }
    return @($killed)
}

function Get-HCQTabRepresented([string]$DisplayName) {
    $names = Get-HCQWorkstationTabNames
    return (@($names | Where-Object { [string]$_ -ceq $DisplayName }).Count -ge 1)
}

# ---------------------------------------------------------------------------
# Stable-checkpoint representation: BOTH exact VMX paths via the qualified
# Open-VMwareGuiTab pattern. Does not power any VM on or off.
# ---------------------------------------------------------------------------
function Invoke-HCQGuiAttachBoth {
    $before = Get-HCQRuntimeCounts
    # OBSERVATION-FIRST. The restore is issued ONLY for a VM entry that is
    # genuinely absent from the canonical Workstation tab strip. Issuing it
    # unconditionally starts a SECOND vmware.exe instance whenever Workstation
    # is already running; that stray instance cannot take ownership of the
    # VMX already locked by the canonical instance and raises modal ownership
    # dialogs, which interfere with the operator.
    $names = @(Get-HCQWorkstationTabNames)
    $issued = @()
    if (-not (@($names | Where-Object { $_ -ceq 'Windows 11' }).Count -ge 1)) {
        Open-VMwareGuiTab $WindowsVmxPath 'Windows'
        $issued += 'Windows'
    }
    $names = @(Get-HCQWorkstationTabNames)
    if (-not (@($names | Where-Object { $_ -ceq 'Ubuntu' }).Count -ge 1)) {
        Open-VMwareGuiTab $UbuntuVmxPath 'Ubuntu'
        $issued += 'Ubuntu'
    }
    if ($issued.Count -gt 0) { Start-Sleep -Seconds 2 }
    # Any competing instance created by the restore is removed, together with
    # the modal dialogs it may own.
    $removed = @(Remove-HCQRogueVmwareInstances)
    $after = Get-HCQRuntimeCounts
    $finalNames = @(Get-HCQWorkstationTabNames)
    $both = (@($finalNames | Where-Object { $_ -ceq 'Windows 11' }).Count -ge 1) -and (@($finalNames | Where-Object { $_ -ceq 'Ubuntu' }).Count -ge 1)
    $noPowerChange = ($before.windows_running -eq $after.windows_running) -and ($before.ubuntu_running -eq $after.ubuntu_running)
    $proof = [ordered]@{
        schema_version = '1.0'; gate = 'HCQ1_GUI_ATTACH_BOTH'
        windows_11_represented = (@($finalNames | Where-Object { $_ -ceq 'Windows 11' }).Count -ge 1)
        ubuntu_represented = (@($finalNames | Where-Object { $_ -ceq 'Ubuntu' }).Count -ge 1)
        tab_strip_names = @($finalNames)
        restore_issued_for = @($issued)
        rogue_instances_removed = @($removed)
        canonical_instance_pids = @(Get-HCQVmwareLockOwnerPid)
        windows_running_before = $before.windows_running
        ubuntu_running_before = $before.ubuntu_running
        windows_running_after = $after.windows_running
        ubuntu_running_after = $after.ubuntu_running
        both_represented = $both
        no_power_state_change = $noPowerChange
        timestamp = [DateTime]::UtcNow.ToString('o')
    }
    if ($Script:RunRoot) {
        # R1 FIX: write a unique file per checkpoint. A fixed name collides with
        # Write-AtomicCreate on a later checkpoint and aborts the run.
        $proofFile = 'HCQ1_GUI_ATTACH_BOTH_' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '.json'
        Write-AtomicCreate (Join-Path $Script:RunRoot ('evidence\' + $proofFile)) $proof | Out-Null
    }
    Assert-True $both 'GUI attach did not represent both exact VM entries'
    Assert-True $noPowerChange 'GUI attach changed VM power state'
    return $proof
}

# ---------------------------------------------------------------------------
# Conditional single-shot Windows tab restoration.
# Issued AT MOST ONCE per trigger, only when the Windows 11 tab is absent,
# then a bounded visibility wait. No retry. No pin loop.
# ---------------------------------------------------------------------------
function Invoke-HCQSingleShotWindowsTabRestore {
    if ($script:HCQGuiRestoreCount -ge 1) {
        return [ordered]@{ issued = $false; reason = 'single-shot budget already consumed'; invocation_count = $script:HCQGuiRestoreCount }
    }
    if (Get-HCQTabRepresented 'Windows 11') {
        return [ordered]@{ issued = $false; reason = 'Windows 11 tab already represented'; invocation_count = $script:HCQGuiRestoreCount }
    }
    $script:HCQGuiRestoreCount++
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $VMwareGuiPath -ArgumentList @('-t', ('"{0}"' -f $WindowsVmxPath)) -PassThru
    $firstVisibleMs = $null
    $samples = New-Object 'Collections.Generic.List[object]'
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $rep = Get-HCQTabRepresented 'Windows 11'
        $samples.Add([pscustomobject][ordered]@{ elapsed_ms = [int64]$sw.ElapsedMilliseconds; windows_11_represented = $rep })
        if ($rep -and $null -eq $firstVisibleMs) { $firstVisibleMs = [int64]$sw.ElapsedMilliseconds; break }
        Start-Sleep -Milliseconds 100
    }
    $sw.Stop()
    # A restore issued while Workstation is already running can leave a
    # competing vmware.exe instance behind, which owns a modal ownership
    # dialog. It is removed here; the canonical instance is left untouched.
    $removed = @(Remove-HCQRogueVmwareInstances)
    $holdStart = [DateTime]::UtcNow
    $stableAbsent = 0
    while (((Get-Date) - $holdStart).TotalSeconds -lt 2) {
        if (-not (Get-HCQTabRepresented 'Windows 11')) { $stableAbsent++ }
        Start-Sleep -Milliseconds 100
    }
    $result = [ordered]@{
        issued = $true
        invocation_count = $script:HCQGuiRestoreCount
        restore_process_id = $proc.Id
        poweron_to_visible_ms = $firstVisibleMs
        visible_within_8000ms = ($null -ne $firstVisibleMs -and $firstVisibleMs -le 8000)
        stable_absent_samples_during_2s_hold = $stableAbsent
        samples = $samples.ToArray()
    }
    if ($Script:RunRoot) {
        Write-AtomicCreate (Join-Path $Script:RunRoot 'evidence\HCQ1_SINGLE_SHOT_TAB_RESTORE.json') $result | Out-Null
    }
    Assert-True ($null -ne $firstVisibleMs) 'single-shot GUI restore did not restore the Windows 11 tab within the bounded wait'
    Assert-True ($stableAbsent -eq 0) 'Windows 11 tab was not stable during the 2 second hold'
    return $result
}

function Get-HCQRuntimeCounts {
    $vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    $out = @(& $vmrun list 2>&1 | ForEach-Object { [string]$_ })
    $running = @($out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z]:\\.*\.vmx$' })
    return [pscustomobject][ordered]@{
        windows_running = (@($running | Where-Object { $_ -ieq $WindowsVmxPath }).Count)
        ubuntu_running = (@($running | Where-Object { $_ -ieq $UbuntuVmxPath }).Count)
    }
}

# ---------------------------------------------------------------------------
# Guest transport — native VIX, no password in process arguments.
# ---------------------------------------------------------------------------
function Invoke-HCQNativeProgram([string]$Arguments, [int]$Timeout = 300) {
    $c = $script:HCQVix
    Assert-True ($null -ne $c -and $c.LoggedIn) 'Native guest login required'
    $program = New-Utf8Pointer 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $argsPointer = New-Utf8Pointer $Arguments
    $job = 0
    try {
        $job = [RansomLabP1GP3P2GuestExecNative]::VixVM_RunProgramInGuest($c.VM, $program, $argsPointer, 0, $c.None, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-VixReady ([type][RansomLabP1GP3P2GuestExecNative]) $job $Timeout 'HCQ GUEST PROGRAM'
        $exitProperty = Get-VixConstant ([IO.File]::ReadAllLines('C:\Program Files (x86)\VMware\VMware VIX\vix.h')) 'VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE'
        [int]$exitValue = 0
        $errorCode = [RansomLabP1GP3P2GuestExecNative]::VixJob_WaitInt32($job, $exitProperty, [ref]$exitValue, $c.None)
        Assert-VixOK $errorCode 'HCQ GUEST EXIT CODE'
        return $exitValue
    } finally {
        if ($job) { [RansomLabP1GP3P2GuestExecNative]::Vix_ReleaseHandle($job) }
        Free-Utf8Pointer $program; Free-Utf8Pointer $argsPointer
    }
}

function Invoke-HCQEncoded([string]$Body, [int]$Timeout = 300) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Body))
    return Invoke-HCQNativeProgram ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded) $Timeout
}

function Start-VM([string]$Vmx, [string]$Label) {
    Assert-True ($Vmx -ceq $WindowsVmxPath) 'R1 native transport starts only the Windows VM'
    Initialize-HCQVix
    $c = $script:HCQVix
    if (-not (Get-VmOn $Vmx)) {
        $job = [RansomLabAQ6C4BNative]::VixVM_PowerOn($c.VM, 0, $c.None, [IntPtr]::Zero, [IntPtr]::Zero)
        Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'HCQ WINDOWS POWER ON'
    }
    Assert-True (Get-VmOn $Vmx) 'Windows failed to enter running inventory'
    # VISQ1-VERIFIED: the native PowerOn transition drops the Windows 11 tab.
    # Issue the single-shot restore here, before the Tools wait.
    $null = Invoke-HCQSingleShotWindowsTabRestore
    $job = [RansomLabAQ6C4BNative]::VixVM_WaitForToolsInGuest($c.VM, 180, [IntPtr]::Zero, [IntPtr]::Zero)
    Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'HCQ TOOLS READY'
    $lease = $null
    try {
        $lease = [RansomLabV02CredentialTransport]::Acquire('RansomLab.Phase15.Windows11.RansomLabController.v1')
        Assert-True ($lease.UserName -ceq 'RansomLabController') 'Guest credential account mismatch'
        Login-Guest $c.VM 'RansomLabController' $lease $c.ResetType $c.AuthType $c.None
        $c.LoggedIn = $true
    } finally { if ($lease) { [RansomLabV02CredentialTransport]::Release($lease) } }
}

function Stop-VM([string]$Vmx, [string]$Label) {
    if (-not (Get-VmOn $Vmx)) { return }
    Assert-True ($Vmx -ceq $WindowsVmxPath) 'R1 native transport never starts or stops Ubuntu'
    Initialize-HCQVix; $c = $script:HCQVix
    $job = [RansomLabAQ6C4BNative]::VixVM_PowerOff($c.VM, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'HCQ WINDOWS POWER OFF'
    $c.LoggedIn = $false
    Assert-True (-not (Get-VmOn $Vmx)) 'Windows not off after native poweroff'
}

function Revert-ExactSnapshot([string]$Vmx, [string]$Snapshot, [string]$Label) {
    # D-163/D-164: the baseline is a CALLER-REGISTERED expectation, not a hard-coded literal.
    # The default keeps the historical R5 Windows baseline so benign-campaign and old
    # qualification callers (which do not register one) behave exactly as before; the
    # ransomware controller registers its own baseline ($script:HCQFrozenWindowsSnapshot)
    # before dot-sourcing this file, so the new V11 baseline can be used without editing
    # every caller and a stale pin can never revert to the wrong state.
    $expectedSnapshot = 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_WINDOWS_20261013'
    $registered = Get-Variable -Name 'HCQFrozenWindowsSnapshot' -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace([string]$registered)) { $expectedSnapshot = [string]$registered }
    Assert-True ($Vmx -ceq $WindowsVmxPath -and $Snapshot -ceq $expectedSnapshot) ('R1 exact snapshot binding required: expected='+$expectedSnapshot+' got='+$Snapshot)
    Stop-VM $Vmx $Label
    # VMware VIX error 15 is VIX_E_FILE_ALREADY_LOCKED. Workstation can retain
    # a short-lived lock immediately after power-off. Retry that one condition
    # only; every other error remains fail-closed.
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    $attempt=0
    while($true){
        $attempt++
        try{
            Initialize-HCQVix; $c = $script:HCQVix
            $ptr = New-Utf8Pointer $Snapshot; [int]$snap = 0
            try {
                Assert-VixOK ([RansomLabAQ6C4BNative]::VixVM_GetNamedSnapshot($c.VM, $ptr, [ref]$snap)) 'HCQ EXACT SNAPSHOT LOOKUP'
                $suppress = Get-VixConstant ([IO.File]::ReadAllLines('C:\Program Files (x86)\VMware\VMware VIX\vix.h')) 'VIX_VMPOWEROP_SUPPRESS_SNAPSHOT_POWERON'
                $job = [RansomLabAQ6C4BNative]::VixVM_RevertToSnapshot($c.VM, $snap, $suppress, $c.None, [IntPtr]::Zero, [IntPtr]::Zero)
                Wait-VixNone $c.ResetType $c.ResetType $job $c.None 360 'HCQ EXACT SNAPSHOT REVERT'
                Write-Host ('HCQ EXACT SNAPSHOT REVERT CONFIRMED: attempts='+$attempt) -ForegroundColor Green
                break
            }finally{
                Free-Utf8Pointer $ptr
                if($snap){[RansomLabAQ6C4BNative]::Vix_ReleaseHandle($snap)}
            }
        }catch{
            $msg=$_.Exception.Message
            try{Close-HCQVix}catch{}
            if($msg -notmatch 'VIX ERROR CODE:\s*15' -or [DateTime]::UtcNow -ge $deadline){throw}
            Write-Host ('HCQ EXACT SNAPSHOT REVERT WAITING FOR TRANSIENT FILE LOCK: attempt='+$attempt) -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
    Assert-True (-not (Get-VmOn $Vmx)) 'Windows started during snapshot recovery'
    Assert-CurrentSnapshot $Vmx $Snapshot $Label
    # NOTE: the GUI tab remedy is deliberately NOT applied here. The revert is
    # part of the safety-critical recovery path; a GUI action must never be
    # able to abort recovery before the host network is restored. The
    # controller applies the remedy after VM safety and network restoration.
}

function Copy-ToGuest([string]$HostPath, [string]$GuestPath) {
    Assert-True ($GuestPath.StartsWith('C:\RansomLab\')) 'R1 guest destination outside approved root'
    $parent = (Split-Path -Parent $GuestPath).Replace("'", "''")
    $exitCode = Invoke-HCQEncoded ("`$ErrorActionPreference='Stop';New-Item -ItemType Directory -Path '$parent' -Force|Out-Null")
    Assert-True ($exitCode -eq 0) 'Guest destination preparation failed'
    # Retry VIX file copy up to 5 times with 10 s settle — VMware Tools guest
    # file service can be momentarily unavailable right after VM boot.
    $attempt = 0
    $copyOk = $false
    while ($attempt -lt 5 -and -not $copyOk) {
        $attempt++
        try {
            Copy-HostToGuest $script:HCQVix.VM $HostPath $GuestPath $script:HCQVix.None 300
            $copyOk = $true
        } catch {
            if ($attempt -lt 5) {
                Write-Host ('Copy-ToGuest attempt {0} failed, retrying in 10 s: {1}' -f $attempt, $_.Exception.Message) -ForegroundColor Yellow
                Start-Sleep -Seconds 10
            } else {
                throw
            }
        }
    }
}

function Copy-FromGuest([string]$GuestPath, [string]$HostPath, [int]$TimeoutSeconds = 300) {
    # Large telemetry captures (tens to hundreds of MB) can exceed the default
    # 300 s VIX copy window, so the bound is a parameter. Any stale or partial
    # target from a previous failed attempt is removed first, so a truncated
    # file can never be mistaken for a complete one.
    if (Test-Path -LiteralPath $HostPath) { Remove-Item -LiteralPath $HostPath -Force -ErrorAction SilentlyContinue }
    Copy-GuestToHost $script:HCQVix.VM $GuestPath $HostPath $script:HCQVix.None $TimeoutSeconds
    Assert-True (Test-Path -LiteralPath $HostPath -PathType Leaf) 'Guest copy missing'
}

function Invoke-GuestPowerShell([string]$Command, [int]$Timeout = 300) {
    $token = [guid]::NewGuid().ToString('N')
    $guestRoot = 'C:\RansomLab\HCQ1_CommandReceipts'
    $out = "$guestRoot\$token.stdout.txt"; $err = "$guestRoot\$token.stderr.txt"
    $escaped = $Command.Replace("'", "''")
    # The wrapper traps its own errors into the stderr file so a failure inside
    # the guest is always retrievable, instead of vanishing into an uncaptured
    # stream. The outer exit code carries the helper's own exit code.
    $body = "`$ErrorActionPreference='Stop';New-Item -ItemType Directory -Path '$guestRoot' -Force|Out-Null;`$rc=1;try{`$p=Start-Process -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '$escaped' -PassThru -RedirectStandardOutput '$out' -RedirectStandardError '$err';`$heldHandle=`$p.Handle;if(-not `$p.WaitForExit($($Timeout*1000))){throw 'Requested guest process timeout'};`$rc=`$p.ExitCode}catch{`$msg=`$_.Exception.Message;Add-Content -LiteralPath '$err' -Value `$msg -Encoding UTF8;`$rc=1};exit `$rc"
    $body = $body.Replace("'`$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe'", "'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'")
    $hostOut = Join-Path $Script:RunRoot ('evidence\' + $token + '.stdout.txt')
    $hostErr = Join-Path $Script:RunRoot ('evidence\' + $token + '.stderr.txt')
    try { $exitCode = Invoke-HCQEncoded $body ($Timeout + 60) } catch {
        try { Copy-FromGuest $out $hostOut } catch { }
        try { Copy-FromGuest $err $hostErr } catch { }
        throw
    }
    Copy-FromGuest $out $hostOut; Copy-FromGuest $err $hostErr
    return [ordered]@{ ExitCode = $exitCode; Text = ([IO.File]::ReadAllText($hostOut) + [IO.File]::ReadAllText($hostErr)) }
}

function Invoke-Guest { throw 'R1 forbids vmrun guest credential arguments' }

function Close-HCQVix {
    if ($null -ne $script:HCQVix) {
        $c = $script:HCQVix
        if ($c.VM) { [RansomLabAQ6C4BNative]::Vix_ReleaseHandle($c.VM) }
        if ($c.HostHandle) { [RansomLabAQ6C4BNative]::VixHost_Disconnect($c.HostHandle) }
        if ($c.Wrapper -ne [IntPtr]::Zero) { [void][RansomLabAQ6C4BNative]::FreeLibrary($c.Wrapper) }
        $script:HCQVix = $null
    }
}
