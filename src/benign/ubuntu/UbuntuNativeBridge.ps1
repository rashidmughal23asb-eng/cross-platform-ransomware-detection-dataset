# Ubuntu native-VIX bridge derived from the qualified T-003/20261022 native VIX pattern.
. (Join-Path $PSScriptRoot 'UbuntuNativeBase.ps1')
$script:HCQVix=$null
$script:UbuntuGuestTarget='RansomLab.Phase15.Ubuntu24.04.ubuntu.v1'
$script:UbuntuGuestUser='ubuntu'

function Get-RunningVmxSet {
    param([string]$VmrunPath)
    $h=@{}
    $out=@(& $VmrunPath -T ws list 2>&1 | ForEach-Object {[string]$_})
    if($LASTEXITCODE -ne 0){throw 'VMRUN_LIST_FAILED'}
    foreach($l in $out){$t=$l.Trim();if($t -match '^[A-Za-z]:\\.*\.vmx$'){$h[$t.ToLowerInvariant()]=$true}}
    return $h
}
function Get-VmOn { param([string]$VmrunPath,[string]$Vmx) return (Get-RunningVmxSet $VmrunPath).ContainsKey($Vmx.ToLowerInvariant()) }

function Start-UbuntuVM {
    param([string]$VmrunPath,[string]$UbuntuVmxPath)
    Initialize-HCQVix
    $c=$script:HCQVix
    if(-not (Get-VmOn $VmrunPath $UbuntuVmxPath)){
        $job=[RansomLabAQ6C4BNative]::VixVM_PowerOn($c.VM,0,$c.None,[IntPtr]::Zero,[IntPtr]::Zero)
        Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'UBUNTU POWER ON'
    }
    if(-not (Get-VmOn $VmrunPath $UbuntuVmxPath)){throw 'UBUNTU_FAILED_TO_START'}
    # VISQ1-VERIFIED (Windows): the native PowerOn transition drops the VM tab.
    # Mirror the Windows pattern: issue the single-shot GUI tab restore here, before
    # the Tools wait, so the running Ubuntu console is visible in VMware Workstation.
    try{ Open-VMwareGuiTab $UbuntuVmxPath 'Ubuntu' }catch{}
    Start-Sleep -Seconds 2
    $job=[RansomLabAQ6C4BNative]::VixVM_WaitForToolsInGuest($c.VM,180,[IntPtr]::Zero,[IntPtr]::Zero)
    Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'UBUNTU TOOLS READY'
    $lease=$null
    try{
        $lease=[RansomLabV02CredentialTransport]::Acquire($script:UbuntuGuestTarget)
        if([string]$lease.UserName -cne $script:UbuntuGuestUser){throw 'UBUNTU_GUEST_CREDENTIAL_USER_MISMATCH'}
        Login-Guest $c.VM $script:UbuntuGuestUser $lease $c.ResetType $c.AuthType $c.None
        $c.LoggedIn=$true
    }finally{if($lease){[RansomLabV02CredentialTransport]::Release($lease)}}
}
function Stop-UbuntuVM {
    param([string]$VmrunPath,[string]$UbuntuVmxPath)
    if(-not (Get-VmOn $VmrunPath $UbuntuVmxPath)){return}
    Initialize-HCQVix;$c=$script:HCQVix
    $job=[RansomLabAQ6C4BNative]::VixVM_PowerOff($c.VM,0,[IntPtr]::Zero,[IntPtr]::Zero)
    Wait-VixNone $c.ResetType $c.ResetType $job $c.None 240 'UBUNTU POWER OFF'
    $c.LoggedIn=$false
    if(Get-VmOn $VmrunPath $UbuntuVmxPath){throw 'UBUNTU_NOT_OFF_AFTER_POWER_OFF'}
}
function Revert-UbuntuExactSnapshot {
    param([string]$VmrunPath,[string]$UbuntuVmxPath,[string]$Snapshot)
    if($Snapshot -cne 'P5G_R4_R5_POST_MATERIALIZATION_PREEXECUTION_UBUNTU_20261013'){throw 'UBUNTU_FROZEN_SNAPSHOT_BINDING_REQUIRED'}

    Stop-UbuntuVM $VmrunPath $UbuntuVmxPath
    try{Close-UbuntuVix}catch{}
    if(Get-VmOn $VmrunPath $UbuntuVmxPath){throw 'UBUNTU_NOT_OFF_BEFORE_SNAPSHOT_REVERT'}

    # VMware VIX error 15 is VIX_E_FILE_ALREADY_LOCKED. Workstation can retain
    # a short-lived lock immediately after power-off. Retry that one condition
    # only; every other error remains fail-closed.
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    $attempt=0
    while($true){
        $attempt++
        try{
            Initialize-HCQVix;$c=$script:HCQVix
            $ptr=New-Utf8Pointer $Snapshot;[int]$snap=0
            try{
                Assert-VixOK ([RansomLabAQ6C4BNative]::VixVM_GetNamedSnapshot($c.VM,$ptr,[ref]$snap)) 'UBUNTU EXACT SNAPSHOT LOOKUP'
                $suppress=Get-VixConstant ([IO.File]::ReadAllLines('C:\Program Files (x86)\VMware\VMware VIX\vix.h')) 'VIX_VMPOWEROP_SUPPRESS_SNAPSHOT_POWERON'
                $job=[RansomLabAQ6C4BNative]::VixVM_RevertToSnapshot($c.VM,$snap,$suppress,$c.None,[IntPtr]::Zero,[IntPtr]::Zero)
                Wait-VixNone $c.ResetType $c.ResetType $job $c.None 360 'UBUNTU EXACT SNAPSHOT REVERT'
                Write-Host ('UBUNTU SNAPSHOT REVERT CONFIRMED: attempts='+$attempt) -ForegroundColor Green
                break
            }finally{
                Free-Utf8Pointer $ptr
                if($snap){[RansomLabAQ6C4BNative]::Vix_ReleaseHandle($snap)}
            }
        }catch{
            $msg=$_.Exception.Message
            try{Close-UbuntuVix}catch{}
            if($msg -notmatch 'VIX ERROR CODE:\s*15' -or [DateTime]::UtcNow -ge $deadline){throw}
            Write-Host ('UBUNTU SNAPSHOT REVERT WAITING FOR TRANSIENT FILE LOCK: attempt='+$attempt) -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
    if(Get-VmOn $VmrunPath $UbuntuVmxPath){throw 'UBUNTU_STARTED_DURING_SNAPSHOT_REVERT'}
}
function Invoke-UbuntuGuestProgram {
    param([string]$Program,[string]$Arguments,[int]$Timeout=300)
    $c=$script:HCQVix
    if($null -eq $c -or -not $c.LoggedIn){throw 'UBUNTU_GUEST_LOGIN_REQUIRED'}
    $p=New-Utf8Pointer $Program;$a=New-Utf8Pointer $Arguments;$job=0
    try{
        $job=[RansomLabP1GP3P2GuestExecNative]::VixVM_RunProgramInGuest($c.VM,$p,$a,0,$c.None,[IntPtr]::Zero,[IntPtr]::Zero)
        Wait-VixReady ([type][RansomLabP1GP3P2GuestExecNative]) $job $Timeout 'UBUNTU GUEST PROGRAM'
        $prop=Get-VixConstant ([IO.File]::ReadAllLines('C:\Program Files (x86)\VMware\VMware VIX\vix.h')) 'VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE'
        [int]$exit=0
        $e=[RansomLabP1GP3P2GuestExecNative]::VixJob_WaitInt32($job,$prop,[ref]$exit,$c.None)
        Assert-VixOK $e 'UBUNTU GUEST EXIT CODE'
        return $exit
    }finally{if($job){[RansomLabP1GP3P2GuestExecNative]::Vix_ReleaseHandle($job)};Free-Utf8Pointer $p;Free-Utf8Pointer $a}
}
function Copy-ToUbuntuGuest {
    param([string]$HostPath,[string]$GuestPath)
    # Historical qualified Ubuntu pattern: copy helpers directly to /tmp.
    # The guest workload creates its own nested work/evidence directories.
    if(-not $GuestPath.StartsWith('/tmp/')){throw 'UBUNTU_GUEST_TRANSFER_PATH_OUTSIDE_TMP'}
    Copy-HostToGuest $script:HCQVix.VM $HostPath $GuestPath $script:HCQVix.None 300
}
function Copy-FromUbuntuGuest {
    param([string]$GuestPath,[string]$HostPath,[int]$TimeoutSeconds=300)
    if(Test-Path -LiteralPath $HostPath){Remove-Item -LiteralPath $HostPath -Force -ErrorAction SilentlyContinue}
    Copy-GuestToHost $script:HCQVix.VM $GuestPath $HostPath $script:HCQVix.None $TimeoutSeconds
    if(-not(Test-Path -LiteralPath $HostPath -PathType Leaf)){throw 'UBUNTU_GUEST_COPY_MISSING'}
}
function New-UbuntuSudoCredentialFile {
    param([string]$GuestPath)
    $lease=$null;$tmp=$null
    try{
        $lease=[RansomLabV02CredentialTransport]::Acquire($script:UbuntuGuestTarget)
        if([string]$lease.UserName -cne $script:UbuntuGuestUser){throw 'UBUNTU_GUEST_CREDENTIAL_USER_MISMATCH'}
        $tmp=[IO.Path]::GetTempFileName();$fs=[IO.File]::Open($tmp,[IO.FileMode]::Truncate,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{for($i=0;;$i++){[byte]$b=[Runtime.InteropServices.Marshal]::ReadByte($lease.Pointer,$i);if($b -eq 0){break};$fs.WriteByte($b)};$fs.WriteByte(10);$fs.Flush($true)}finally{$fs.Dispose()}
        Copy-ToUbuntuGuest $tmp $GuestPath
        return $GuestPath
    }finally{if($tmp -and (Test-Path -LiteralPath $tmp)){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue};if($lease){[RansomLabV02CredentialTransport]::Release($lease)}}
}
function Close-UbuntuVix {
    if($script:HCQVix){$c=$script:HCQVix;try{if($c.LoggedIn){Logout-Guest $c.VM $c.ResetType $c.AuthType $c.None}}catch{};try{if($c.VM){[RansomLabAQ6C4BNative]::Vix_ReleaseHandle($c.VM)}}catch{};try{if($c.HostHandle){[RansomLabAQ6C4BNative]::VixHost_Disconnect($c.HostHandle)}}catch{};try{if($c.Wrapper -ne [IntPtr]::Zero){[void][RansomLabAQ6C4BNative]::FreeLibrary($c.Wrapper)}}catch{};$script:HCQVix=$null}
}
