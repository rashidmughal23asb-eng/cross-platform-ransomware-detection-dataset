# HCQ1 qualification-only bridge. Historical helper functions reused as reference.
# Does not permit official transaction modes or command-line credentials.
function Assert-True {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-LowerSHA256 {
    param([string]$Path)
    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

function New-Utf8Pointer {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal(
        $Bytes.Length + 1
    )

    try {
        [Runtime.InteropServices.Marshal]::Copy(
            $Bytes,0,$Ptr,$Bytes.Length
        )
        [Runtime.InteropServices.Marshal]::WriteByte(
            $Ptr,$Bytes.Length,0
        )
    }
    finally {
        [Array]::Clear($Bytes,0,$Bytes.Length)
    }

    return $Ptr
}

function Free-Utf8Pointer {
    param([IntPtr]$Pointer)

    if ($Pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($Pointer)
    }
}

function Get-VmxQuotedValue {
    param(
        [string[]]$Lines,
        [string]$Key
    )

    $Pattern =
        '^\s*' +
        [regex]::Escape($Key) +
        '\s*=\s*"([^"]*)"\s*$'

    $Found = @()

    foreach ($Line in $Lines) {
        $M = [regex]::Match([string]$Line,$Pattern)
        if ($M.Success) {
            $Found += $M.Groups[1].Value
        }
    }

    Assert-True ($Found.Count -eq 1) `
        "VMX KEY NOT UNIQUE: $Key"

    return [string]$Found[0]
}

function Parse-CInteger {
    param([string]$Text)

    $Value = $Text.Trim()

    if ($Value -match '^-?0[xX]([0-9A-Fa-f]+)$') {
        $Number =
            [Convert]::ToInt64($Matches[1],16)

        if ($Value.StartsWith('-')) {
            $Number = -$Number
        }

        return [Int64]$Number
    }

    return [Int64]$Value
}

function Get-VixConstant {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string[]]$Lines,

        [string]$Name
    )

    $Escaped = [regex]::Escape($Name)

    $EnumPattern =
        '^\s*' + $Escaped +
        '\s*=\s*\(?\s*([-+]?(?:0[xX][0-9A-Fa-f]+|\d+))\s*\)?\s*,?\s*(?://.*)?$'

    $DefinePattern =
        '^\s*#\s*define\s+' + $Escaped +
        '\s+\(?\s*([-+]?(?:0[xX][0-9A-Fa-f]+|\d+))\s*\)?(?:\s|$)'

    $Candidates = @()

    foreach ($Line in $Lines) {
        $M = [regex]::Match(
            [string]$Line,
            $EnumPattern
        )

        if (-not $M.Success) {
            $M = [regex]::Match(
                [string]$Line,
                $DefinePattern
            )
        }

        if ($M.Success) {
            $Candidates += $M.Groups[1].Value
        }
    }

    $Unique = @(
        $Candidates |
        ForEach-Object { Parse-CInteger $_ } |
        Sort-Object -Unique
    )

    Assert-True ($Unique.Count -eq 1) `
        "VIX CONSTANT NOT UNIQUE: $Name"

    return [int]$Unique[0]
}

function Get-NativeMethod {
    param(
        [type]$Type,
        [string]$Name
    )

    $Methods = @(
        $Type.GetMethods(
            [Reflection.BindingFlags]::Public -bor
            [Reflection.BindingFlags]::NonPublic -bor
            [Reflection.BindingFlags]::Static
        ) |
        Where-Object {
            $_.Name -ceq $Name
        }
    )

    Assert-True ($Methods.Count -eq 1) `
        "NATIVE METHOD NOT UNIQUE: $Name"

    return $Methods[0]
}

function Invoke-Native {
    param(
        [type]$Type,
        [string]$Name,
        [AllowEmptyCollection()]
        [object[]]$Arguments
    )

    $Method = Get-NativeMethod $Type $Name
    $Args = [object[]]$Arguments.Clone()

    $Return =
        $Method.Invoke(
            $null,
            $Args
        )

    return [pscustomobject]@{
        ReturnValue = $Return
        Arguments   = $Args
    }
}

function Assert-VixOK {
    param(
        [UInt64]$Code,
        [string]$Operation
    )

    Assert-True ($Code -eq 0) `
        "$Operation VIX ERROR CODE: $Code"
}

function Wait-VixReady {
    param(
        [type]$PollNativeType,
        [int]$JobHandle,
        [int]$TimeoutSeconds,
        [string]$Operation
    )

    Assert-True ($JobHandle -ne 0) `
        "$Operation INVALID JOB HANDLE"

    $Watch =
        [Diagnostics.Stopwatch]::StartNew()

    try {
        while ($true) {
            $Check =
                Invoke-Native `
                    $PollNativeType `
                    'VixJob_CheckCompletion' `
                    @([int]$JobHandle,[byte]0)

            Assert-VixOK `
                ([UInt64]$Check.ReturnValue) `
                "$Operation CHECK"

            if (
                [byte]$Check.Arguments[1] -ne 0
            ) {
                return
            }

            Assert-True `
                ($Watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) `
                "$Operation TIMEOUT"

            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        $Watch.Stop()
    }
}

function Wait-VixNone {
    param(
        [type]$PollNativeType,
        [type]$WaitNativeType,
        [int]$JobHandle,
        [int]$PropertyNone,
        [int]$TimeoutSeconds,
        [string]$Operation
    )

    Wait-VixReady `
        $PollNativeType `
        $JobHandle `
        $TimeoutSeconds `
        $Operation

    try {
        $Wait =
            Invoke-Native `
                $WaitNativeType `
                'VixJob_WaitNone' `
                @(
                    [int]$JobHandle,
                    [int]$PropertyNone
                )

        Assert-VixOK `
            ([UInt64]$Wait.ReturnValue) `
            "$Operation WAIT"
    }
    finally {
        try {
            [void](
                Invoke-Native `
                    $WaitNativeType `
                    'Vix_ReleaseHandle' `
                    @([int]$JobHandle)
            )
        }
        catch {}
    }
}

function Wait-VixHandle {
    param(
        [type]$NativeType,
        [int]$JobHandle,
        [int]$ResultProperty,
        [int]$PropertyNone,
        [int]$TimeoutSeconds,
        [string]$Operation
    )

    Wait-VixReady `
        $NativeType `
        $JobHandle `
        $TimeoutSeconds `
        $Operation

    try {
        $Wait =
            Invoke-Native `
                $NativeType `
                'VixJob_WaitHandle' `
                @(
                    [int]$JobHandle,
                    [int]$ResultProperty,
                    [int]0,
                    [int]$PropertyNone
                )

        Assert-VixOK `
            ([UInt64]$Wait.ReturnValue) `
            "$Operation WAIT"

        $Handle =
            [int]$Wait.Arguments[2]

        Assert-True ($Handle -ne 0) `
            "$Operation RESULT HANDLE INVALID"

        return $Handle
    }
    finally {
        try {
            [void](
                Invoke-Native `
                    $NativeType `
                    'Vix_ReleaseHandle' `
                    @([int]$JobHandle)
            )
        }
        catch {}
    }
}

function Login-Guest {
    param(
        [int]$VM,
        [string]$User,
        [object]$Lease,
        [type]$ResetType,
        [type]$AuthType,
        [int]$PropertyNone
    )

    $UserPtr =
        New-Utf8Pointer $User

    try {
        $Job =
            Invoke-Native `
                $AuthType `
                'VixVM_LoginInGuest' `
                @(
                    $VM,
                    $UserPtr,
                    $Lease.Pointer,
                    0,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero
                )

        Wait-VixNone `
            $ResetType `
            $AuthType `
            ([int]$Job.ReturnValue) `
            $PropertyNone `
            120 `
            "LOGIN $User"
    }
    finally {
        Free-Utf8Pointer $UserPtr
    }
}

function Logout-Guest {
    param(
        [int]$VM,
        [type]$ResetType,
        [type]$AuthType,
        [int]$PropertyNone
    )

    $Job =
        Invoke-Native `
            $AuthType `
            'VixVM_LogoutFromGuest' `
            @(
                $VM,
                [IntPtr]::Zero,
                [IntPtr]::Zero
            )

    Wait-VixNone `
        $ResetType `
        $AuthType `
        ([int]$Job.ReturnValue) `
        $PropertyNone `
        120 `
        'GUEST LOGOUT'
}

function Copy-HostToGuest {
    param(
        [int]$VM,
        [string]$HostPath,
        [string]$GuestPath,
        [int]$PropertyNone,
        [int]$TimeoutSeconds = 300
    )

    $HostPtr =
        New-Utf8Pointer $HostPath

    $GuestPtr =
        New-Utf8Pointer $GuestPath

    try {
        $Job =
            [RansomLabP1GP3P2GuestExecNative]::
            VixVM_CopyFileFromHostToGuest(
                $VM,
                $HostPtr,
                $GuestPtr,
                0,
                $PropertyNone,
                [IntPtr]::Zero,
                [IntPtr]::Zero
            )

        Wait-VixNone `
            ([type][RansomLabP1GP3P2GuestExecNative]) `
            ([type][RansomLabP1GP3P2GuestExecNative]) `
            $Job `
            $PropertyNone `
            $TimeoutSeconds `
            'COPY HOST TO GUEST'
    }
    finally {
        Free-Utf8Pointer $HostPtr
        Free-Utf8Pointer $GuestPtr
    }
}

function Copy-GuestToHost {
    param(
        [int]$VM,
        [string]$GuestPath,
        [string]$HostPath,
        [int]$PropertyNone,
        [int]$TimeoutSeconds = 300
    )

    $GuestPtr =
        New-Utf8Pointer $GuestPath

    $HostPtr =
        New-Utf8Pointer $HostPath

    try {
        $Job =
            [RansomLabP1GP3P2GuestExecNative]::
            VixVM_CopyFileFromGuestToHost(
                $VM,
                $GuestPtr,
                $HostPtr,
                0,
                $PropertyNone,
                [IntPtr]::Zero,
                [IntPtr]::Zero
            )

        Wait-VixNone `
            ([type][RansomLabP1GP3P2GuestExecNative]) `
            ([type][RansomLabP1GP3P2GuestExecNative]) `
            $Job `
            $PropertyNone `
            $TimeoutSeconds `
            'COPY GUEST TO HOST'
    }
    finally {
        Free-Utf8Pointer $GuestPtr
        Free-Utf8Pointer $HostPtr
    }
}
function Initialize-HCQVix {
    if($script:HCQVix){return}
    $VMSecretLease=$null;$PropertyListHandle=0;$VMHandle=0;$HostHandle=0;$WrapperModule=[IntPtr]::Zero
    try{
$WindowsVMX =
    'D:\Windows 11\Windows 11.vmx'

$UbuntuVMX =
    'D:\Ubuntu 24.04\Ubuntu.vmx'

$VMRun =
    'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'

$VixHeader =
    'C:\Program Files (x86)\VMware\VMware VIX\vix.h'

$VixWrapper =
    'C:\Program Files (x86)\VMware\VMware VIX\Vix64AllProductsDyn.dll'

$AQRoot =
    'D:\RansomLab_Host_Preservation\AutomationQualification'

$FrozenOrchestrator =
    Join-Path $AQRoot `
    'AQ3A_WindowsOrchestratorCandidate\phase15_windows_orchestrator_candidate_v0.3.3.ps1'

$ExpectedFrozenOrchestratorSHA =
    '15a9406d90a7ceacfb483c545923b4799454b5a1c2d8b39e2cfeb1ff19593546'

$ResetSource =
    Join-Path $AQRoot `
    'AQ6C4B_AuthoritativeS2NativeResetExecution\aq6c4b_native_reset_executor_v0.1.cs'

$AuthSource =
    Join-Path $AQRoot `
    'AQ6C3_R1A_NativeInteropCorrection\aq6c3_r1_native_interop_v0.1.cs'

$GuestExecSource =
    Join-Path $AQRoot `
    'P1G_P3_P2_A0_R3_R1_NativeVixGuestExecutionInteropExtensionFreeze\p1g_p3_p2_a0_r3_r1_native_vix_guest_execution_interop_v0.1.cs'

$ControllerTarget =
    'RansomLab.Phase15.Windows11.RansomLabController.v1'

$ControllerUser =
    'RansomLabController'
    $CandidateText =
        [IO.File]::ReadAllText(
            $FrozenOrchestrator
        )

    Assert-True ((Get-LowerSHA256 $FrozenOrchestrator) -ceq $ExpectedFrozenOrchestratorSHA) 'WinCandidate identity mismatch'

    $CredentialMatch =
        [regex]::Match(
            $CandidateText,
            '(?ms)^\$CredentialTransportSource\s*=\s*@"[ \t]*\r?\n(?<body>.*?)^\s*"@[ \t]*$'
        )

    Assert-True `
        $CredentialMatch.Success `
        "FROZEN CREDENTIAL TRANSPORT SOURCE NOT RESOLVED"

    $CredentialTransportSource =
        $CredentialMatch.Groups['body'].Value

    Write-Host `
        "FrozenCredentialTransportSourceResolved : True"

    # --------------------------------------------------------
    # Source-derive VIX constants
    # --------------------------------------------------------

    $HeaderLines =
        [IO.File]::ReadAllLines(
            $VixHeader
        )

    $VIX_PROPERTY_NONE =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_PROPERTY_NONE'

    $VIX_API_VERSION =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_API_VERSION'

    $VIX_PROVIDER =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_SERVICEPROVIDER_VMWARE_WORKSTATION'

    $VIX_VMOPEN_NORMAL =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_VMOPEN_NORMAL'

    $VIX_JOB_RESULT_HANDLE =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_PROPERTY_JOB_RESULT_HANDLE'

    $VIX_ENCRYPTION_PASSWORD =
        Get-VixConstant `
            -Lines $HeaderLines `
            -Name 'VIX_PROPERTY_VM_ENCRYPTION_PASSWORD'

    # --------------------------------------------------------
    # Load already-qualified interop
    # --------------------------------------------------------

    Add-Type `
        -Path $ResetSource `
        -ErrorAction Stop

    $AuthTypes =
        @(
            Add-Type `
                -TypeDefinition (
                    [IO.File]::ReadAllText(
                        $AuthSource
                    )
                ) `
                -Language CSharp `
                -PassThru `
                -ErrorAction Stop
        )

    $AuthTypeMatches =
        @(
            $AuthTypes |
            Where-Object {
                $_.FullName -ceq
                'RansomLabAQ6C3R1Native'
            }
        )

    Assert-True `
        ($AuthTypeMatches.Count -eq 1) `
        "AUTH NATIVE TYPE NOT UNIQUE"

    $AuthType =
        $AuthTypeMatches[0]

    Add-Type `
        -Path $GuestExecSource `
        -ErrorAction Stop

    Add-Type `
        -TypeDefinition $CredentialTransportSource `
        -Language CSharp `
        -ErrorAction Stop

    $ResetType =
        [type][RansomLabAQ6C4BNative]

    # --------------------------------------------------------
    # Preload VIX wrapper
    # --------------------------------------------------------

    $WrapperModule =
        [RansomLabAQ6C4BNative]::LoadLibraryEx(
            $VixWrapper,
            [IntPtr]::Zero,
            [uint32]0x00000008
        )

    Assert-True `
        ($WrapperModule -ne [IntPtr]::Zero) `
        "VIX WRAPPER PRELOAD FAILED"

    # --------------------------------------------------------
    # Resolve VM-encryption Credential Manager target
    # --------------------------------------------------------

    $VMXLines =
        [IO.File]::ReadAllLines(
            $WindowsVMX
        )

    $EncryptedGuid =
        Get-VmxQuotedValue `
            $VMXLines `
            'encryptedVM.guid'

    $GuidBare =
        (
            $EncryptedGuid -replace '[{}]',''
        ).ToLowerInvariant()

    $CmdKey =
        @(
            & "$env:SystemRoot\System32\cmdkey.exe" `
                /list 2>&1
        )

    Assert-True `
        ($LASTEXITCODE -eq 0) `
        "CMDKEY LIST FAILED"

    $VMTargets =
        @(
            $CmdKey |
            Where-Object {
                ([string]$_) -match '^\s*Target\s*:' -and
                ([string]$_).ToLowerInvariant().Contains(
                    $GuidBare
                )
            }
        )

    Assert-True `
        ($VMTargets.Count -eq 1) `
        "VM ENCRYPTION CREDENTIAL TARGET NOT UNIQUE"

    $VMTargetMatch =
        [regex]::Match(
            [string]$VMTargets[0],
            '^\s*Target\s*:\s*(.+?)\s*$'
        )

    Assert-True `
        $VMTargetMatch.Success `
        "VM CREDENTIAL TARGET PARSE FAILED"

    $VMEncryptionTarget =
        $VMTargetMatch.Groups[1].Value.Trim()

    $ControllerTargetCount =
        @(
            $CmdKey |
            Where-Object {
                ([string]$_) -match '^\s*Target\s*:' -and
                ([string]$_).IndexOf(
                    $ControllerTarget,
                    [StringComparison]::OrdinalIgnoreCase
                ) -ge 0
            }
        ).Count

    Assert-True `
        ($ControllerTargetCount -eq 1) `
        "CONTROLLER CREDENTIAL TARGET NOT UNIQUE"

    # --------------------------------------------------------
    # Native VIX host connection
    # --------------------------------------------------------

    $HostJob =
        [RansomLabAQ6C4BNative]::VixHost_Connect(
            $VIX_API_VERSION,
            $VIX_PROVIDER,
            [IntPtr]::Zero,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            0,
            $VIX_PROPERTY_NONE,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )

    $HostHandle =
        Wait-VixHandle `
            $ResetType `
            $HostJob `
            $VIX_JOB_RESULT_HANDLE `
            $VIX_PROPERTY_NONE `
            120 `
            'VIX HOST CONNECT'

    # --------------------------------------------------------
    # Open encrypted VM using Credential Manager secret
    # --------------------------------------------------------

    $VMSecretLease =
        [RansomLabV02CredentialTransport]::Acquire(
            $VMEncryptionTarget
        )

    [int]$PropertyHandle = 0

    [UInt64]$PropertyError =
        [RansomLabAQ6C4BNative]::
        VixPropertyList_AllocEncryptionPassword(
            $HostHandle,
            [ref]$PropertyHandle,
            $VIX_ENCRYPTION_PASSWORD,
            $VMSecretLease.Pointer,
            $VIX_PROPERTY_NONE
        )

    Assert-VixOK `
        $PropertyError `
        'VM ENCRYPTION PROPERTY LIST'

    $PropertyListHandle =
        $PropertyHandle

    $VMXPathPtr =
        New-Utf8Pointer $WindowsVMX

    try {

        $OpenJob =
            [RansomLabAQ6C4BNative]::VixHost_OpenVM(
                $HostHandle,
                $VMXPathPtr,
                $VIX_VMOPEN_NORMAL,
                $PropertyListHandle,
                [IntPtr]::Zero,
                [IntPtr]::Zero
            )

        $VMHandle =
            Wait-VixHandle `
                $ResetType `
                $OpenJob `
                $VIX_JOB_RESULT_HANDLE `
                $VIX_PROPERTY_NONE `
                120 `
                'OPEN ENCRYPTED WINDOWS VM'
    }
    finally {
        Free-Utf8Pointer $VMXPathPtr
    }

    [RansomLabAQ6C4BNative]::
    Vix_ReleaseHandle(
        $PropertyListHandle
    )

    $PropertyListHandle = 0

    [RansomLabV02CredentialTransport]::
    Release(
        $VMSecretLease
    )

    $VMSecretLease = $null

    $script:HCQVix=[pscustomobject]@{VM=$VMHandle;HostHandle=$HostHandle;ResetType=$ResetType;AuthType=$AuthType;None=$VIX_PROPERTY_NONE;Wrapper=$WrapperModule;LoggedIn=$false}
    Write-Host 'HCQ1_NATIVE_ENCRYPTED_VM_OPEN=PASS'
    }finally{
        if($VMSecretLease){[RansomLabV02CredentialTransport]::Release($VMSecretLease)}
        if($PropertyListHandle){[RansomLabAQ6C4BNative]::Vix_ReleaseHandle($PropertyListHandle)}
        if(-not $script:HCQVix){
            if($VMHandle){[RansomLabAQ6C4BNative]::Vix_ReleaseHandle($VMHandle)}
            if($HostHandle){[RansomLabAQ6C4BNative]::VixHost_Disconnect($HostHandle)}
            if($WrapperModule -ne [IntPtr]::Zero){[void][RansomLabAQ6C4BNative]::FreeLibrary($WrapperModule)}
        }
    }
}
