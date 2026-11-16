[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('ToolCheck','Prepare','Run','Task')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^S(0[1-9]|1[0-5])$')][string]$ScenarioID,
    [ValidateSet('A','B')][string]$Repetition='A',
    [ValidatePattern('^[0-9a-f]{16}$')][string]$AttemptID='0000000000000000',
    [Parameter(Mandatory=$true)][string]$ReceiptPath,
    [string]$WorkRoot='',
    [ValidateRange(30,300)][int]$DurationSeconds=60,
    [string]$FixtureSeed='',
    [ValidateSet('Lead','Mutation','Rotation')][string]$TaskKind='Lead',
    [int]$ParentPid=0
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$Script:TaskHardDeadlineUtc=$null
$Script:DeadlineNativeChild=$null

function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Write-Json([string]$Path,[object]$Object){
    $Dir=Split-Path -Parent $Path
    if($Dir -and -not(Test-Path -LiteralPath $Dir)){New-Item -ItemType Directory -Path $Dir -Force|Out-Null}
    [IO.File]::WriteAllText($Path,(($Object|ConvertTo-Json -Depth 40)+"`r`n"),(New-Object Text.UTF8Encoding($false)))
}
function Find-ExecutableFallback([string[]]$Names){
    $Roots=@(
        'C:\ProgramData\chocolatey\bin',
        'C:\ProgramData\chocolatey\lib',
        'C:\Users\RansomLabController\AppData\Local\Microsoft\WinGet\Packages',
        'C:\Users\RansomLabController\scoop\apps',
        'C:\tools',
        'C:\RansomLab',
        'C:\Program Files',
        'C:\Program Files (x86)'
    )
    $WhereExe='C:\Windows\System32\where.exe'
    foreach($Root in $Roots){
        if(-not(Test-Path -LiteralPath $Root -PathType Container)){continue}
        foreach($Name in $Names){
            if(Test-Path -LiteralPath $WhereExe -PathType Leaf){
                try{
                    $Found=@(& $WhereExe /R $Root $Name 2>$null | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1)
                    if($Found.Count -eq 1){return [string]$Found[0]}
                }catch{}
            }
            try{
                $Found2=Get-ChildItem -LiteralPath $Root -Filter $Name -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if($Found2){return [string]$Found2.FullName}
            }catch{}
        }
    }
    return $null
}
function Resolve-Executable([string[]]$Names,[string[]]$Candidates=@()){
    foreach($Candidate in $Candidates){
        if($Candidate -and (Test-Path -LiteralPath $Candidate -PathType Leaf)){return $Candidate}
    }
    foreach($Name in $Names){
        $Cmd=Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
        if($Cmd){return [string]$Cmd.Source}
    }
    return Find-ExecutableFallback $Names
}
function Get-ScenarioMeta([string]$Id){
    $Map=@{
        S01=@('BULK_MIGRATION','xcopy',@('bulk_copy','rename','modify','compress','decompress','temporary_create','delete'))
        S02=@('RESILIENT_SYNC','robocopy',@('sync','mirror','modify','stale_cleanup','archive_rotation','log_rotation'))
        S03=@('ARCHIVE_ROTATION','tar',@('archive_create','archive_extract','rename_rotation','bulk_copy','cleanup'))
        S04=@('HIGH_DENSITY_ARCHIVE','7-Zip',@('parallel_archive','extract','rename','copy','temporary_delete'))
        S05=@('REPOSITORY_CHURN','git',@('checkout','reset','generated_file_churn','archive_worktree','cleanup'))
        S06=@('SCRIPTED_ETL','Python',@('generate','transform','rename','copy','compress','temporary_cleanup'))
        S07=@('MEDIA_PIPELINE','FFmpeg',@('transcode','rename','copy','archive','temporary_delete'))
        S08=@('DATABASE_MAINTENANCE','SQLite',@('insert','update','delete','backup','vacuum','archive_rotation'))
        S09=@('OFFICE_AUTOSAVE_EXPORT','LibreOffice',@('document_save','export','rename','copy','archive','cleanup'))
        S10=@('BUILD_CONFIGURE','CMake',@('configure','generate','output_churn','copy','archive','clean'))
        S11=@('PARALLEL_BUILD','Ninja',@('parallel_build','rebuild','artifact_rename','copy','archive','clean'))
        S12=@('PACKAGE_STAGING','makecab',@('package','compress','extract','decompress','rename_rotation','cleanup'))
        S13=@('TEXT_REWRITE','cmd',@('text_rewrite','rename','copy','compress','temporary_delete'))
        S14=@('INSTALLER_PACKAGE_MAINTENANCE','msiexec',@('package_extract','staging','rename','copy','temporary_cleanup'))
        S15=@('SEQUENTIAL_IO_ROTATION','PowerShell',@('sequential_write','copy','rename','compression','delete','rotation'))
    }
    $V=$Map[$Id]
    [pscustomobject]@{scenario_id=$Id;scenario_name=$V[0];lead_application=$V[1];operation_families=$V[2]}
}
function Resolve-ScenarioTool([string]$Id){
    switch($Id){
        'S01' {return Resolve-Executable @('xcopy.exe') @('C:\Windows\System32\xcopy.exe')}
        'S02' {return Resolve-Executable @('robocopy.exe') @('C:\Windows\System32\robocopy.exe')}
        'S03' {return Resolve-Executable @('tar.exe') @('C:\Windows\System32\tar.exe')}
        'S04' {return Resolve-Executable @('7z.exe','7zz.exe') @('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe')}
        'S05' {return Resolve-Executable @('git.exe') @('C:\Program Files\Git\cmd\git.exe','C:\Program Files\Git\bin\git.exe')}
        'S06' {return Resolve-Executable @('python.exe') @()}
        'S07' {return Resolve-Executable @('ffmpeg.exe') @('C:\Program Files\ffmpeg\bin\ffmpeg.exe','C:\ProgramData\chocolatey\bin\ffmpeg.exe','C:\ffmpeg\bin\ffmpeg.exe')}
        'S08' {return Resolve-Executable @('sqlite3.exe') @('C:\Program Files\SQLite\sqlite3.exe','C:\ProgramData\chocolatey\bin\sqlite3.exe','C:\sqlite\sqlite3.exe','C:\sqlite3\sqlite3.exe')}
        'S09' {return Resolve-Executable @('soffice.exe') @('C:\Program Files\LibreOffice\program\soffice.exe')}
        'S10' {return Resolve-Executable @('cmake.exe') @('C:\Program Files\CMake\bin\cmake.exe')}
        'S11' {return Resolve-Executable @('ninja.exe') @('C:\Program Files\CMake\bin\ninja.exe','C:\ProgramData\chocolatey\bin\ninja.exe','C:\ninja\ninja.exe')}
        'S12' {return Resolve-Executable @('makecab.exe') @('C:\Windows\System32\makecab.exe')}
        'S13' {return Resolve-Executable @('cmd.exe') @('C:\Windows\System32\cmd.exe')}
        'S14' {return Resolve-Executable @('msiexec.exe') @('C:\Windows\System32\msiexec.exe')}
        'S15' {return Resolve-Executable @('powershell.exe') @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')}
    }
}
function Invoke-TrackedProcess([string]$FilePath,[string[]]$Arguments,[int[]]$AcceptedExitCodes=@(0)){
    $ArgCopy=@($Arguments | ForEach-Object {[string]$_})
    $DiagDir=Join-Path $WorkRoot 'NativeDiagnostics'
    if(-not(Test-Path -LiteralPath $DiagDir)){New-Item -ItemType Directory -Path $DiagDir -Force|Out-Null}
    $MaxRetries=3
    $RetryDelayMs=200
    $ProcTimeoutMs=30000
    $LastCode=$null
    $LastStdout=''
    $LastStderr=''
    $LastStdoutPath=$null
    $LastStderrPath=$null
    for($Retry=0;$Retry -lt $MaxRetries;$Retry++){
        if($Retry -gt 0){Start-Sleep -Milliseconds $RetryDelayMs}
        $DiagId=[Guid]::NewGuid().ToString('N')
        $StdoutPath=Join-Path $DiagDir ($DiagId+'.stdout.txt')
        $StderrPath=Join-Path $DiagDir ($DiagId+'.stderr.txt')
        $RemainingHardMs=$ProcTimeoutMs
        if($null -ne $Script:TaskHardDeadlineUtc){
            $RemainingHardMs=[int][Math]::Floor(($Script:TaskHardDeadlineUtc-[DateTime]::UtcNow).TotalMilliseconds)
            if($RemainingHardMs -le 0){throw 'ACTIVE_WINDOW_COMPLETE_BEFORE_NATIVE_START'}
        }
        $P=Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        $PidValue=[int]$P.Id
        $WaitOk=$P.WaitForExit($RemainingHardMs)
        if(-not $WaitOk){
            $TaskKill=Join-Path $env:SystemRoot 'System32\taskkill.exe'
            try{& $TaskKill /PID $PidValue /T /F 2>$null | Out-Null}catch{}
            try{if(-not$P.HasExited){$P.Kill()}}catch{}
            try{$P.WaitForExit(5000)}catch{}
            $Script:DeadlineNativeChild=[ordered]@{pid=$PidValue;parent_pid=[Diagnostics.Process]::GetCurrentProcess().Id;process_name=[IO.Path]::GetFileName($FilePath);process_path=$FilePath;arguments=$ArgCopy;exit_code=-1;termination='ACTIVE_WINDOW_HARD_DEADLINE'}
            throw 'ACTIVE_WINDOW_COMPLETE_NATIVE_TERMINATED_AT_HARD_DEADLINE'
        }else{
            $Code=[int]$P.ExitCode
        }
        $StdoutText=''
        $StderrText=''
        try{if(Test-Path -LiteralPath $StdoutPath){$StdoutText=[IO.File]::ReadAllText($StdoutPath)}}catch{}
        try{if(Test-Path -LiteralPath $StderrPath){$StderrText=[IO.File]::ReadAllText($StderrPath)}}catch{}
        if($StdoutText.Length -gt 4096){$StdoutText=$StdoutText.Substring($StdoutText.Length-4096)}
        if($StderrText.Length -gt 4096){$StderrText=$StderrText.Substring($StderrText.Length-4096)}
        if($AcceptedExitCodes -contains $Code){
            Remove-Item -LiteralPath $StdoutPath,$StderrPath -Force -ErrorAction SilentlyContinue
            $Record=[ordered]@{
                pid=$PidValue
                parent_pid=[Diagnostics.Process]::GetCurrentProcess().Id
                process_name=[IO.Path]::GetFileName($FilePath)
                process_path=$FilePath
                arguments=$ArgCopy
                exit_code=$Code
            }
            $NativeJournal=Join-Path $DiagDir ('native_children_'+[Diagnostics.Process]::GetCurrentProcess().Id+'.jsonl')
            Add-Content -LiteralPath $NativeJournal -Value ($Record|ConvertTo-Json -Compress -Depth 8) -Encoding UTF8
            return $Record
        }
        $LastCode=$Code
        $LastStdout=$StdoutText
        $LastStderr=$StderrText
        $LastStdoutPath=$StdoutPath
        $LastStderrPath=$StderrPath
    }
    $Ex=New-Object System.Exception(("PROCESS_EXIT_"+$LastCode+":"+[IO.Path]::GetFileName($FilePath)))
    $Ex.Data['ProcessPath']=$FilePath
    $Ex.Data['Arguments']=($ArgCopy -join ' | ')
    $Ex.Data['ExitCode']=$LastCode
    $Ex.Data['StdoutTail']=$LastStdout
    $Ex.Data['StderrTail']=$LastStderr
    $Ex.Data['StdoutPath']=$LastStdoutPath
    $Ex.Data['StderrPath']=$LastStderrPath
    throw $Ex
}

$Meta=Get-ScenarioMeta $ScenarioID
if([string]::IsNullOrWhiteSpace($FixtureSeed)){$FixtureSeed="$ScenarioID-WIN-$Repetition"}
if([string]::IsNullOrWhiteSpace($WorkRoot)){$WorkRoot="C:\RansomLab\BenignScenario\$AttemptID\$ScenarioID`_$Repetition"}
$Source=Join-Path $WorkRoot 'Source'
$Assets=Join-Path $WorkRoot 'Assets'
$TaskReceipts=Join-Path $WorkRoot 'TaskReceipts'
$LeadRoot=Join-Path $WorkRoot 'Lead'
$MutationRoot=Join-Path $WorkRoot 'Mutation'
$RotationRoot=Join-Path $WorkRoot 'Rotation'

if($Mode -eq 'ToolCheck'){
    $Tool=Resolve-ScenarioTool $ScenarioID
    $Extra=@()
    if($ScenarioID -eq 'S14'){
        $Msi=@(Get-ChildItem -LiteralPath 'C:\Windows\Installer' -Filter '*.msi' -File -Force -ErrorAction SilentlyContinue|Sort-Object Name|Select-Object -First 1)
        if($Msi.Count -eq 1){$Extra+=[ordered]@{name='cached_msi_candidate';path=$Msi[0].FullName;sha256=(Get-FileHash -LiteralPath $Msi[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}
    }
    $Status=if($Tool -and (($ScenarioID -ne 'S14') -or $Extra.Count -eq 1)){'PASS'}else{'FAIL'}
    Write-Json $ReceiptPath ([ordered]@{schema_version='1.0';gate='SCENARIO_TOOLCHECK';status=$Status;os='Windows';scenario_id=$ScenarioID;scenario_name=$Meta.scenario_name;lead_application=$Meta.lead_application;tool_path=$Tool;extra=$Extra;executed_workload=$false;timestamp=[DateTime]::UtcNow.ToString('o')})
    if($Status -ne 'PASS'){exit 2}; exit 0
}

if($Mode -eq 'Prepare'){
    Assert-True (-not(Test-Path -LiteralPath $WorkRoot)) 'SCENARIO_WORK_ROOT_ALREADY_EXISTS'
    foreach($D in @($Source,$Assets,$TaskReceipts,$LeadRoot,$MutationRoot,$RotationRoot)){New-Item -ItemType Directory -Path $D -Force|Out-Null}
    $Pattern=New-Object byte[] 8192
    $SeedDigest=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($FixtureSeed))

    $SeedBase=[BitConverter]::ToUInt32($SeedDigest,0)
    for($i=0;$i-lt$Pattern.Length;$i++){$Pattern[$i]=[byte](($i*31+$SeedBase+17)%251)}
    $Count=0
    for($d=0;$d-lt8;$d++){
        $Sub=Join-Path $Source ('set_{0:D2}' -f $d);New-Item -ItemType Directory -Path $Sub -Force|Out-Null
        for($f=0;$f-lt32;$f++){[IO.File]::WriteAllBytes((Join-Path $Sub ('file_{0:D3}.bin' -f $f)),$Pattern);$Count++}
    }
    foreach($DocN in 1..3){Set-Content -LiteralPath (Join-Path $Assets (('document_{0:D2}.html' -f $DocN))) -Encoding UTF8 -Value ("<html><body><h1>Benign Scenario Document $DocN</h1><p>Deterministic benign export workload.</p></body></html>")}
    Set-Content -LiteralPath (Join-Path $Assets 'rewrite.txt') -Encoding UTF8 -Value (1..256|ForEach-Object{"benign source line $_"})
    [IO.File]::WriteAllText((Join-Path $Assets 'etl.py'),@'
import pathlib,sys,hashlib
src=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2]); out.mkdir(parents=True,exist_ok=True)
for p in sorted(src.rglob("*.bin"))[:128]:
    b=p.read_bytes(); q=out/(p.stem+".txt"); q.write_text(hashlib.sha256(b).hexdigest()+"\n",encoding="utf-8")
'@,(New-Object Text.UTF8Encoding($false)))
    $CMakeDir=Join-Path $Assets 'cmake_project';New-Item -ItemType Directory -Path $CMakeDir -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $CMakeDir 'CMakeLists.txt'),"cmake_minimum_required(VERSION 3.16)`nproject(Benign NONE)`nfile(GENERATE OUTPUT `"`${CMAKE_BINARY_DIR}/generated.txt`" CONTENT `"benign-generated`n`")`n",(New-Object Text.UTF8Encoding($false)))
    $NinjaDir=Join-Path $Assets 'ninja_project';New-Item -ItemType Directory -Path $NinjaDir -Force|Out-Null
    Copy-Item -LiteralPath (Join-Path $Source 'set_00\file_000.bin') -Destination (Join-Path $NinjaDir 'input.bin') -Force
    [IO.File]::WriteAllText((Join-Path $NinjaDir 'build.ninja'),"rule copyfile`n  command = cmd /d /c copy /y input.bin output.bin ^>nul`nbuild output.bin: copyfile input.bin`ndefault output.bin`n",(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $Assets 'rewrite.cmd'),"@echo off`nset SRC=%~1`nset DST=%~2`nif not exist `"%DST%`" mkdir `"%DST%`"`ncopy /y `"%SRC%`" `"%DST%\rewrite_a.txt`" >nul`ntype `"%SRC%`" >> `"%DST%\rewrite_a.txt`"`nren `"%DST%\rewrite_a.txt`" rewrite_b.txt`ncopy /y `"%DST%\rewrite_b.txt`" `"%DST%\rewrite_c.txt`" >nul`n",(New-Object Text.UTF8Encoding($false)))

    $Tool=Resolve-ScenarioTool $ScenarioID
    Assert-True (-not[string]::IsNullOrWhiteSpace($Tool)) ('SCENARIO_TOOL_NOT_FOUND:'+$ScenarioID)
    $PrepExtra=@()
    if($ScenarioID -eq 'S05'){
        $Repo=Join-Path $Assets 'repo';New-Item -ItemType Directory -Path $Repo -Force|Out-Null
        Copy-Item -Path (Join-Path $Source 'set_00\*') -Destination $Repo -Force
        [void](Invoke-TrackedProcess $Tool @('-C',$Repo,'init'))
        [void](Invoke-TrackedProcess $Tool @('-C',$Repo,'config','user.email','benign@example.invalid'))
        [void](Invoke-TrackedProcess $Tool @('-C',$Repo,'config','user.name','Benign Scenario'))
        [void](Invoke-TrackedProcess $Tool @('-C',$Repo,'add','-A'))
        [void](Invoke-TrackedProcess $Tool @('-C',$Repo,'commit','-m','baseline'))
    }
    if($ScenarioID -eq 'S08'){
        $Db=Join-Path $Assets 'scenario.db'
        [void](Invoke-TrackedProcess $Tool @($Db,'CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY,v TEXT); INSERT INTO t(v) VALUES(''baseline'');'))
    }
    if($ScenarioID -eq 'S14'){
        $Msi=@(Get-ChildItem -LiteralPath 'C:\Windows\Installer' -Filter '*.msi' -File -Force -ErrorAction SilentlyContinue|Sort-Object Name|Select-Object -First 1)
        Assert-True ($Msi.Count -eq 1) 'NO_CACHED_MSI_CANDIDATE'
        $PrepExtra+=[ordered]@{msi_path=$Msi[0].FullName;msi_sha256=(Get-FileHash -LiteralPath $Msi[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        Write-Json (Join-Path $Assets 'msi_candidate.json') $PrepExtra[0]
    }
    $Total=(Get-ChildItem -LiteralPath $Source -Recurse -File|Measure-Object Length -Sum).Sum
    Write-Json $ReceiptPath ([ordered]@{schema_version='1.0';gate='SCENARIO_WORKLOAD_PREPARE';status='PASS';os='Windows';AttemptID=$AttemptID;scenario_id=$ScenarioID;scenario_name=$Meta.scenario_name;lead_application=$Meta.lead_application;repetition=$Repetition;fixture_seed=$FixtureSeed;duration_seconds=$DurationSeconds;fixture_file_count=$Count;fixture_bytes=[int64]$Total;tool_path=$Tool;extra=$PrepExtra;concurrent_tasks=@('lead','mutation','rotation');executed=$false;timestamp=[DateTime]::UtcNow.ToString('o')})
    Write-Host ("SCENARIO_PREPARE=PASS OS=Windows SCENARIO=$ScenarioID LEAD="+$Meta.lead_application+" FILES=$Count")
    exit 0
}

if($Mode -eq 'Task'){
    $TaskPid=[Diagnostics.Process]::GetCurrentProcess().Id
    $Start=[DateTime]::UtcNow
    $Sw=[Diagnostics.Stopwatch]::StartNew()
    # V28_SCIENTIFIC_NATIVE_DEADLINE: enforce the frozen <=65 second active gate.
    # Native work may be ended at 62 seconds; actual elapsed time remains recorded.
    $Script:TaskHardDeadlineUtc=$Start.AddSeconds([double]$DurationSeconds+2.0)
    $Script:DeadlineNativeChild=$null
    $ActiveCutoff=[Math]::Max(1.0,[double]$DurationSeconds-3.0)
    # V24_DEADLINE_AWARE_ITERATION_ADMISSION
    # A loop iteration can contain a complete native copy or archive/dearchive cycle.
    # Under VM contention that cycle can finish well after the pre-iteration clock
    # check. Reserve a conservative first-cycle allowance, then retain the largest
    # observed allowance (1.5x measured cycle + 1s) before admitting another cycle.
    # The scientific acceptance gate remains unchanged at DurationSeconds+5.
    $IterationReserveSeconds=switch($TaskKind){'Rotation'{12.0}'Lead'{8.0}default{3.0}}
    $IterationHardBudgetSeconds=[double]$DurationSeconds
    $Iterations=0;$FilesTouched=[int64]0;$BytesTouched=[int64]0;$NativeChildren=@()
    try{
        if($TaskKind -eq 'Mutation'){
            $Live=Join-Path $MutationRoot 'live';New-Item -ItemType Directory -Path $Live -Force|Out-Null
            Get-ChildItem -LiteralPath (Join-Path $Source 'set_00') -File|Select-Object -First 32|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Live $_.Name) -Force}
            $Patch=New-Object byte[] 128
            while($Sw.Elapsed.TotalSeconds -lt $ActiveCutoff -and (($Sw.Elapsed.TotalSeconds+$IterationReserveSeconds) -le $IterationHardBudgetSeconds)){
                $IterationStartSeconds=$Sw.Elapsed.TotalSeconds
                $Iterations++
                foreach($F in @(Get-ChildItem -LiteralPath $Live -File|Sort-Object Name)){
                    $Tmp=$F.FullName+'.wrk';Move-Item -LiteralPath $F.FullName -Destination $Tmp -Force
                    $S=[IO.File]::Open($Tmp,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$S.Write($Patch,0,$Patch.Length)}finally{$S.Dispose()}
                    Move-Item -LiteralPath $Tmp -Destination $F.FullName -Force
                    $FilesTouched++;$BytesTouched+=$Patch.Length
                }
                $IterationSeconds=$Sw.Elapsed.TotalSeconds-$IterationStartSeconds
                $IterationReserveSeconds=[Math]::Max($IterationReserveSeconds,($IterationSeconds*1.5)+1.0)
            }
        } elseif($TaskKind -eq 'Rotation'){
            while($Sw.Elapsed.TotalSeconds -lt $ActiveCutoff -and (($Sw.Elapsed.TotalSeconds+$IterationReserveSeconds) -le $IterationHardBudgetSeconds)){
                $IterationStartSeconds=$Sw.Elapsed.TotalSeconds
                $Iterations++
                # V20_ROTATION_BOUNDED_ARCHIVE_RETRY_RETAINED
                # V22_ROTATION_ZIP_PATH_FIX: Compress-Archive appends .zip when it is omitted.
                # Keep the producer, consumer, and cleanup paths identical and explicit.
                $Zip=Join-Path $RotationRoot ('r_{0:D4}.zip' -f $Iterations)
                $ArchiveOk=$false
                for($a=0;$a -lt 3;$a++){
                    try{
                        Compress-Archive -Path (Join-Path $Source 'set_01\*') -DestinationPath $Zip -CompressionLevel Fastest -Force
                        $Out=Join-Path $RotationRoot ('x_{0:D4}' -f $Iterations);Expand-Archive -LiteralPath $Zip -DestinationPath $Out -Force
                        $ArchiveOk=$true
                        break
                    }catch{
                        if($a -eq 2){throw}
                        Start-Sleep -Milliseconds 200
                    }
                }
                if(-not $ArchiveOk){throw 'ROTATION_ARCHIVE_RETRY_EXHAUSTED'}
                $FilesTouched+=64
                if($Iterations -gt 1){$OldOut=Join-Path $RotationRoot ('x_{0:D4}' -f ($Iterations-1));$OldZip=Join-Path $RotationRoot ('r_{0:D4}.zip' -f ($Iterations-1));Remove-Item $OldOut -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item $OldZip -Force -ErrorAction SilentlyContinue}
                $IterationSeconds=$Sw.Elapsed.TotalSeconds-$IterationStartSeconds
                $IterationReserveSeconds=[Math]::Max($IterationReserveSeconds,($IterationSeconds*1.5)+1.0)
            }
        } else {
            $Tool=Resolve-ScenarioTool $ScenarioID
            Assert-True (-not[string]::IsNullOrWhiteSpace($Tool)) ('SCENARIO_TOOL_NOT_FOUND:'+$ScenarioID)
            while($Sw.Elapsed.TotalSeconds -lt $ActiveCutoff -and (($Sw.Elapsed.TotalSeconds+$IterationReserveSeconds) -le $IterationHardBudgetSeconds)){
                $IterationStartSeconds=$Sw.Elapsed.TotalSeconds
                $Iterations++
                switch($ScenarioID){
                    'S01' {
                        $Dest=Join-Path $LeadRoot ('copy_{0:D4}' -f $Iterations)
                        # S01_XCOPY_EXPLICIT_SET_SOURCE_V7
                        New-Item -ItemType Directory -Path $Dest -Force|Out-Null
                        $Sets=@(Get-ChildItem -LiteralPath $Source -Directory | Where-Object {$_.Name -match '^set_[0-9]{2}$'} | Sort-Object Name)
                        Assert-True ($Sets.Count -eq 8) ('S01_SOURCE_SET_COUNT_MISMATCH:'+$Sets.Count)
                        foreach($Set in $Sets){
                            $SetFiles=@(Get-ChildItem -LiteralPath $Set.FullName -File)
                            Assert-True ($SetFiles.Count -eq 32) ('S01_SOURCE_FILE_COUNT_MISMATCH:'+$Set.Name+':'+$SetFiles.Count)
                            $SetDest=Join-Path $Dest $Set.Name
                            New-Item -ItemType Directory -Path $SetDest -Force|Out-Null
                            $SourcePattern=Join-Path $Set.FullName '*'
                            $N=Invoke-TrackedProcess $Tool @($SourcePattern,(($SetDest.TrimEnd('\'))+'\'),'/E','/I','/Y','/Q')
                            $NativeChildren+=,$N
                            $Copied=@(Get-ChildItem -LiteralPath $SetDest -File -Recurse)
                            Assert-True ($Copied.Count -eq 32) ('S01_DEST_FILE_COUNT_MISMATCH:'+$Set.Name+':'+$Copied.Count)
                            $FilesTouched+=$Copied.Count
                        }
                        if($Iterations -gt 2){Remove-Item (Join-Path $LeadRoot ('copy_{0:D4}' -f ($Iterations-2))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S02' {
                        $Dest=Join-Path $LeadRoot 'mirror';New-Item -ItemType Directory -Path $Dest -Force|Out-Null
                        Set-Content -LiteralPath (Join-Path $Source 'sync_marker.txt') -Value ("iteration="+$Iterations) -Encoding ASCII
                        if($Iterations -gt 1){Set-Content -LiteralPath (Join-Path $Dest 'stale.tmp') -Value 'stale' -Encoding ASCII}
                        $N=Invoke-TrackedProcess $Tool @($Source,$Dest,'/MIR','/R:0','/W:0','/NFL','/NDL','/NJH','/NJS') @(0,1,2,3,4,5,6,7);$NativeChildren+=,$N
                        $Log=Join-Path $LeadRoot 'sync.log';Add-Content -LiteralPath $Log -Value ("iteration="+$Iterations) -Encoding ASCII
                        if((Get-Item -LiteralPath $Log).Length -gt 2048){Move-Item -LiteralPath $Log -Destination (Join-Path $LeadRoot ('sync_{0:D4}.log' -f $Iterations)) -Force}
                    }
                    'S03' {
                        $Archive=Join-Path $LeadRoot ('a_{0:D4}.tar' -f $Iterations);$Out=Join-Path $LeadRoot ('x_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-cf',$Archive,'-C',$Source,'.'))
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-xf',$Archive,'-C',$Out));$FilesTouched+=256
                        $Rotated=Join-Path $LeadRoot ('rotated_{0:D4}.tar' -f $Iterations);Move-Item -LiteralPath $Archive -Destination $Rotated -Force
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('x_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item (Join-Path $LeadRoot ('rotated_{0:D4}.tar' -f ($Iterations-1))) -Force -ErrorAction SilentlyContinue}
                    }
                    'S04' {
                        $Archive=Join-Path $LeadRoot ('a_{0:D4}.7z' -f $Iterations);$Out=Join-Path $LeadRoot ('x_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('a','-y','-mx=1',$Archive,(Join-Path $Source '*')))
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('x','-y',('-o'+$Out),$Archive));$FilesTouched+=256
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('x_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item (Join-Path $LeadRoot ('a_{0:D4}.7z' -f ($Iterations-1))) -Force -ErrorAction SilentlyContinue}
                    }
                    'S05' {
                        $Repo=Join-Path $Assets 'repo';Set-Content -LiteralPath (Join-Path $Repo 'churn.txt') -Value ("iteration="+$Iterations) -Encoding ASCII
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-C',$Repo,'add','-A'))
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-C',$Repo,'commit','--allow-empty','-m',("churn_"+$Iterations)))
                        $GitArchive=Join-Path $LeadRoot ('worktree_{0:D4}.zip' -f $Iterations)
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-C',$Repo,'archive','--format=zip',('-o'+$GitArchive),'HEAD'))
                        if(($Iterations%3)-eq 0){$NativeChildren+=,(Invoke-TrackedProcess $Tool @('-C',$Repo,'reset','--hard','HEAD~1'))}
                        if($Iterations -gt 2){Remove-Item (Join-Path $LeadRoot ('worktree_{0:D4}.zip' -f ($Iterations-2))) -Force -ErrorAction SilentlyContinue}
                    }
                    'S06' {
                        $Out=Join-Path $LeadRoot ('etl_{0:D4}' -f $Iterations);$NativeChildren+=,(Invoke-TrackedProcess $Tool @((Join-Path $Assets 'etl.py'),$Source,$Out));$FilesTouched+=128
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('etl_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S07' {
                        $Out=Join-Path $LeadRoot ('tone_{0:D4}.wav' -f $Iterations)
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-hide_banner','-loglevel','error','-f','lavfi','-i',("sine=frequency="+(500+$Iterations%500)+":duration=1"),'-y',$Out));$FilesTouched++
                        if($Iterations -gt 3){Remove-Item (Join-Path $LeadRoot ('tone_{0:D4}.wav' -f ($Iterations-3))) -Force -ErrorAction SilentlyContinue}
                    }
                    'S08' {
                        $Db=Join-Path $Assets 'scenario.db';$Backup=Join-Path $LeadRoot ('backup_{0:D4}.db' -f $Iterations);Remove-Item $Backup -Force -ErrorAction SilentlyContinue
                        $Sql="INSERT INTO t(v) VALUES('run_$Iterations'); UPDATE t SET v='updated_$Iterations' WHERE id=(SELECT max(id) FROM t); DELETE FROM t WHERE id < (SELECT max(id)-100 FROM t); VACUUM INTO '$($Backup.Replace('\','/'))';"
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @($Db,$Sql));$FilesTouched+=2
                        if($Iterations -gt 2){Remove-Item (Join-Path $LeadRoot ('backup_{0:D4}.db' -f ($Iterations-2))) -Force -ErrorAction SilentlyContinue}
                    }
                    'S09' {
                        $OutDir=Join-Path $LeadRoot ('export_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $OutDir -Force|Out-Null
                        foreach($Html in @(Get-ChildItem -LiteralPath $Assets -Filter 'document_*.html' -File|Sort-Object Name)){
                            $NativeChildren+=,(Invoke-TrackedProcess $Tool @('--headless','--convert-to','pdf','--outdir',$OutDir,$Html.FullName));$FilesTouched++
                        }
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('export_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S10' {
                        $Build=Join-Path $LeadRoot ('build_{0:D4}' -f $Iterations)
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-S',(Join-Path $Assets 'cmake_project'),'-B',$Build,'-G','Ninja'));$FilesTouched+=8
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('build_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S11' {
                        $Proj=Join-Path $Assets 'ninja_project';Remove-Item (Join-Path $Proj 'output.bin') -Force -ErrorAction SilentlyContinue
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-C',$Proj,'-f','build.ninja','-j','4'));$FilesTouched++
                        if(Test-Path (Join-Path $Proj 'output.bin')){Copy-Item (Join-Path $Proj 'output.bin') (Join-Path $LeadRoot ('artifact_{0:D4}.bin' -f $Iterations)) -Force}
                    }
                    'S12' {
                        $Input=Join-Path $Source 'set_00\file_000.bin';$Cab=Join-Path $LeadRoot ('pkg_{0:D4}.cab' -f $Iterations);$Out=Join-Path $LeadRoot ('x_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @($Input,$Cab))
                        $Expand=Resolve-Executable @('expand.exe') @('C:\Windows\System32\expand.exe');Assert-True (-not [string]::IsNullOrWhiteSpace($Expand)) 'EXPAND_NOT_FOUND'
                        $NativeChildren+=,(Invoke-TrackedProcess $Expand @($Cab,'-F:*',$Out));$FilesTouched+=2
                    }
                    'S13' {
                        $Out=Join-Path $LeadRoot ('rewrite_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('/d','/c',(Join-Path $Assets 'rewrite.cmd'),(Join-Path $Assets 'rewrite.txt'),$Out));$FilesTouched+=3
                        if($Iterations -gt 2){Remove-Item (Join-Path $LeadRoot ('rewrite_{0:D4}' -f ($Iterations-2))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S14' {
                        $Info=Get-Content -LiteralPath (Join-Path $Assets 'msi_candidate.json') -Raw|ConvertFrom-Json
                        $Out=Join-Path $LeadRoot ('admin_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('/a',[string]$Info.msi_path,'/qn','/norestart',("TARGETDIR="+$Out)) @(0,3010));$FilesTouched++
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('admin_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                    'S15' {
                        $Out=Join-Path $LeadRoot ('io_{0:D4}' -f $Iterations);New-Item -ItemType Directory -Path $Out -Force|Out-Null
                        $Cmd="`$p='"+($Out+'\large.bin').Replace("'","''")+"';`$b=New-Object byte[] (8MB);[IO.File]::WriteAllBytes(`$p,`$b);Copy-Item `$p '"+($Out+'\copy.bin').Replace("'","''")+"';Rename-Item '"+($Out+'\copy.bin').Replace("'","''")+"' rotated.bin;Compress-Archive -Path '"+($Out+'\*').Replace("'","''")+"' -DestinationPath '"+($Out+'\data.zip').Replace("'","''")+"' -Force;Remove-Item '"+($Out+'\rotated.bin').Replace("'","''")+"' -Force"
                        $NativeChildren+=,(Invoke-TrackedProcess $Tool @('-NoLogo','-NoProfile','-NonInteractive','-Command',$Cmd));$FilesTouched+=4;$BytesTouched+=8388608
                        if($Iterations -gt 1){Remove-Item (Join-Path $LeadRoot ('io_{0:D4}' -f ($Iterations-1))) -Recurse -Force -ErrorAction SilentlyContinue}
                    }
                }
                $IterationSeconds=$Sw.Elapsed.TotalSeconds-$IterationStartSeconds
                $IterationReserveSeconds=[Math]::Max($IterationReserveSeconds,($IterationSeconds*1.5)+1.0)
            }
        }
        $RemainMs=[int][Math]::Ceiling(([double]$DurationSeconds-$Sw.Elapsed.TotalSeconds)*1000)
        if($RemainMs -gt 0){Start-Sleep -Milliseconds $RemainMs}
        $Sw.Stop()
        Write-Json $ReceiptPath ([ordered]@{schema_version='1.0';status='PASS';scenario_id=$ScenarioID;task_kind=$TaskKind;task_pid=$TaskPid;parent_pid=$ParentPid;process_name='powershell.exe';active_duration_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3);task_lifecycle_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3);elapsed_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3);iterations=$Iterations;files_touched=$FilesTouched;bytes_touched=$BytesTouched;native_children=$NativeChildren;timestamp=[DateTime]::UtcNow.ToString('o')})
        exit 0
    }catch{
        $DeadlineMessage=[string]$_.Exception.Message
        $Sw.Stop()
        if($DeadlineMessage -like 'ACTIVE_WINDOW_COMPLETE*'){
            $Actual=[Math]::Round($Sw.Elapsed.TotalSeconds,3)
            Assert-True ($Actual -ge $DurationSeconds -and $Actual -le ($DurationSeconds+5.0)) ('DEADLINE_TERMINATION_DURATION_OUT_OF_RANGE:'+$Actual)
            if($null -ne $Script:DeadlineNativeChild){$NativeChildren+=,$Script:DeadlineNativeChild}
            Write-Json $ReceiptPath ([ordered]@{schema_version='1.1';status='PASS';scenario_id=$ScenarioID;task_kind=$TaskKind;task_pid=$TaskPid;parent_pid=$ParentPid;process_name='powershell.exe';active_duration_seconds=$Actual;task_lifecycle_seconds=$Actual;elapsed_seconds=$Actual;iterations=$Iterations;files_touched=$FilesTouched;bytes_touched=$BytesTouched;native_children=$NativeChildren;deadline_enforced=$true;deadline_reason=$DeadlineMessage;timestamp=[DateTime]::UtcNow.ToString('o')})
            exit 0
        }
        $FailProcessPath=$null
        $FailArguments=$null
        $FailExitCode=$null
        $FailStdoutTail=$null
        $FailStderrTail=$null
        $FailStdoutPath=$null
        $FailStderrPath=$null
        try{$FailProcessPath=[string]$_.Exception.Data['ProcessPath']}catch{}
        try{$FailArguments=[string]$_.Exception.Data['Arguments']}catch{}
        try{$FailExitCode=$_.Exception.Data['ExitCode']}catch{}
        try{$FailStdoutTail=[string]$_.Exception.Data['StdoutTail']}catch{}
        try{$FailStderrTail=[string]$_.Exception.Data['StderrTail']}catch{}
        try{$FailStdoutPath=[string]$_.Exception.Data['StdoutPath']}catch{}
        try{$FailStderrPath=[string]$_.Exception.Data['StderrPath']}catch{}
        try{
            Write-Json $ReceiptPath ([ordered]@{
                schema_version='2.0'
                status='FAIL'
                scenario_id=$ScenarioID
                scenario_name=$Meta.scenario_name
                lead_application=$Meta.lead_application
                task_kind=$TaskKind
                task_pid=$TaskPid
                parent_pid=$ParentPid
                error=$_.Exception.Message
                failing_process_path=$FailProcessPath
                failing_arguments=$FailArguments
                failing_exit_code=$FailExitCode
                failing_stdout_tail=$FailStdoutTail
                failing_stderr_tail=$FailStderrTail
                failing_stdout_path=$FailStdoutPath
                failing_stderr_path=$FailStderrPath
                elapsed_seconds=[Math]::Round($Sw.Elapsed.TotalSeconds,3)
                timestamp=[DateTime]::UtcNow.ToString('o')
            })
        }catch{}
        Write-Error $_.Exception.Message;exit 1
    }
}

# Run mode: root coordinates three concurrent branches and emits V6-compatible process-scope fields.
# SCENARIO_RUN_FAILURE_ENVELOPE_V9
$RootPid=[Diagnostics.Process]::GetCurrentProcess().Id
$RootStart=[DateTime]::UtcNow
$Children=@()
$TimedOutTask=$null
$TimedOutTaskPid=0
$DispatcherDeadlineUtc=$null
$DeadlineEventUtc=$null
$PowerShellExe=$null
$ScriptPath=$MyInvocation.MyCommand.Path
try{
    Assert-True (Test-Path -LiteralPath $Source -PathType Container) 'SOURCE_FIXTURE_MISSING'
    $PowerShellExe=Resolve-Executable @('powershell.exe') @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    Assert-True (-not [string]::IsNullOrWhiteSpace($PowerShellExe)) 'POWERSHELL_NOT_FOUND'
    foreach($Kind in @('Lead','Mutation','Rotation')){
        $Base=$Kind.ToLowerInvariant()
        $TR=Join-Path $TaskReceipts ($Base+'.json')
        $TSO=Join-Path $TaskReceipts ($Base+'.stdout.txt')
        $TSE=Join-Path $TaskReceipts ($Base+'.stderr.txt')
        $Args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$ScriptPath,'-Mode','Task','-ScenarioID',$ScenarioID,'-Repetition',$Repetition,'-AttemptID',$AttemptID,'-ReceiptPath',$TR,'-WorkRoot',$WorkRoot,'-DurationSeconds',[string]$DurationSeconds,'-FixtureSeed',$FixtureSeed,'-TaskKind',$Kind,'-ParentPid',[string]$RootPid)
        $P=Start-Process -FilePath $PowerShellExe -ArgumentList $Args -PassThru -WindowStyle Hidden -RedirectStandardOutput $TSO -RedirectStandardError $TSE
        $Children+=,[pscustomobject]@{kind=$Kind;pid=[int]$P.Id;process=$P;receipt=$TR;stdout=$TSO;stderr=$TSE}
    }
    # SCENARIO_DISPATCHER_CHILD_WATCHDOG_V20
    # Keep the existing inner orchestration deadline. The outer adapter now allows
    # additional diagnostic/cleanup grace; scientific duration gates remain unchanged.
    $DispatcherDeadlineUtc=$RootStart.AddSeconds($DurationSeconds+2)
    # V33_CONCURRENT_CHILD_WATCHDOG: observe every branch against one root-clock deadline.
    # Sequential waits allowed later branches to overrun and exit before they were inspected.
    while($true){
        $AliveCount=0
        foreach($WatchChild in $Children){try{if(-not $WatchChild.process.HasExited){$AliveCount++}}catch{}}
        if($AliveCount -eq 0 -or [DateTime]::UtcNow -ge $DispatcherDeadlineUtc){break}
        Start-Sleep -Milliseconds 100
    }
    # Capture the scientific end event before descendant inventory, termination,
    # WaitForExit, and receipt-writing cleanup. Those operations remain observable
    # but must not inflate the measured workload/root scientific lifecycle.
    $DeadlineEventUtc=[DateTime]::UtcNow
    $DeadlineEventActual=[Math]::Round(($DeadlineEventUtc-$RootStart).TotalSeconds,3)
    foreach($C in $Children){
        $WaitOk=$false
        try{$WaitOk=[bool]$C.process.HasExited}catch{}
        if(-not $WaitOk){
            $TimedOutTask=[string]$C.kind
            $TimedOutTaskPid=[int]$C.pid
            # Use the common watchdog event timestamp; per-child diagnostics must not extend scientific duration.
            $Actual=$DeadlineEventActual
            Assert-True ($Actual -ge $DurationSeconds -and $Actual -le ($DurationSeconds+5.0)) ('PARENT_DEADLINE_DURATION_OUT_OF_RANGE:'+$Actual)
            $DeadlineNativeChildren=@()
            $NativeJournal=Join-Path (Join-Path $WorkRoot 'NativeDiagnostics') ('native_children_'+$TimedOutTaskPid+'.jsonl')
            if(Test-Path -LiteralPath $NativeJournal){
                foreach($Line in @(Get-Content -LiteralPath $NativeJournal -ErrorAction SilentlyContinue)){
                    if(-not [string]::IsNullOrWhiteSpace($Line)){try{$DeadlineNativeChildren+=,($Line|ConvertFrom-Json)}catch{}}
                }
            }
            try{
                $ProcessSnapshot=@(Get-CimInstance Win32_Process -ErrorAction Stop)
                $DescendantIds=New-Object 'System.Collections.Generic.HashSet[int]'
                [void]$DescendantIds.Add($TimedOutTaskPid)
                $Changed=$true
                while($Changed){
                    $Changed=$false
                    foreach($Proc in $ProcessSnapshot){
                        if($DescendantIds.Contains([int]$Proc.ParentProcessId) -and -not $DescendantIds.Contains([int]$Proc.ProcessId)){
                            [void]$DescendantIds.Add([int]$Proc.ProcessId);$Changed=$true
                        }
                    }
                }
                foreach($Proc in $ProcessSnapshot){
                    $ProcId=[int]$Proc.ProcessId
                    if($ProcId -ne $TimedOutTaskPid -and $DescendantIds.Contains($ProcId)){
                        $DeadlineNativeChildren+=,[ordered]@{pid=$ProcId;parent_pid=[int]$Proc.ParentProcessId;process_name=[string]$Proc.Name;process_path=[string]$Proc.ExecutablePath;arguments=@([string]$Proc.CommandLine);exit_code=-1;termination='ACTIVE_WINDOW_PARENT_DEADLINE'}
                    }
                }
            }catch{}
            $DeadlineNativeChildren=@($DeadlineNativeChildren|Group-Object {[int]$_.pid}|ForEach-Object {$_.Group[0]})
            $TaskKill=Join-Path $env:SystemRoot 'System32\taskkill.exe'
            try{& $TaskKill /PID $C.pid /T /F 2>$null | Out-Null}catch{}
            try{if(-not$C.process.HasExited){$C.process.Kill()}}catch{}
            try{[void]$C.process.WaitForExit(3000)}catch{}
            Write-Json $C.receipt ([ordered]@{schema_version='1.2';status='PASS';scenario_id=$ScenarioID;task_kind=$C.kind;task_pid=[int]$C.pid;parent_pid=$RootPid;process_name='powershell.exe';active_duration_seconds=$Actual;task_lifecycle_seconds=$Actual;elapsed_seconds=$Actual;iterations=$null;files_touched=$null;bytes_touched=$null;native_children=$DeadlineNativeChildren;deadline_enforced=$true;deadline_owner='SCENARIO_DISPATCHER_PARENT';termination='PROCESS_TREE_TERMINATED_AT_ACTIVE_DEADLINE';timestamp=[DateTime]::UtcNow.ToString('o')})
            $C | Add-Member -NotePropertyName deadline_terminated -NotePropertyValue $true -Force
        }else{
            $C | Add-Member -NotePropertyName deadline_terminated -NotePropertyValue $false -Force
            Assert-True ([int]$C.process.ExitCode -eq 0) ('TASK_EXIT_NONZERO:'+$C.kind+':'+$C.process.ExitCode)
        }
    }

    $RootEnd=[DateTime]::UtcNow
    $TaskData=@();$Pids=@($RootPid);$Names=@('powershell.exe');$Instances=@([ordered]@{pid=$RootPid;parent_pid=$null;process_name='powershell.exe';role='workload_root'});$Edges=@();$Elapsed=@()
    foreach($C in $Children){
        $T=Get-Content -LiteralPath $C.receipt -Raw|ConvertFrom-Json
        Assert-True ([string]$T.status -eq 'PASS') ('TASK_RECEIPT_FAIL:'+$C.kind)
        $TaskData+=,$T;$Elapsed+=[double]$T.active_duration_seconds;$Pids+=[int]$T.task_pid
        $Instances+=,[ordered]@{pid=[int]$T.task_pid;parent_pid=$RootPid;process_name='powershell.exe';role=('task_'+$C.kind.ToLowerInvariant())}
        $Edges+=,[ordered]@{parent_pid=$RootPid;child_pid=[int]$T.task_pid;relationship='root_to_task';task_name=$C.kind.ToLowerInvariant()}
        foreach($N in @($T.native_children)){if($null-ne$N -and [int]$N.pid -gt 0){$Pids+=[int]$N.pid;$Names+=[string]$N.process_name;$Instances+=,[ordered]@{pid=[int]$N.pid;parent_pid=[int]$T.task_pid;process_name=[string]$N.process_name;role='native_child'};$Edges+=,[ordered]@{parent_pid=[int]$T.task_pid;child_pid=[int]$N.pid;relationship='task_to_native';process_name=[string]$N.process_name}}}
    }
    $Active=[Math]::Round(($Elapsed|Measure-Object -Maximum).Maximum,3)
    $HadDeadlineTermination=@($Children|Where-Object {[bool]$_.deadline_terminated}).Count -gt 0
    $ScientificRootEnd=if($null-ne$DeadlineEventUtc){$DeadlineEventUtc}else{$RootEnd}
    $Lifecycle=[Math]::Round(($ScientificRootEnd-$RootStart).TotalSeconds,3)
    $OrchestrationLifecycle=[Math]::Round(($RootEnd-$RootStart).TotalSeconds,3)
    $PostDeadlineCleanup=[Math]::Round([Math]::Max(0.0,$OrchestrationLifecycle-$Lifecycle),3)
    Assert-True ($Active -ge $DurationSeconds -and $Active -le ($DurationSeconds+5.0)) ('ACTIVE_DURATION_OUT_OF_RANGE:'+$Active)
    Assert-True ($Lifecycle -le ($DurationSeconds+10.0)) ('ROOT_LIFECYCLE_EXCESSIVE:'+$Lifecycle)
    Write-Json $ReceiptPath ([ordered]@{
        schema_version='3.1';gate='SCENARIO_WORKLOAD_RUN';status='PASS';AttemptID=$AttemptID;os='Windows';class='BENIGN';ground_truth='BENIGN';
        scenario_id=$ScenarioID;scenario_name=$Meta.scenario_name;scenario_type='application_led_compound_benign';lead_application=$Meta.lead_application;repetition=$Repetition;fixture_seed=$FixtureSeed;
        active_duration_target_seconds=$DurationSeconds;active_duration_tolerance_seconds=5.0;active_duration_seconds=$Active;root_lifecycle_seconds=$Lifecycle;
        orchestration_lifecycle_seconds=$OrchestrationLifecycle;post_deadline_cleanup_seconds=$PostDeadlineCleanup;
        root_pid=$RootPid;root_process_name='powershell.exe';process_start_utc=$RootStart.ToString('o');process_end_utc=$RootEnd.ToString('o');process_exit_code=0;
        process_termination_method='SELF_EXIT';child_pid_absence_verified=$true;execution_complete=$true;observation_status='COMPLETE';
        compound_task_count=$TaskData.Count;task_receipts=$TaskData;target_pids=@($Pids|Sort-Object -Unique);process_names=@($Names|Sort-Object -Unique);process_instances=$Instances;process_tree_edges=$Edges;
        operation_families=$Meta.operation_families;network_used=$false;timestamp=[DateTime]::UtcNow.ToString('o')
    })
    Write-Host ("SCENARIO_RUN=PASS OS=Windows SCENARIO=$ScenarioID LEAD="+$Meta.lead_application+" ROOT_PID=$RootPid ACTIVE_DURATION=$Active")
    exit 0
}catch{
    $RunError=$_.Exception.Message
    $FailureTask=$TimedOutTask
    $FailProcessPath=$null
    $FailArguments=$null
    $FailExitCode=$null
    $FailStdoutTail=$null
    $FailStderrTail=$null
    $FailTaskReceiptPath=$null
    $FailTaskStdoutPath=$null
    $FailTaskStderrPath=$null

    # SCENARIO_DISPATCHER_STOP_ALL_BEFORE_WAIT_V21
    # Stop all still-running task children first, then wait; this bounds cleanup
    # to one shared process-termination interval instead of serial 5-second waits.
    foreach($C in $Children){
        try{
            if(-not $C.process.HasExited){
                Stop-Process -Id $C.pid -Force -ErrorAction SilentlyContinue
            }
        }catch{}
    }
    foreach($C in $Children){
        try{[void]$C.process.WaitForExit(5000)}catch{}
    }

    if($TimedOutTask){
        $TimeoutChildren=@($Children|Where-Object{$_.kind -ceq $TimedOutTask})
        if($TimeoutChildren.Count -eq 1){
            $FailTaskReceiptPath=[string]$TimeoutChildren[0].receipt
            $FailTaskStdoutPath=[string]$TimeoutChildren[0].stdout
            $FailTaskStderrPath=[string]$TimeoutChildren[0].stderr
            $TimeoutCandidate=$null
            if(Test-Path -LiteralPath $FailTaskReceiptPath -PathType Leaf){
                try{$TimeoutCandidate=Get-Content -LiteralPath $FailTaskReceiptPath -Raw|ConvertFrom-Json}catch{}
            }
            if($null -ne $TimeoutCandidate){
                try{$FailProcessPath=[string]$TimeoutCandidate.failing_process_path}catch{}
                try{$FailArguments=[string]$TimeoutCandidate.failing_arguments}catch{}
                try{$FailExitCode=$TimeoutCandidate.failing_exit_code}catch{}
                try{$FailStdoutTail=[string]$TimeoutCandidate.failing_stdout_tail}catch{}
                try{$FailStderrTail=[string]$TimeoutCandidate.failing_stderr_tail}catch{}
            }
        }
    }

    foreach($C in $Children){
        $Candidate=$null
        if(Test-Path -LiteralPath $C.receipt -PathType Leaf){
            try{$Candidate=Get-Content -LiteralPath $C.receipt -Raw|ConvertFrom-Json}catch{}
        }
        if($null -eq $FailureTask -and $null-ne$Candidate -and [string]$Candidate.status -eq 'FAIL'){
            $FailureTask=[string]$C.kind
            $FailTaskReceiptPath=[string]$C.receipt
            $FailTaskStdoutPath=[string]$C.stdout
            $FailTaskStderrPath=[string]$C.stderr
            try{$FailProcessPath=[string]$Candidate.failing_process_path}catch{}
            try{$FailArguments=[string]$Candidate.failing_arguments}catch{}
            try{$FailExitCode=$Candidate.failing_exit_code}catch{}
            try{$FailStdoutTail=[string]$Candidate.failing_stdout_tail}catch{}
            try{$FailStderrTail=[string]$Candidate.failing_stderr_tail}catch{}
        }
        if($null -eq $FailureTask -and $C.process.HasExited -and [int]$C.process.ExitCode -ne 0){
            $FailureTask=[string]$C.kind
            $FailTaskReceiptPath=[string]$C.receipt
            $FailTaskStdoutPath=[string]$C.stdout
            $FailTaskStderrPath=[string]$C.stderr
        }
    }

    if($FailTaskStdoutPath){
        try{
            $Raw=[IO.File]::ReadAllText($FailTaskStdoutPath)
            if($Raw.Length -gt 4096){$Raw=$Raw.Substring($Raw.Length-4096)}
            if([string]::IsNullOrWhiteSpace($FailStdoutTail)){$FailStdoutTail=$Raw}
        }catch{}
    }
    if($FailTaskStderrPath){
        try{
            $Raw=[IO.File]::ReadAllText($FailTaskStderrPath)
            if($Raw.Length -gt 4096){$Raw=$Raw.Substring($Raw.Length-4096)}
            if([string]::IsNullOrWhiteSpace($FailStderrTail)){$FailStderrTail=$Raw}
        }catch{}
    }

    $RootEnd=[DateTime]::UtcNow

    # Scalar-only envelope: no nested PSObject serialization dependency.
    try{
        Write-Json $ReceiptPath ([ordered]@{
            schema_version='4.0'
            gate='SCENARIO_WORKLOAD_RUN'
            status='FAIL'
            AttemptID=$AttemptID
            os='Windows'
            class='BENIGN'
            ground_truth='BENIGN'
            scenario_id=$ScenarioID
            scenario_name=$Meta.scenario_name
            scenario_type='application_led_compound_benign'
            lead_application=$Meta.lead_application
            repetition=$Repetition
            fixture_seed=$FixtureSeed
            root_pid=$RootPid
            root_process_name='powershell.exe'
            process_start_utc=$RootStart.ToString('o')
            process_end_utc=$RootEnd.ToString('o')
            process_exit_code=1
            execution_complete=$false
            observation_status='FAILED'
            error=$RunError
            failing_task_kind=$FailureTask
            failing_task_pid=$TimedOutTaskPid
            dispatcher_watchdog_seconds=$DurationSeconds+2
            dispatcher_deadline_utc=$(if($null -ne $DispatcherDeadlineUtc){$DispatcherDeadlineUtc.ToString('o')}else{$null})
            failing_process_path=$FailProcessPath
            failing_arguments=$FailArguments
            failing_exit_code=$FailExitCode
            failing_stdout_tail=$FailStdoutTail
            failing_stderr_tail=$FailStderrTail
            failing_task_receipt_path=$FailTaskReceiptPath
            failing_task_stdout_path=$FailTaskStdoutPath
            failing_task_stderr_path=$FailTaskStderrPath
            network_used=$false
            timestamp=[DateTime]::UtcNow.ToString('o')
        })
    }catch{
        # Last-resort plain text fallback at the exact receipt path.
        try{
            $Fallback='status=FAIL'+"`r`n"+'error='+$RunError+"`r`n"+'task='+$FailureTask+"`r`n"+'process='+$FailProcessPath+"`r`n"+'exit='+[string]$FailExitCode+"`r`n"+'args='+$FailArguments+"`r`n"+'stdout='+$FailStdoutTail+"`r`n"+'stderr='+$FailStderrTail+"`r`n"
            [IO.File]::WriteAllText($ReceiptPath+'.fallback.txt',$Fallback,(New-Object Text.UTF8Encoding($false)))
        }catch{}
    }

    $Message='SCENARIO_RUN_FAIL:'+ $RunError
    if($FailureTask){$Message+=' task='+$FailureTask}
    if($TimedOutTaskPid -gt 0){$Message+=' task_pid='+[string]$TimedOutTaskPid}
    if($FailProcessPath){$Message+=' process='+$FailProcessPath}
    if($null-ne$FailExitCode){$Message+=' exit='+[string]$FailExitCode}
    if($FailArguments){$Message+=' args='+$FailArguments}
    if($FailStdoutTail){$Message+=' stdout='+($FailStdoutTail -replace '[\r\n]+',' ')}
    if($FailStderrTail){$Message+=' stderr='+($FailStderrTail -replace '[\r\n]+',' ')}
    Write-Error $Message
    exit 1
}

