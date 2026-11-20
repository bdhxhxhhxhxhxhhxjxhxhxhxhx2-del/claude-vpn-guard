#Requires -Version 5.1
<#
Claude VPN Guard v2 - 自动补登记（计划任务）安装工具（Windows PowerShell 5.1）

作用：
  1. 把防护脚本和日常启动器复制到 C:\ProgramData\ClaudeVpnGuardV2，这个目录只有管理员和系统能修改；
  2. 注册计划任务 \ClaudeVpnGuardV2\AutoSync：以系统身份，在登录 2 分钟后、以及之后每 30 分钟，
     运行一次「同步程序清单」，把 Claude 更新后的新程序登记进防火墙规则。
计划任务只同步程序清单：不改变防护开关（关着的仍然关着），没有规则时也不会创建规则。
它在本机运行，不调用 Claude、不联网，不消耗 token。

用法：
  双击「安装自动补登记.cmd」：安装或更新（覆盖已安装的脚本，重新注册任务），装好后立即运行一次并核对结果。
  双击「卸载自动补登记.cmd」：删除计划任务和安装目录；防护规则不受影响。
  powershell -NoProfile -ExecutionPolicy Bypass -File AutoSync.ps1 -Action Status   查看安装状态（只读）
  powershell -NoProfile -ExecutionPolicy Bypass -File AutoSync.ps1 -Action DryRun   预演（只读，不做任何修改）

注意：脚本里的中文只用于显示。文件须保存为带 BOM 的 UTF-8，否则中文会显示成乱码（不影响逻辑）。
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Status', 'DryRun')]
    [string]$Action = 'Status',
    [switch]$Worker,
    [string]$RunId = ''
)

$ErrorActionPreference = 'Stop'

# Guard.ps1 也有 -Action、-Worker、-RunId 参数：引用它之前，先把本脚本的参数和调用信息另存。
$asAction = $Action
$asWorker = [bool]$Worker
$asRunId = $RunId
$asInvocation = $MyInvocation.InvocationName
$asScriptPath = $PSCommandPath
$asSourceDir = $PSScriptRoot
. ($PSScriptRoot + '\Guard.ps1')

# ============================================================ 配置

$asInstallDir = $script:CvgInstallDir
$asTaskPath = $script:CvgTaskPath
$asTaskName = $script:CvgTaskName
$asMarkerName = 'installed-by-claude-vpn-guard.json'
$asFiles = @('Guard.ps1', '查看状态.cmd', '开启防护.cmd', '关闭防护.cmd', '卸载防护.cmd', '使用说明.md')
$asIntervalMinutes = 30
$asLogonDelayMinutes = 2
$asPowerShell = $env:SystemRoot + '\System32\WindowsPowerShell\v1.0\powershell.exe'
# 计划任务的访问权限：管理员和系统完全控制；已登录用户只能查看（不能修改，也不能手动运行），
# 这样「查看状态」以普通权限也能读到它上次和下次运行的时间。写法与 Windows 自带任务相同。
$asTaskSddl = 'D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)'

# ============================================================ 辅助函数

function Test-AsReparse {
    # 路径本身或任一上级目录是链接（重解析点）时返回 $true。
    param([string]$Path)
    $part = [System.IO.Path]::GetFullPath($Path)
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $true }
        }
        $next = Split-Path -Parent $part
        if (-not $next -or $next -eq $part) { break }
        $part = $next
    }
    return $false
}

function Get-AsAclProblems {
    # 必须归管理员或系统所有，且只有管理员和系统能写。返回问题列表（空表示合格）。
    # 安装目录本身还必须关闭继承；目录里的文件则正常继承目录的权限（-AllowInherited），这是安全的。
    param([string]$Path, [switch]$AllowInherited)
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $privileged = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($privileged -notcontains $owner) { $problems.Add('所有者不是管理员或系统：' + $owner) }
    if (-not $AllowInherited -and -not $acl.AreAccessRulesProtected) { $problems.Add('没有关闭权限继承') }
    $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($entry in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($entry.AccessControlType -eq 'Allow' -and $privileged -notcontains $entry.IdentityReference.Value -and ($entry.FileSystemRights -band $writeMask)) {
            $problems.Add('非管理员有写权限：' + $entry.IdentityReference.Value)
        }
    }
    return $problems.ToArray()
}

function New-AsProtectedDirectory {
    # 一次性带权限创建目录（与第一版防护已验证的写法相同）：系统和管理员完全控制，普通用户只读，关闭继承。
    param([string]$Path)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($entry in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute'))) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($entry[0])
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]$entry[1], ([System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'), ([System.Security.AccessControl.PropagationFlags]::None), ([System.Security.AccessControl.AccessControlType]::Allow))
        $acl.AddAccessRule($rule)
    }
    $null = [System.IO.Directory]::CreateDirectory($Path, $acl)
}

function Get-AsTask {
    try { return (Get-ScheduledTask -TaskPath $asTaskPath -TaskName $asTaskName -ErrorAction Stop) } catch { return $null }
}

function New-AsTaskXml {
    # 计划任务定义：以系统身份运行（不弹窗口），登录后 2 分钟一次，之后每 30 分钟一次；单次最多运行 5 分钟。
    param([string]$GuardPath, [datetime]$Start)
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $GuardPath + '" -Action Sync'
    $command = [System.Security.SecurityElement]::Escape($asPowerShell)
    $escapedArguments = [System.Security.SecurityElement]::Escape($arguments)
    $startText = $Start.ToString('yyyy-MM-ddTHH:mm:ss')
    return @"
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Claude VPN Guard v2: registers new Claude program versions in the firewall rules (sync only; never turns protection on or off). Runs locally; no network access.</Description>
    <SecurityDescriptor>$asTaskSddl</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT$($asLogonDelayMinutes)M</Delay>
    </LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>$startText</StartBoundary>
      <Repetition>
        <Interval>PT$($asIntervalMinutes)M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$command</Command>
      <Arguments>$escapedArguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

function Read-AsLogSince {
    # 读取安装目录日志里某个时间之后的记录。
    param([datetime]$Since)
    $log = Join-Path $asInstallDir 'logs\guard-log.jsonl'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in @(Get-Content -LiteralPath $log -Encoding UTF8)) {
        try {
            $o = $line | ConvertFrom-Json
            if ([datetime]$o.Time -ge $Since) { $rows.Add($o) }
        } catch { }
    }
    return $rows.ToArray()
}

# ============================================================ 安装（需要管理员）

function Invoke-AsInstall {
    $guardTarget = Join-Path $asInstallDir 'Guard.ps1'
    $createdDir = $false
    $registered = $false
    $hadTask = ($null -ne (Get-AsTask))
    try {
        Write-CvgLine '[1/5] 检查源文件和当前的 Claude 程序清单……'
        foreach ($f in $asFiles) { if (-not (Test-Path -LiteralPath (Join-Path $asSourceDir $f))) { throw ('源文件不存在：' + $f) } }
        $tokens = $null; $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $asSourceDir 'Guard.ps1'), [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count) { throw 'Guard.ps1 有语法错误，拒绝安装。' }
        $patterns = @($script:CvgProgramPatterns)
        $found = @(Get-CvgProgramPaths)
        if ($found.Count -eq 0) { throw '按当前用户的路径找不到任何 Claude 程序，拒绝安装。' }
        Write-CvgLine ('      程序路径 {0} 条，现在能找到 {1} 个 Claude 程序' -f $patterns.Count, $found.Count)

        Write-CvgLine ('[2/5] 准备受保护的安装目录 {0}……' -f $asInstallDir)
        if (Test-AsReparse $asInstallDir) { throw '安装目录或它的上级目录是链接，拒绝安装。' }
        if (Test-Path -LiteralPath $asInstallDir) {
            if (-not (Test-Path -LiteralPath (Join-Path $asInstallDir $asMarkerName))) { throw '安装目录已经存在，但不是本工具创建的（没有标记文件），拒绝覆盖。请检查后手动处理。' }
            $problems = @(Get-AsAclProblems $asInstallDir)
            if ($problems.Count) { throw ('安装目录的权限不安全：' + ($problems -join '；')) }
            Write-CvgLine '      目录已存在，是本工具之前安装的，将更新其中的文件'
        } else {
            New-AsProtectedDirectory $asInstallDir
            $createdDir = $true
            if (Test-AsReparse $asInstallDir) { throw '新建的安装目录是链接，拒绝继续。' }
            $problems = @(Get-AsAclProblems $asInstallDir)
            if ($problems.Count) { throw ('安装目录的权限没有按预期设置：' + ($problems -join '；')) }
            Write-CvgLine '      已创建：系统和管理员完全控制，普通用户只读'
        }

        Write-CvgLine '[3/5] 复制文件并核对……'
        foreach ($f in $asFiles) { Copy-Item -LiteralPath (Join-Path $asSourceDir $f) -Destination (Join-Path $asInstallDir $f) -Force }
        $stateSource = Join-Path $asSourceDir 'state\probe-passed.json'
        if (Test-Path -LiteralPath $stateSource) {
            $stateDir = Join-Path $asInstallDir 'state'
            if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
            Copy-Item -LiteralPath $stateSource -Destination (Join-Path $stateDir 'probe-passed.json') -Force
        }
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $config = [ordered]@{ Schema = 1; ProgramPatterns = $patterns; InstalledAt = (Get-Date).ToString('o'); InstalledFrom = $asSourceDir }
        [System.IO.File]::WriteAllText((Join-Path $asInstallDir 'config.json'), ($config | ConvertTo-Json -Depth 4), $encoding)
        $guardHash = (Get-FileHash -LiteralPath (Join-Path $asSourceDir 'Guard.ps1') -Algorithm SHA256).Hash
        $marker = [ordered]@{ Tool = 'ClaudeVpnGuardV2'; InstalledAt = (Get-Date).ToString('o'); GuardSha256 = $guardHash }
        [System.IO.File]::WriteAllText((Join-Path $asInstallDir $asMarkerName), ($marker | ConvertTo-Json), $encoding)
        foreach ($f in $asFiles) {
            $a = (Get-FileHash -LiteralPath (Join-Path $asSourceDir $f) -Algorithm SHA256).Hash
            $b = (Get-FileHash -LiteralPath (Join-Path $asInstallDir $f) -Algorithm SHA256).Hash
            if ($a -ne $b) { throw ('复制后内容不一致：' + $f) }
        }
        foreach ($f in @($asFiles) + @('config.json', $asMarkerName)) {
            $problems = @(Get-AsAclProblems (Join-Path $asInstallDir $f) -AllowInherited)
            if ($problems.Count) { throw ('安装后的 ' + $f + ' 权限不安全：' + ($problems -join '；')) }
        }
        Write-CvgLine ('      已复制 {0} 个文件，内容与源文件一致；写入安装时的程序路径（config.json）' -f $asFiles.Count)

        Write-CvgLine '[4/5] 注册计划任务……'
        $xml = New-AsTaskXml -GuardPath $guardTarget -Start ((Get-Date).AddMinutes(5))
        Register-ScheduledTask -TaskName $asTaskName -TaskPath $asTaskPath -Xml $xml -User 'NT AUTHORITY\SYSTEM' -Force | Out-Null
        $registered = $true
        $task = Get-AsTask
        if ($null -eq $task) { throw '计划任务注册后读不到。' }
        $taskAction = @($task.Actions)[0]
        if ([string]$taskAction.Execute -ine $asPowerShell -or [string]$taskAction.Arguments -notlike ('*"' + $guardTarget + '"*-Action Sync*')) { throw '计划任务的运行内容与预期不符。' }
        if ([string]$task.Principal.UserId -notmatch '(?i)^(NT AUTHORITY\\)?SYSTEM$|^S-1-5-18$') { throw ('计划任务的运行身份不是系统：' + [string]$task.Principal.UserId) }
        if ([string]$task.Principal.RunLevel -ne 'Highest') { throw '计划任务没有以最高权限运行。' }
        if (@($task.Triggers).Count -ne 2) { throw '计划任务的触发条件与预期不符。' }
        Write-CvgLine ('      已注册 {0}{1}：以系统身份，登录 {2} 分钟后运行，之后每 {3} 分钟运行一次' -f $asTaskPath, $asTaskName, $asLogonDelayMinutes, $asIntervalMinutes)
        # Register-ScheduledTask 会忽略任务定义里的 SecurityDescriptor，这里注册后再显式设置一次并读回核对。
        # 设置失败不影响补登记本身，只是「查看状态」以普通权限看不到下次运行时间，所以只提示、不中止。
        try {
            $service = New-Object -ComObject 'Schedule.Service'
            $service.Connect()
            $registeredTask = $service.GetFolder($asTaskPath.TrimEnd('\')).GetTask($asTaskName)
            $registeredTask.SetSecurityDescriptor($asTaskSddl, 0)
            $applied = [string]$registeredTask.GetSecurityDescriptor(4)
            if ($applied -match '\(A;[^;]*;[^;]*;;;AU\)') { Write-CvgLine '      访问权限：已登录用户可以查看任务状态（不能修改，也不能手动运行）' }
            else { Write-CvgLine ('      访问权限：设置后读回的权限里没有已登录用户（{0}），「查看状态」将只显示日志里的补登记记录' -f $applied) 'warn' }
        } catch {
            Write-CvgLine ('      访问权限：设置失败（{0}），「查看状态」将只显示日志里的补登记记录' -f $_.Exception.Message) 'warn'
        }
    } catch {
        $err = $_
        Write-CvgLine ('安装没有完成：' + $err.Exception.Message) 'err'
        if ($registered -and -not $hadTask) {
            try { Unregister-ScheduledTask -TaskPath $asTaskPath -TaskName $asTaskName -Confirm:$false; Write-CvgLine '已撤销本次注册的计划任务。' 'warn' } catch { Write-CvgLine ('撤销计划任务时出错：' + $_.Exception.Message) 'err' }
        }
        if ($createdDir) {
            try { Remove-Item -LiteralPath $asInstallDir -Recurse -Force; Write-CvgLine '已删除本次创建的安装目录。' 'warn' } catch { Write-CvgLine ('删除安装目录时出错：' + $_.Exception.Message) 'err' }
        }
        throw $err
    }

    # ---------- 立即运行一次，确认它能以系统身份正常工作（失败只报告，不撤销安装）
    Write-CvgLine '[5/5] 立即运行一次，确认它能以系统身份正常补登记……'
    $before = (Get-Date).AddSeconds(-2)
    Start-ScheduledTask -TaskPath $asTaskPath -TaskName $asTaskName
    $finished = $false
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Seconds 1
        $task = Get-AsTask
        $info = $task | Get-ScheduledTaskInfo
        if ([string]$task.State -ne 'Running' -and $info.LastRunTime -ge $before) { $finished = $true; break }
    }
    $info = Get-AsTask | Get-ScheduledTaskInfo
    $entries = @(Read-AsLogSince $before)
    $syncEntry = @($entries | Where-Object { $_.Event -eq 'sync' }) | Select-Object -Last 1
    $errorEntry = @($entries | Where-Object { $_.Event -eq 'error' }) | Select-Object -Last 1
    $code = [int64]$info.LastTaskResult
    Write-CvgLine ''
    if (-not $finished) {
        Write-CvgLine '计划任务已安装，但 2 分钟内没有等到首次运行结束。稍后双击「查看状态.cmd」看「自动补登记」那一行。' 'warn'
        $script:CvgExitCode = 1
    } elseif ($code -eq 0 -and $syncEntry) {
        Write-CvgLine ('首次运行成功：新建 {0} 条，清理 {1} 条，共 {2} 条规则（防护开关保持不变）。' -f $syncEntry.Data.Created, $syncEntry.Data.Removed, $syncEntry.Data.Total) 'ok'
    } elseif ($code -eq 0 -and -not $errorEntry) {
        Write-CvgLine '首次运行正常结束。目前没有安装防护规则，所以没有需要补登记的；开启防护后它会自动工作。' 'ok'
    } else {
        $why = if ($errorEntry) { [string]$errorEntry.Data.Message } else { '代码 0x{0:X8}' -f $code }
        Write-CvgLine ('计划任务已安装，但首次运行没有成功：' + $why) 'err'
        Write-CvgLine '请把这个窗口的内容发给 Claude。' 'err'
        $script:CvgExitCode = 1
    }
    Write-CvgLine ''
    Write-CvgLine ('安装位置：{0}（只有管理员能修改）' -f $asInstallDir)
    Write-CvgLine '以后双击工作目录或安装目录里的「查看状态 / 开启防护 / 关闭防护 / 卸载防护」，都会使用安装目录里的脚本。'
    Write-CvgLine '「查看状态」里的「自动补登记」一行会显示它上次和下次运行的时间。卸载：双击工作目录里的「卸载自动补登记.cmd」。'
}

# ============================================================ 卸载（需要管理员）

function Invoke-AsUninstall {
    Write-CvgLine '[1/3] 删除计划任务……'
    if ($null -ne (Get-AsTask)) {
        Unregister-ScheduledTask -TaskPath $asTaskPath -TaskName $asTaskName -Confirm:$false
        Write-CvgLine '      已删除'
    } else {
        Write-CvgLine '      没有找到计划任务'
    }
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $service.GetFolder('\').DeleteFolder($asTaskPath.Trim('\'), 0)
    } catch { }

    Write-CvgLine ('[2/3] 删除安装目录 {0}……' -f $asInstallDir)
    if (Test-Path -LiteralPath $asInstallDir) {
        if (Test-AsReparse $asInstallDir) { throw '安装目录是链接，拒绝删除。' }
        if (-not (Test-Path -LiteralPath (Join-Path $asInstallDir $asMarkerName))) { throw '安装目录里没有本工具的标记文件，拒绝删除。' }
        $log = Join-Path $asInstallDir 'logs\guard-log.jsonl'
        if (Test-Path -LiteralPath $log) {
            $keepDir = Join-Path $asSourceDir 'logs'
            if (-not (Test-Path -LiteralPath $keepDir)) { New-Item -ItemType Directory -Path $keepDir -Force | Out-Null }
            $kept = Join-Path $keepDir ('autosync-guard-log-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.jsonl')
            Copy-Item -LiteralPath $log -Destination $kept
            Write-CvgLine ('      运行日志已另存到 ' + $kept)
        }
        Remove-Item -LiteralPath $asInstallDir -Recurse -Force
        Write-CvgLine '      已删除'
    } else {
        Write-CvgLine '      没有安装目录'
    }

    Write-CvgLine '[3/3] 确认……'
    $left = @()
    if ($null -ne (Get-AsTask)) { $left += '计划任务' }
    if (Test-Path -LiteralPath $asInstallDir) { $left += '安装目录' }
    if ($left.Count) { throw ('仍有残留：' + ($left -join '、')) }
    Write-CvgLine ''
    Write-CvgLine '已卸载自动补登记。防护规则不受影响，仍可用「开启防护 / 关闭防护 / 卸载防护」管理。' 'ok'
    Write-CvgLine '之后 Claude 更新时，需要你手动双击一次「开启防护」把新程序补登记进去。' 'warn'
}

# ============================================================ 只读：状态与预演

function Show-AsStatus {
    Write-CvgLine ('安装目录   : ' + $asInstallDir)
    if (-not (Test-Path -LiteralPath $asInstallDir)) {
        Write-CvgLine '             不存在（还没有安装）'
    } else {
        $hasMarker = Test-Path -LiteralPath (Join-Path $asInstallDir $asMarkerName)
        Write-CvgLine ('             标记文件：' + $(if ($hasMarker) { '有' } else { '没有（不是本工具创建的目录）' }))
        $problems = @(Get-AsAclProblems $asInstallDir)
        if ($problems.Count) { foreach ($p in $problems) { Write-CvgLine ('             权限问题：' + $p) 'warn' } }
        else { Write-CvgLine '             权限：只有管理员和系统能修改' }
        foreach ($f in $asFiles) {
            $dst = Join-Path $asInstallDir $f
            if (-not (Test-Path -LiteralPath $dst)) { Write-CvgLine ('             {0}：缺失' -f $f) 'warn'; continue }
            $same = ((Get-FileHash -LiteralPath (Join-Path $asSourceDir $f) -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash)
            Write-CvgLine ('             {0}：{1}' -f $f, $(if ($same) { '与工作目录一致' } else { '与工作目录不同（重新运行安装即可更新）' })) $(if ($same) { 'info' } else { 'warn' })
        }
        $configFile = Join-Path $asInstallDir 'config.json'
        if (Test-Path -LiteralPath $configFile) {
            try { $c = [System.IO.File]::ReadAllText($configFile, [System.Text.Encoding]::UTF8) | ConvertFrom-Json; Write-CvgLine ('             config.json：{0} 条程序路径' -f @($c.ProgramPatterns).Count) }
            catch { Write-CvgLine ('             config.json 无法读取：' + $_.Exception.Message) 'warn' }
        } else { Write-CvgLine '             config.json：缺失' 'warn' }
    }
    Write-CvgLine ('计划任务   : ' + (Get-CvgAutoSyncInfo))
    $recent = @(Read-AsLogSince ([datetime]::MinValue) | Where-Object { $_.Event -in @('sync', 'error') }) | Select-Object -Last 3
    foreach ($e in @($recent)) {
        $text = if ($e.Event -eq 'sync') { '补登记：新建 {0}，清理 {1}，共 {2}' -f $e.Data.Created, $e.Data.Removed, $e.Data.Total } else { '出错：' + [string]$e.Data.Message }
        Write-CvgLine ('最近记录   : {0}  {1}' -f ([datetime]$e.Time).ToString('MM-dd HH:mm'), $text)
    }
}

function Invoke-AsDryRun {
    $ok = $true
    Write-CvgLine '（只读预演，不做任何修改）'
    Write-CvgLine '[1] 要复制的文件：'
    foreach ($f in $asFiles) {
        $p = Join-Path $asSourceDir $f
        if (Test-Path -LiteralPath $p) { Write-CvgLine ('      {0}  {1}' -f $f, (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.Substring(0, 12)) }
        else { $ok = $false; Write-CvgLine ('      {0}  缺失' -f $f) 'err' }
    }
    $tokens = $null; $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $asSourceDir 'Guard.ps1'), [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count) { $ok = $false; Write-CvgLine '      Guard.ps1 有语法错误' 'err' } else { Write-CvgLine '      Guard.ps1 语法检查通过' }
    Write-CvgLine '[2] 安装时写进 config.json 的程序路径：'
    foreach ($p in @($script:CvgProgramPatterns)) { Write-CvgLine ('      ' + $p) }
    $found = @(Get-CvgProgramPaths)
    Write-CvgLine ('      现在按这些路径能找到 {0} 个程序' -f $found.Count) $(if ($found.Count) { 'info' } else { 'err' })
    if ($found.Count -eq 0) { $ok = $false }
    Write-CvgLine ('[3] 安装目录 {0}：' -f $asInstallDir)
    if (Test-AsReparse $asInstallDir) { $ok = $false; Write-CvgLine '      路径上有链接，安装会被拒绝' 'err' }
    if (Test-Path -LiteralPath $asInstallDir) {
        $hasMarker = Test-Path -LiteralPath (Join-Path $asInstallDir $asMarkerName)
        Write-CvgLine ('      已存在；标记文件：{0}' -f $(if ($hasMarker) { '有（安装会更新其中的文件）' } else { '没有（安装会被拒绝）' })) $(if ($hasMarker) { 'info' } else { 'err' })
        if (-not $hasMarker) { $ok = $false }
    } else {
        Write-CvgLine '      不存在；安装时新建，权限：系统和管理员完全控制，普通用户只读，关闭继承，所有者为管理员组'
    }
    Write-CvgLine '[4] 计划任务：'
    try {
        $xml = [xml](New-AsTaskXml -GuardPath (Join-Path $asInstallDir 'Guard.ps1') -Start ((Get-Date).AddMinutes(5)))
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
        Write-CvgLine ('      名称：{0}{1}' -f $asTaskPath, $asTaskName)
        Write-CvgLine ('      身份：{0}（系统），权限级别 {1}' -f $xml.SelectSingleNode('//t:Principal/t:UserId', $ns).InnerText, $xml.SelectSingleNode('//t:Principal/t:RunLevel', $ns).InnerText)
        Write-CvgLine ('      触发：登录后延迟 {0}；从 {1} 起每 {2} 重复' -f $xml.SelectSingleNode('//t:LogonTrigger/t:Delay', $ns).InnerText, $xml.SelectSingleNode('//t:TimeTrigger/t:StartBoundary', $ns).InnerText, $xml.SelectSingleNode('//t:TimeTrigger/t:Repetition/t:Interval', $ns).InnerText)
        Write-CvgLine ('      运行：{0} {1}' -f $xml.SelectSingleNode('//t:Exec/t:Command', $ns).InnerText, $xml.SelectSingleNode('//t:Exec/t:Arguments', $ns).InnerText)
        Write-CvgLine ('      单次最长运行：{0}；不会同时运行两份' -f $xml.SelectSingleNode('//t:Settings/t:ExecutionTimeLimit', $ns).InnerText)
        Write-CvgLine ('      访问权限：{0}（管理员和系统完全控制，已登录用户只能查看）' -f $xml.SelectSingleNode('//t:RegistrationInfo/t:SecurityDescriptor', $ns).InnerText)
    } catch { $ok = $false; Write-CvgLine ('      任务定义有问题：' + $_.Exception.Message) 'err' }
    Write-CvgLine ('      现在：' + (Get-CvgAutoSyncInfo))
    if ($ok) { Write-CvgLine '预演通过：可以安装。' 'ok'; return 0 }
    Write-CvgLine '预演没有通过，请先解决上面的问题。' 'err'
    return 1
}

# ============================================================ 前台窗口

function Confirm-AsStart {
    if ($asAction -eq 'Install') {
        Write-CvgLine '将要做的事：'
        Write-CvgLine ('  1. 把防护脚本和日常启动器复制到 {0}，这个目录只有管理员能修改。' -f $asInstallDir)
        Write-CvgLine ('  2. 注册计划任务 {0}{1}：以系统身份，在登录 {2} 分钟后、以及之后每 {3} 分钟，运行一次「同步程序清单」。' -f $asTaskPath, $asTaskName, $asLogonDelayMinutes, $asIntervalMinutes)
        Write-CvgLine '     它只把 Claude 新版本的程序补登记进规则，不改变防护开关；在本机运行，不联网、不消耗 token。'
        Write-CvgLine '  3. 装好后立即运行一次，确认它能正常工作。'
        Write-CvgLine ''
        Write-CvgLine '按 Y 开始安装，其他键取消（60 秒无操作自动取消）。' 'warn'
        $seconds = 60
    } else {
        Write-CvgLine ('将删除计划任务和安装目录 {0}。防护规则不受影响，仍由「开启 / 关闭 / 卸载防护」管理。' -f $asInstallDir) 'warn'
        Write-CvgLine '卸载后，Claude 更新时需要你手动双击「开启防护」补登记。'
        Write-CvgLine '按 Y 确认卸载，其他键取消（30 秒无操作自动取消）。'
        $seconds = 30
    }
    if ((Read-CvgKey $seconds) -eq 'Y') { return $true }
    Write-CvgLine '已取消，没有做任何改动。'
    return $false
}

function Invoke-AsViaWorker {
    # 前台窗口没有管理员权限：在后台启动隐藏的管理员进程执行，并把它的进度显示在当前窗口。
    $runDir = $script:CvgRunDir
    if (-not $runDir) { throw '找不到当前用户的 AppData 目录，无法显示后台进度。' }
    if (-not (Test-Path -LiteralPath $runDir)) { New-Item -ItemType Directory -Path $runDir -Force | Out-Null }
    $id = ([guid]::NewGuid().ToString('N')).Substring(0, 12)
    $progress = $runDir + '\run-' + $id + '.txt'
    [System.IO.File]::WriteAllText($progress, '', (New-Object System.Text.UTF8Encoding($false)))
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Action {1} -Worker -RunId {2}' -f $asScriptPath, $asAction, $id
    Write-CvgLine '正在以管理员身份在后台执行，进度会显示在这个窗口里（不会另外弹出窗口）……'
    try {
        $proc = Start-Process -FilePath $asPowerShell -ArgumentList $argLine -Verb RunAs -WindowStyle Hidden -PassThru -ErrorAction Stop
    } catch {
        throw ('无法以管理员身份启动：' + $_.Exception.Message)
    }
    $code = Watch-CvgProgress -Path $progress -Process $proc -TimeoutSeconds 600
    try {
        Get-ChildItem -LiteralPath $runDir -Filter 'run-*.txt' -File | Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
    return $code
}

# 被其他脚本以 ". AutoSync.ps1" 方式引用时只提供函数，不执行任何动作。
if ($asInvocation -ne '.') {
    if ($asWorker) {
        if ($asRunId -notmatch '^[0-9a-f]{12}$' -or -not $script:CvgRunDir) { exit 2 }
        $script:CvgProgressFile = $script:CvgRunDir + '\run-' + $asRunId + '.txt'
    }
    $asCode = 0
    $titles = @{ Install = '安装自动补登记'; Uninstall = '卸载自动补登记'; Status = '自动补登记状态'; DryRun = '自动补登记预演' }
    try {
        if (-not $asWorker) {
            try { $Host.UI.RawUI.WindowTitle = 'Claude VPN 防护 - ' + $titles[$asAction] } catch { }
            Write-CvgLine ''
            Write-CvgLine ('===== Claude VPN 防护：' + $titles[$asAction] + ' =====')
        }
        if ($asAction -eq 'Status') {
            Show-AsStatus
        } elseif ($asAction -eq 'DryRun') {
            $asCode = [int](@(Invoke-AsDryRun)[-1])
        } elseif ($asWorker) {
            if (-not (Test-CvgAdmin)) { throw '后台进程没有拿到管理员权限。' }
            if ($asAction -eq 'Install') { Invoke-AsInstall } else { Invoke-AsUninstall }
            $asCode = [int]$script:CvgExitCode
        } elseif (Confirm-AsStart) {
            if (Test-CvgAdmin) {
                if ($asAction -eq 'Install') { Invoke-AsInstall } else { Invoke-AsUninstall }
                $asCode = [int]$script:CvgExitCode
            } else {
                $asCode = [int](@(Invoke-AsViaWorker)[-1])
            }
        }
    } catch {
        Write-CvgLine ('错误：' + $_.Exception.Message) 'err'
        $asCode = 1
    } finally {
        if ($asWorker) { Add-CvgProgress ("DONE`t" + [string]$asCode) }
    }
    exit $asCode
}
