#Requires -Version 5.1
<#
Claude VPN Guard v2（适用于 Windows PowerShell 5.1）

目的：让 Claude 只能从 VPN 隧道地址联网；隧道不在时 Claude 自动断网。
做法：Windows 防火墙出站阻断规则。规则常驻在防火墙里，不需要后台进程。

用法：powershell -NoProfile -ExecutionPolicy Bypass -File Guard.ps1 -Action <动作>

  Status   查看状态（只读，不需要管理员；会逐条核对规则条件，约 20 秒）
  Plan     预览将要创建的规则（只读，不需要管理员）
  On       开启防护：首次会创建规则；之后是补登记新的 Claude 程序并启用规则
  Off      关闭防护：只停用规则，规则保留，可随时再开启
  Sync     同步程序清单，不改变开关状态
  Remove   卸载：删除本工具创建的全部规则

On / Off / Sync / Remove 会修改防火墙，需要管理员权限。没有提权时，确认在当前窗口里完成，
随后脚本在后台以管理员身份执行，进度实时显示在当前窗口，不会另外弹出窗口。
同一时间只允许进行一个修改类操作。
本脚本只操作名称以 CVG2- 开头、且分组为 ClaudeVpnGuard-v2 的规则，不碰其他规则。

注意：脚本里的中文只用于显示。文件须保存为带 BOM 的 UTF-8，否则中文会显示成乱码（不影响逻辑）。
#>
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Plan', 'On', 'Off', 'Sync', 'Remove')]
    [string]$Action = 'Status',
    [switch]$Force,
    [switch]$Yes,
    [switch]$Worker,
    [string]$RunId = ''
)

$ErrorActionPreference = 'Stop'

# 从 PowerShell 7 的终端里启动 5.1 时，继承来的模块路径可能让内置模块加载失败，这里显式加载系统自带的版本。
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    foreach ($cvgModule in @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security')) {
        try { Import-Module -Name ($PSHOME + '\Modules\' + $cvgModule + '\' + $cvgModule + '.psd1') -ErrorAction Stop } catch { }
    }
}

# ============================================================ 配置

$script:CvgGroup       = 'ClaudeVpnGuard-v2'
$script:CvgPrefix      = 'CVG2-'
$script:CvgTunAddress  = '10.33.0.2'            # Amnezia Xray 隧道的固定本地地址
$script:CvgTunDesc     = 'tun2socks Tunnel'     # 隧道网卡的设备描述
# Anthropic 公布的网段（2026-11-11 核对：https://platform.claude.com/docs/en/api/ip-addresses）
$script:CvgAnthropicV4 = @('160.79.104.0/21', '153.61.208.0/20', '153.61.224.0/22')
$script:CvgAnthropicV6 = @('2607:6bc0::/48')
$script:CvgAllV6       = @('::/1', '8000::/1')   # 全部 IPv6
# 需要登记的 Claude 程序（支持通配符；每次同步时按当时存在的文件展开）
$script:CvgProgramPatterns = @(
    ($env:LOCALAPPDATA + '\AnthropicClaude\claude.exe'),
    ($env:LOCALAPPDATA + '\AnthropicClaude\Update.exe'),
    ($env:LOCALAPPDATA + '\AnthropicClaude\app-*\claude.exe'),
    ($env:LOCALAPPDATA + '\AnthropicClaude\app-*\squirrel.exe'),
    ($env:APPDATA + '\Claude\claude-code\*\*\claude.exe'),
    ($env:USERPROFILE + '\.local\bin\claude.exe')
)
# 安装到受保护目录后，config.json 里保存的是安装时解析好的绝对路径，以系统身份运行的计划任务也能据此找到程序。
$script:CvgConfigFile    = $PSScriptRoot + '\config.json'
$script:CvgPatternSource = '当前用户的环境变量'
$script:CvgConfigError   = ''
if (Test-Path -LiteralPath $script:CvgConfigFile) {
    try {
        $cvgConfig = [System.IO.File]::ReadAllText($script:CvgConfigFile, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        $cvgPatterns = @(@($cvgConfig.ProgramPatterns) | Where-Object { ($_ -is [string]) -and -not [string]::IsNullOrWhiteSpace($_) })
        if ($cvgPatterns.Count -gt 0) { $script:CvgProgramPatterns = $cvgPatterns; $script:CvgPatternSource = '安装时保存的路径（config.json）' }
        else { $script:CvgConfigError = 'config.json 里没有有效的程序路径，改用当前用户的环境变量' }
    } catch { $script:CvgConfigError = 'config.json 无法读取，改用当前用户的环境变量：' + $_.Exception.Message }
}
$script:CvgDescription  = 'Claude VPN Guard v2. Managed by Guard.ps1; safe to remove with Guard.ps1 -Action Remove.'
$script:CvgMarkerFile   = $PSScriptRoot + '\state\probe-passed.json'
$script:CvgLogFile      = $PSScriptRoot + '\logs\guard-log.jsonl'
$script:CvgLockName     = 'Global\ClaudeVpnGuardV2'
# 前台窗口和后台管理员进程交换进度的目录：必须是普通用户可写的位置（安装目录只有管理员能写）
$script:CvgRunDir       = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'ClaudeVpnGuardV2\runs' } else { $null })
$script:CvgInstallDir   = Join-Path $env:ProgramData 'ClaudeVpnGuardV2'
$script:CvgTaskPath     = '\ClaudeVpnGuardV2\'
$script:CvgTaskName     = 'AutoSync'
$script:CvgProgressFile = $null                 # 后台管理员进程把进度写到这里，由前台窗口实时显示
$script:CvgExitCode     = 0

# ============================================================ 基础函数

function Test-CvgAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-CvgLog {
    param([string]$Event, $Data)
    try {
        $dir = Split-Path -Parent $script:CvgLogFile
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $line = ([ordered]@{ Time = (Get-Date).ToString('o'); Event = $Event; Data = $Data } | ConvertTo-Json -Compress -Depth 6)
        Add-Content -LiteralPath $script:CvgLogFile -Value $line -Encoding UTF8
    } catch { }
}

function Read-CvgKey {
    # 在限定秒数内等待一次按键，返回键名；超时或没有可用的控制台时返回 $null（一律按「未确认」处理）。
    param([int]$Seconds)
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { return $null }
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try { if ([Console]::KeyAvailable) { return [string]([Console]::ReadKey($true).Key) } } catch { return $null }
        Start-Sleep -Milliseconds 150
    }
    return $null
}

function Write-CvgColored {
    param([string]$Text, [string]$Level)
    switch ($Level) {
        'ok' { Write-Host $Text -ForegroundColor Green }
        'warn' { Write-Host $Text -ForegroundColor Yellow }
        'err' { Write-Host $Text -ForegroundColor Red }
        'act' { Write-Host $Text -ForegroundColor Cyan }
        default { Write-Host $Text }
    }
}

function Add-CvgProgress {
    param([string]$Line)
    if (-not $script:CvgProgressFile) { return }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    for ($i = 0; $i -lt 40; $i++) {
        try { [System.IO.File]::AppendAllText($script:CvgProgressFile, $Line + "`n", $encoding); return } catch { Start-Sleep -Milliseconds 50 }
    }
}

function Write-CvgLine {
    # 所有显示都经过这里：直接显示在本窗口；在后台管理员进程里还会写入进度文件，由前台窗口转显。
    param([string]$Text = '', [string]$Level = 'info')
    Write-CvgColored $Text $Level
    if ($script:CvgProgressFile) { Add-CvgProgress ($Level + "`t" + ($Text -replace "[`r`n`t]", ' ')) }
}

# ============================================================ 地址计算

function ConvertTo-CvgV4Number {
    param([string]$Ip)
    $b = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    if ($b.Length -ne 4) { throw ('不是 IPv4 地址：' + $Ip) }
    return ([long]$b[0] * 16777216) + ([long]$b[1] * 65536) + ([long]$b[2] * 256) + [long]$b[3]
}

function ConvertFrom-CvgV4Number {
    param([long]$Number)
    return ('{0}.{1}.{2}.{3}' -f (($Number -shr 24) -band 255), (($Number -shr 16) -band 255), (($Number -shr 8) -band 255), ($Number -band 255))
}

function Get-CvgV4Complement {
    # 返回「除隧道地址和 127.0.0.0/8 之外的全部 IPv4」，写成 a-b 形式的范围。
    param([string]$TunAddress)
    $tun = ConvertTo-CvgV4Number $TunAddress
    $loopStart = ConvertTo-CvgV4Number '127.0.0.0'
    $loopEnd = ConvertTo-CvgV4Number '127.255.255.255'
    if ($tun -ge $loopStart -and $tun -le $loopEnd) { throw '隧道地址不能是回环地址。' }
    $holes = @(
        [pscustomobject]@{ S = $tun; E = $tun },
        [pscustomobject]@{ S = $loopStart; E = $loopEnd }
    ) | Sort-Object S
    $out = New-Object 'System.Collections.Generic.List[string]'
    [long]$cursor = 0
    foreach ($h in $holes) {
        if ($h.S -gt $cursor) { $out.Add((ConvertFrom-CvgV4Number $cursor) + '-' + (ConvertFrom-CvgV4Number ($h.S - 1))) }
        $cursor = $h.E + 1
    }
    if ($cursor -le 4294967295) { $out.Add((ConvertFrom-CvgV4Number $cursor) + '-' + (ConvertFrom-CvgV4Number 4294967295)) }
    return $out.ToArray()
}

function Test-CvgV4InRanges {
    param([string]$Ip, [string[]]$Ranges)
    $n = ConvertTo-CvgV4Number $Ip
    foreach ($r in $Ranges) {
        $parts = $r.Split('-')
        $s = ConvertTo-CvgV4Number $parts[0]
        $e = if ($parts.Count -gt 1) { ConvertTo-CvgV4Number $parts[1] } else { $s }
        if ($n -ge $s -and $n -le $e) { return $true }
    }
    return $false
}

function ConvertTo-CvgCanonicalAddress {
    # 防火墙回读时会改写地址写法（例如 /21 变成 /255.255.248.0），这里统一成可比较的形式。
    param([string]$Text)
    $t = $Text.Trim()
    if ($t -eq '') { return '' }
    if ($t -match ':') { return $t.ToLowerInvariant() }
    $s = $null; $e = $null
    if ($t -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
        $s = ConvertTo-CvgV4Number $Matches[1]; $e = ConvertTo-CvgV4Number $Matches[2]
    } elseif ($t -match '^(\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)$') {
        $base = ConvertTo-CvgV4Number $Matches[1]; $mask = ConvertTo-CvgV4Number $Matches[2]
        $s = $base -band $mask; $e = $s + (4294967295 - $mask)
    } elseif ($t -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
        $base = ConvertTo-CvgV4Number $Matches[1]; $size = [long][math]::Pow(2, 32 - [int]$Matches[2])
        $s = $base - ($base % $size); $e = $s + $size - 1
    } elseif ($t -match '^\d+\.\d+\.\d+\.\d+$') {
        $s = ConvertTo-CvgV4Number $t; $e = $s
    } else {
        return $t.ToLowerInvariant()
    }
    return ('{0}-{1}' -f $s, $e)
}

function Get-CvgAddressSignature {
    # 把一组地址条件化成可比较的签名：IPv4 先换算成数值区间再合并相邻区间，
    # 这样即使防火墙回读时把范围拆开或合并，只要覆盖的地址相同，签名就相同。
    param($Addresses)
    $v4 = New-Object 'System.Collections.Generic.List[object]'
    $other = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Addresses)) {
        $c = ConvertTo-CvgCanonicalAddress ([string]$item)
        if ($c -match '^(\d+)-(\d+)$') { $v4.Add([pscustomobject]@{ S = [long]$Matches[1]; E = [long]$Matches[2] }) }
        elseif ($c -ne '') { $other.Add($c) }
    }
    $merged = New-Object 'System.Collections.Generic.List[string]'
    $cur = $null
    foreach ($r in @($v4 | Sort-Object S, E)) {
        if ($null -eq $cur) { $cur = [pscustomobject]@{ S = $r.S; E = $r.E }; continue }
        if ($r.S -le ($cur.E + 1)) {
            if ($r.E -gt $cur.E) { $cur.E = $r.E }
        } else {
            $merged.Add(('{0}-{1}' -f $cur.S, $cur.E))
            $cur = [pscustomobject]@{ S = $r.S; E = $r.E }
        }
    }
    if ($null -ne $cur) { $merged.Add(('{0}-{1}' -f $cur.S, $cur.E)) }
    return ((@($merged) + @($other | Sort-Object -Unique)) -join '|')
}

function Test-CvgAddressSetEqual {
    param($Actual, $Expected)
    return ((Get-CvgAddressSignature $Actual) -eq (Get-CvgAddressSignature $Expected))
}

# ============================================================ 规则清单

function Get-CvgProgramPaths {
    $found = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pattern in $script:CvgProgramPatterns) {
        foreach ($item in @(Get-Item -Path $pattern -Force -ErrorAction SilentlyContinue)) {
            if (-not $item.PSIsContainer) { $found.Add($item.FullName) }
        }
    }
    return @($found | Sort-Object -Unique)
}

function Get-CvgPathId {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Path.ToLowerInvariant())) } finally { $sha.Dispose() }
    return (($bytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-CvgShortPath {
    param([string]$Path)
    $parts = $Path.Split('\')
    if ($parts.Count -le 2) { return $Path }
    return ($parts[($parts.Count - 2)..($parts.Count - 1)] -join '\')
}

function Get-CvgDisplayName {
    # Windows 防火墙不允许规则的显示名称里出现竖线，这里只保留字母、数字、空格、点、括号和连字符。
    param([string]$Kind, [string]$Detail)
    $clean = (($Detail -replace '[^A-Za-z0-9 ._()\-]', ' ') -replace '\s+', ' ').Trim()
    $name = 'Claude VPN Guard v2 - ' + $Kind + ' - ' + $clean
    if ($name.Length -gt 120) { $name = $name.Substring(0, 120).Trim() }
    return $name
}

function Get-CvgTextProblems {
    # 创建规则前检查文字字段：防火墙不接受含竖线的标识、名称、说明和分组。返回问题列表（空表示可用）。
    param($Spec, [string]$Group)
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $fields = [ordered]@{ '规则标识' = [string]$Spec.Name; '显示名称' = [string]$Spec.DisplayName; '说明' = [string]$script:CvgDescription; '分组' = [string]$Group }
    foreach ($key in $fields.Keys) {
        $value = [string]$fields[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { $problems.Add($key + '为空') }
        elseif ($value.Contains('|')) { $problems.Add($key + '含有竖线') }
        elseif ($value.Length -gt 200) { $problems.Add($key + '过长') }
        elseif ($value -ieq 'all') { $problems.Add($key + '不能是 all') }
    }
    return $problems.ToArray()
}

function Get-CvgExpectedRules {
    # D 层：对所有程序生效，按目的地（Anthropic 网段）拦截。
    # P 层：对每个 Claude 程序生效，拦截它从非隧道地址发出的全部流量。
    $local = @(Get-CvgV4Complement $script:CvgTunAddress)
    $rules = New-Object 'System.Collections.Generic.List[object]'
    $rules.Add([pscustomobject]@{
        Name = $script:CvgPrefix + 'D-v4'; Kind = 'D'; Program = $null; Local = $local; Remote = $script:CvgAnthropicV4
        InterfaceType = $null; Label = '所有程序 -> Anthropic IPv4 网段'; DisplayName = (Get-CvgDisplayName 'D' 'Anthropic IPv4')
    })
    $rules.Add([pscustomobject]@{
        Name = $script:CvgPrefix + 'D-v6'; Kind = 'D'; Program = $null; Local = $null; Remote = $script:CvgAnthropicV6
        InterfaceType = $null; Label = '所有程序 -> Anthropic IPv6 网段'; DisplayName = (Get-CvgDisplayName 'D' 'Anthropic IPv6')
    })
    foreach ($path in @(Get-CvgProgramPaths)) {
        $id = Get-CvgPathId $path
        $short = Get-CvgShortPath $path
        $rules.Add([pscustomobject]@{
            Name = $script:CvgPrefix + 'P-' + $id + '-v4'; Kind = 'P'; Program = $path; Local = $local; Remote = $null
            InterfaceType = $null; Label = $path + '（IPv4）'; DisplayName = (Get-CvgDisplayName 'P' ($short + ' IPv4'))
        })
        $rules.Add([pscustomobject]@{
            Name = $script:CvgPrefix + 'P-' + $id + '-v6'; Kind = 'P'; Program = $path; Local = $null; Remote = $script:CvgAllV6
            InterfaceType = $null; Label = $path + '（IPv6）'; DisplayName = (Get-CvgDisplayName 'P' ($short + ' IPv6'))
        })
    }
    return $rules.ToArray()
}

# ============================================================ 防火墙读写

function New-CvgBlockRule {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Group,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [string]$Program,
        [string[]]$LocalAddress,
        [string[]]$RemoteAddress,
        [string]$InterfaceType,
        [bool]$Enabled = $true
    )
    $p = @{
        Name = $Name; DisplayName = $DisplayName; Group = $Group
        Description = $script:CvgDescription
        PolicyStore = 'PersistentStore'
        Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; Protocol = 'Any'
        Enabled = $(if ($Enabled) { 'True' } else { 'False' })
    }
    if ($Program) { $p.Program = $Program }
    if ($LocalAddress) { $p.LocalAddress = $LocalAddress }
    if ($RemoteAddress) { $p.RemoteAddress = $RemoteAddress }
    if ($InterfaceType) { $p.InterfaceType = $InterfaceType }
    New-NetFirewallRule @p -ErrorAction Stop | Out-Null
}

function Get-CvgRules {
    # 按名称模式读取规则，并只保留分组完全匹配的（即本工具自己的规则）。每次查询约 2 秒。
    param([string]$Store, [string]$NamePattern, [string]$Group)
    $rules = @()
    try { $rules = @(Get-NetFirewallRule -PolicyStore $Store -Name $NamePattern -ErrorAction Stop) }
    catch {
        if ([string]$_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
    }
    return @($rules | Where-Object { $_.Group -ceq $Group })
}

function Get-CvgRuleProblems {
    # 把一条现有规则和预期逐项比对，返回问题列表（空表示完全符合）。每条约 0.6 秒。
    param($Rule, $Spec, [bool]$ExpectEnabled, [switch]$IgnoreEnabled)
    $problems = New-Object 'System.Collections.Generic.List[string]'
    if ([string]$Rule.Direction -ne 'Outbound') { $problems.Add('方向不是出站') }
    if ([string]$Rule.Action -ne 'Block') { $problems.Add('动作不是阻止') }
    if ([string]$Rule.Profile -ne 'Any') { $problems.Add('配置文件不是全部') }
    if (-not $IgnoreEnabled -and ([string]$Rule.Enabled -ne [string]$ExpectEnabled)) { $problems.Add('启用状态为 ' + [string]$Rule.Enabled) }
    try {
        $app = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $addr = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $ift = $Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $wantProgram = if ($Spec.Program) { [string]$Spec.Program } else { 'Any' }
        if ([string]$app.Program -ine $wantProgram) { $problems.Add('程序路径不符') }
        $wantLocal = if ($Spec.Local) { @($Spec.Local) } else { @('Any') }
        $wantRemote = if ($Spec.Remote) { @($Spec.Remote) } else { @('Any') }
        if (-not (Test-CvgAddressSetEqual @($addr.LocalAddress) $wantLocal)) { $problems.Add('本地地址条件不符：' + (@($addr.LocalAddress) -join ',')) }
        if (-not (Test-CvgAddressSetEqual @($addr.RemoteAddress) $wantRemote)) { $problems.Add('远端地址条件不符：' + (@($addr.RemoteAddress) -join ',')) }
        if ([string]$port.Protocol -ne 'Any') { $problems.Add('协议不是全部') }
        $wantType = if ($Spec.InterfaceType) { [string]$Spec.InterfaceType } else { 'Any' }
        if ([string]$ift.InterfaceType -ne $wantType) { $problems.Add('接口类型条件不符') }
    } catch {
        $problems.Add('读取规则条件失败：' + $_.Exception.Message)
    }
    return $problems.ToArray()
}

function Set-CvgRulesEnabled {
    # 把本工具的规则全部设为启用或停用，返回操作后的规则列表。
    # 先整批修改；个别没改成的再逐条修改（探针测试验证过的方式）；最后核对。
    param([string]$Prefix, [string]$Group, [bool]$Enabled, $Rules = $null)
    $value = if ($Enabled) { 'True' } else { 'False' }
    if ($null -eq $Rules) { $Rules = @(Get-CvgRules 'PersistentStore' ($Prefix + '*') $Group) }
    $todo = @(@($Rules) | Where-Object { [string]$_.Enabled -ne $value })
    if ($todo.Count) {
        try { $todo | Set-NetFirewallRule -Enabled $value -ErrorAction Stop } catch { }
    }
    $after = @(Get-CvgRules 'PersistentStore' ($Prefix + '*') $Group)
    $left = @($after | Where-Object { [string]$_.Enabled -ne $value })
    if ($left.Count) {
        foreach ($r in $left) { Set-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -Enabled $value -ErrorAction Stop }
        $after = @(Get-CvgRules 'PersistentStore' ($Prefix + '*') $Group)
        if (@($after | Where-Object { [string]$_.Enabled -ne $value }).Count) {
            throw ('有规则没能' + $(if ($Enabled) { '启用' } else { '停用' }) + '。')
        }
    }
    return $after
}

function Test-CvgOrphanRemovable {
    # 多余规则能否清理：只有对应的程序文件已经不存在（或规则本身不针对程序）时才清理；读不到程序路径时保留。
    param([string]$Program)
    if ([string]::IsNullOrWhiteSpace($Program) -or $Program -eq '?') { return $false }
    if ($Program -eq 'Any') { return $true }
    return (-not (Test-Path -LiteralPath $Program))
}

function Remove-CvgRulesByPrefix {
    # 删除指定前缀和分组的全部规则，并确认两个策略存储里都没有残留。返回删除的条数。
    # 先整批删除；没删掉的再逐条删除（探针测试验证过的方式）。
    param([string]$Prefix, [string]$Group, $Rules = $null)
    if ($null -eq $Rules) { $Rules = @(Get-CvgRules 'PersistentStore' ($Prefix + '*') $Group) }
    $Rules = @($Rules)
    if ($Rules.Count) {
        try { $Rules | Remove-NetFirewallRule -ErrorAction Stop } catch { }
    }
    for ($i = 0; $i -lt 10; $i++) {
        $left = @(Get-CvgRules 'PersistentStore' ($Prefix + '*') $Group)
        foreach ($r in $left) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction Stop }
        $active = @(Get-CvgRules 'ActiveStore' ($Prefix + '*') $Group)
        if ($left.Count -eq 0 -and $active.Count -eq 0) { return $Rules.Count }
        Start-Sleep -Milliseconds 300
    }
    throw ('仍有规则残留：' + $Prefix + '*')
}

function Get-CvgFirewallNote {
    # 返回防火墙本身的问题说明；一切正常时返回空字符串。
    try {
        foreach ($svc in @('BFE', 'MpsSvc')) {
            if ([string](Get-Service -Name $svc).Status -ne 'Running') { return ('服务未运行：' + $svc + '，规则不会生效') }
        }
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        if (@($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count) { return 'Windows 防火墙有配置文件未启用，规则不会完全生效' }
        if (@($profiles | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' }).Count) { return '策略禁止本地防火墙规则，规则不会生效' }
        return ''
    } catch {
        return ('无法读取防火墙状态：' + $_.Exception.Message)
    }
}

# ============================================================ 状态

function Get-CvgVpnInfo {
    $info = [ordered]@{ Connected = $false; Alias = $null; Note = '未连接（本机没有隧道地址 ' + $script:CvgTunAddress + '）' }
    $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $script:CvgTunAddress })
    if ($addrs.Count -gt 1) {
        $info.Note = '警告：隧道地址同时出现在多块网卡上'
    } elseif ($addrs.Count -eq 1) {
        $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $addrs[0].InterfaceIndex })
        if ($adapter.Count -eq 1) {
            $info.Alias = [string]$adapter[0].Name
            if ([string]$adapter[0].InterfaceDescription -ne $script:CvgTunDesc) {
                $info.Note = '警告：隧道地址出现在非隧道网卡「' + $adapter[0].Name + '」上'
            } elseif ([string]$adapter[0].Status -ne 'Up' -or [string]$addrs[0].AddressState -ne 'Preferred') {
                $info.Note = '隧道网卡存在但未就绪'
            } else {
                $info.Connected = $true
                $info.Note = '已连接（' + $adapter[0].Name + '，' + $script:CvgTunAddress + '）'
            }
        }
    }
    return [pscustomobject]$info
}

function Get-CvgLastAutoSyncRecords {
    # 从安装目录的日志里取最近一次「补登记」和最近一次「出错」记录（普通用户可读）。
    $log = Join-Path $script:CvgInstallDir 'logs\guard-log.jsonl'
    $result = [pscustomobject]@{ Sync = $null; Error = $null }
    if (-not (Test-Path -LiteralPath $log)) { return $result }
    foreach ($line in @(Get-Content -LiteralPath $log -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        try {
            $o = $line | ConvertFrom-Json
            if ($o.Event -eq 'sync') { $result.Sync = $o } elseif ($o.Event -eq 'error') { $result.Error = $o }
        } catch { }
    }
    return $result
}

function Get-CvgAutoSyncInfo {
    # 读取「自动补登记」计划任务的状态（只读），返回一行说明。
    $installed = Test-Path -LiteralPath (Join-Path $script:CvgInstallDir 'installed-by-claude-vpn-guard.json')
    $text = ''
    try {
        $task = Get-ScheduledTask -TaskPath $script:CvgTaskPath -TaskName $script:CvgTaskName -ErrorAction Stop
        try {
            $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop
            $code = [int64]$info.LastTaskResult
            $result = switch ($code) { 0 { '成功' } 267009 { '正在运行' } 267011 { '还没运行过' } default { '失败（代码 0x{0:X8}）' -f $code } }
            $last = if ($info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { $info.LastRunTime.ToString('MM-dd HH:mm') } else { '无' }
            $next = if ($info.NextRunTime -and $info.NextRunTime.Year -gt 2000) { $info.NextRunTime.ToString('MM-dd HH:mm') } else { '无' }
            $state = if ([string]$task.State -eq 'Disabled') { '已停用' } else { '已安装' }
            $text = '{0}；上次运行 {1}（{2}）；下次运行 {3}' -f $state, $last, $result, $next
        } catch {
            $text = '已安装；读取运行信息失败：' + $_.Exception.Message
        }
    } catch {
        if ([string]$_.CategoryInfo.Category -ne 'ObjectNotFound') { $text = '无法读取计划任务：' + $_.Exception.Message }
        elseif ($installed) { $text = '已安装（以普通权限看不到计划任务的运行信息）' }
        else { return '未安装（Claude 更新后需要手动双击「开启防护」补登记）' }
    }
    $records = Get-CvgLastAutoSyncRecords
    if ($records.Sync) {
        $text += ('；最近一次补登记 {0}（新建 {1}，清理 {2}，共 {3} 条）' -f ([datetime]$records.Sync.Time).ToString('MM-dd HH:mm'), $records.Sync.Data.Created, $records.Sync.Data.Removed, $records.Sync.Data.Total)
    }
    if ($records.Error -and (-not $records.Sync -or [datetime]$records.Error.Time -gt [datetime]$records.Sync.Time)) {
        $text += ('；最近出错 {0}：{1}' -f ([datetime]$records.Error.Time).ToString('MM-dd HH:mm'), [string]$records.Error.Data.Message)
    }
    return $text
}

function Get-CvgActiveProblems {
    # 核对生效策略（ActiveStore）与持久策略一致：启用状态相同，启用的规则生效状态为 OK。刚修改过时稍等再查。
    param($Persist)
    $list = New-Object 'System.Collections.Generic.List[string]'
    for ($try = 0; $try -lt 3; $try++) {
        $list.Clear()
        $activeBy = @{}
        foreach ($r in @(Get-CvgRules 'ActiveStore' ($script:CvgPrefix + '*') $script:CvgGroup)) { $activeBy[$r.Name] = $r }
        foreach ($r in @($Persist)) {
            if (-not $activeBy.ContainsKey($r.Name)) { $list.Add($r.Name + '：没有出现在生效策略中') }
            elseif ([string]$activeBy[$r.Name].Enabled -ne [string]$r.Enabled) { $list.Add($r.Name + '：生效策略中的启用状态为 ' + [string]$activeBy[$r.Name].Enabled) }
            elseif ([string]$r.Enabled -eq 'True' -and [string]$activeBy[$r.Name].PrimaryStatus -ne 'OK') { $list.Add($r.Name + '：生效状态为 ' + [string]$activeBy[$r.Name].PrimaryStatus) }
        }
        if ($list.Count -eq 0) { break }
        Start-Sleep -Milliseconds 500
    }
    return $list.ToArray()
}

function Get-CvgState {
    # 汇总当前状态。-Full 时还会逐条核对每条规则的条件（约 0.6 秒一条），并显示进度。
    param([switch]$Full, $Persist = $null, $Vpn = $null)
    if ($null -eq $Persist) { $Persist = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup) }
    $Persist = @($Persist)
    if ($null -eq $Vpn) { $Vpn = Get-CvgVpnInfo }
    $expected = @(Get-CvgExpectedRules)
    $switch = 'NotInstalled'
    if ($Persist.Count -gt 0) {
        $on = @($Persist | Where-Object { [string]$_.Enabled -eq 'True' }).Count
        if ($on -eq $Persist.Count) { $switch = 'On' } elseif ($on -eq 0) { $switch = 'Off' } else { $switch = 'Mixed' }
    }
    $byName = @{}
    foreach ($r in $Persist) { $byName[$r.Name] = $r }
    $expectedNames = @($expected | ForEach-Object { $_.Name })
    $missing = @()
    $orphans = @()
    $activeProblems = @()
    if ($switch -ne 'NotInstalled') {
        $missing = @($expected | Where-Object { -not $byName.ContainsKey($_.Name) })
        $orphans = @($Persist | Where-Object { $expectedNames -notcontains $_.Name })
        $activeProblems = @(Get-CvgActiveProblems $Persist)
    }
    $bad = New-Object 'System.Collections.Generic.List[object]'
    $checked = $false
    if ($Full -and $switch -ne 'NotInstalled') {
        $toCheck = @($expected | Where-Object { $byName.ContainsKey($_.Name) })
        Write-CvgLine ('正在逐条核对规则条件（{0} 条，约 {1} 秒）……' -f $toCheck.Count, [int][math]::Ceiling($toCheck.Count * 0.7))
        $k = 0
        foreach ($spec in $toCheck) {
            $k++
            $p = @(Get-CvgRuleProblems -Rule $byName[$spec.Name] -Spec $spec -IgnoreEnabled)
            if ($p.Count) { $bad.Add([pscustomobject]@{ Name = $spec.Name; Label = $spec.Label; Problems = $p }) }
            if (($k % 6) -eq 0 -and $k -lt $toCheck.Count) { Write-CvgLine ('      已核对 {0}/{1}' -f $k, $toCheck.Count) }
        }
        $checked = $true
    }
    $firewallNote = Get-CvgFirewallNote
    $complete = ($switch -ne 'NotInstalled' -and $missing.Count -eq 0 -and $bad.Count -eq 0)
    return [pscustomobject]@{
        Switch = $switch; Expected = $expected; Persist = $Persist
        Missing = $missing; Bad = $bad.ToArray(); Orphans = $orphans; ActiveProblems = $activeProblems
        FirewallNote = $firewallNote; Vpn = $Vpn; FiltersChecked = $checked
        Complete = $complete
        Healthy = ($switch -eq 'On' -and $complete -and $activeProblems.Count -eq 0 -and $firewallNote -eq '')
    }
}

function Show-CvgStatus {
    param($State)
    $switchText = switch ($State.Switch) {
        'NotInstalled' { '未安装' }
        'On' { '已开启' }
        'Off' { '已关闭（规则保留，未生效）' }
        default { '不一致（部分规则启用、部分停用）' }
    }
    $effect = switch ($State.Switch) {
        'On' { if ($State.Vpn.Connected) { 'Claude 经 VPN 联网；VPN 断开时会自动断网' } else { 'VPN 未连接，Claude 当前被断网' } }
        'Mixed' { '规则状态不一致：双击「开启防护.cmd」可修复' }
        default { '没有防护：VPN 断开时 Claude 会直连' }
    }
    Write-CvgLine ('防护开关 : ' + $switchText)
    Write-CvgLine ('VPN 隧道 : ' + $State.Vpn.Note)
    Write-CvgLine ('当前效果 : ' + $effect)
    Write-CvgLine ('规则数量 : 现有 {0} 条；按当前程序清单应有 {1} 条' -f @($State.Persist).Count, @($State.Expected).Count)
    if ($State.FirewallNote) { Write-CvgLine ('防火墙   : ' + $State.FirewallNote) 'warn' }
    if ($State.Switch -eq 'NotInstalled') {
        if (Test-Path -LiteralPath $script:CvgMarkerFile) { Write-CvgLine '下一步   : 探针测试已通过，可以双击「开启防护.cmd」' }
        else { Write-CvgLine '下一步   : 先双击「运行探针测试.cmd」，通过后才能开启防护' }
        return
    }
    $missingD = @(@($State.Missing) | Where-Object { $_.Kind -eq 'D' })
    $missingP = @(@($State.Missing) | Where-Object { $_.Kind -eq 'P' } | ForEach-Object { $_.Program } | Sort-Object -Unique)
    if ($missingD.Count) { Write-CvgLine ('缺少主规则 : ' + (($missingD | ForEach-Object { $_.Name }) -join ', ')) 'err' }
    if ($missingP.Count) {
        Write-CvgLine ('未登记程序 : {0} 个（通常是 Claude 更新后的新路径），双击「开启防护.cmd」即可补上' -f $missingP.Count) 'warn'
        foreach ($p in $missingP) { Write-CvgLine ('    ' + $p) }
    }
    foreach ($b in @($State.Bad)) { Write-CvgLine ('规则异常 : {0}（{1}）' -f $b.Name, ($b.Problems -join '；')) 'err' }
    if (@($State.Bad).Count) { Write-CvgLine '处理办法 : 双击「卸载防护.cmd」后再双击「开启防护.cmd」，即可按正确条件重建' 'warn' }
    foreach ($a in @($State.ActiveProblems)) { Write-CvgLine ('生效异常 : ' + $a) 'err' }
    if (@($State.Orphans).Count) { Write-CvgLine ('多余规则 : {0} 条（不在当前程序清单里；程序文件已删除的，会在下次开启或自动补登记时清理）' -f @($State.Orphans).Count) }
    if ($State.Healthy) {
        if ($State.FiltersChecked) { Write-CvgLine '检查结果 : 全部规则符合预期且已生效' 'ok' }
        else { Write-CvgLine '检查结果 : 规则齐全且已生效' 'ok' }
    } elseif ($State.Switch -eq 'Off' -and $State.Complete -and @($State.ActiveProblems).Count -eq 0) {
        Write-CvgLine '检查结果 : 规则完整，可随时开启'
    }
}

function Show-CvgPlan {
    $expected = @(Get-CvgExpectedRules)
    $local = @(Get-CvgV4Complement $script:CvgTunAddress)
    Write-Host '（只读，不做任何修改）'
    Write-Host ('隧道地址             : ' + $script:CvgTunAddress)
    Write-Host ('会被拦截的本地地址   : ' + ($local -join ' , '))
    Write-Host ('Anthropic IPv4 网段  : ' + ($script:CvgAnthropicV4 -join ' , '))
    Write-Host ('Anthropic IPv6 网段  : ' + ($script:CvgAnthropicV6 -join ' , '))
    Write-Host ''
    Write-Host ('将创建 {0} 条规则（全部为出站、阻止、所有配置文件、所有协议）：' -f $expected.Count)
    foreach ($spec in $expected) {
        Write-Host ('  {0}  {1}' -f $spec.Name, $spec.Label)
        Write-Host ('      显示名称：' + $spec.DisplayName)
    }
    Write-Host ''
    Write-Host '自检（纯计算）：'
    $ok = $true
    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $inside = Test-CvgV4InRanges ([string]$a.IPAddress) $local
        $shouldBlock = ([string]$a.IPAddress -ne $script:CvgTunAddress -and [string]$a.IPAddress -notlike '127.*')
        $mark = if ($inside -eq $shouldBlock) { '正确' } else { $ok = $false; '错误' }
        Write-Host ('  {0,-16} {1,-34} {2}  [{3}]' -f $a.IPAddress, $a.InterfaceAlias, $(if ($inside) { '拦截' } else { '放行' }), $mark)
    }
    if (Test-CvgV4InRanges $script:CvgTunAddress $local) { $ok = $false; Write-Host '  错误：隧道地址落在拦截范围内' -ForegroundColor Red }
    $textBad = 0
    foreach ($spec in $expected) {
        $textProblems = @(Get-CvgTextProblems -Spec $spec -Group $script:CvgGroup)
        if ($textProblems.Count) { $textBad++; $ok = $false; Write-Host ('  名称检查失败：{0}（{1}）' -f $spec.Name, ($textProblems -join '；')) -ForegroundColor Red }
    }
    if ($textBad -eq 0) { Write-Host ('  名称检查通过：{0} 条规则的标识、显示名称、说明、分组都不含竖线。' -f $expected.Count) }
    if ($ok) { Write-Host '  自检通过：只有隧道地址和回环地址被放行。' -ForegroundColor Green }
    else { Write-Host '  自检失败：请不要开启防护。' -ForegroundColor Red; $script:CvgExitCode = 1 }
}

# ============================================================ 修改类动作（需要管理员）

function Sync-CvgRules {
    # 让防火墙里的规则与当前程序清单一致：补建缺少的、清理程序已不存在的，然后统一启用或停用。
    # 已有规则的条件不在这里逐条复核（那需要十几秒）；「查看状态」会做完整核对。
    param([bool]$Enabled, $Existing = $null)
    $expected = @(Get-CvgExpectedRules)
    if (@($expected | Where-Object { $_.Kind -eq 'P' }).Count -eq 0) { throw '没有找到任何 Claude 程序文件，拒绝继续（可能是在另一个账户下运行）。' }
    foreach ($spec in $expected) {
        $textProblems = @(Get-CvgTextProblems -Spec $spec -Group $script:CvgGroup)
        if ($textProblems.Count) { throw ('规则定义检查没有通过，没有做任何改动：' + $spec.Name + '：' + ($textProblems -join '；')) }
    }
    if ($null -eq $Existing) { $Existing = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup) }
    $Existing = @($Existing)
    $byName = @{}
    foreach ($r in $Existing) { $byName[$r.Name] = $r }
    $expectedNames = @($expected | ForEach-Object { $_.Name })
    $missing = @($expected | Where-Object { -not $byName.ContainsKey($_.Name) })
    $orphans = @($Existing | Where-Object { $expectedNames -notcontains $_.Name })
    # 只清理「对应的程序文件已经不存在」的多余规则；程序文件还在（或读不到程序路径）的一律保留，避免误删。
    $removable = New-Object 'System.Collections.Generic.List[object]'
    $keptOrphans = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $orphans) {
        $program = '?'
        try { $program = [string]($r | Get-NetFirewallApplicationFilter -ErrorAction Stop).Program } catch { }
        if (Test-CvgOrphanRemovable $program) { $removable.Add($r) } else { $keptOrphans.Add($r) }
    }
    $removableNames = @($removable | ForEach-Object { $_.Name })
    $keep = @($Existing | Where-Object { $removableNames -notcontains $_.Name })

    Write-CvgLine ('[2/4] 按当前程序清单整理规则：新建 {0} 条，清理 {1} 条……' -f $missing.Count, $removable.Count)
    $i = 0
    foreach ($spec in $missing) {
        $i++
        New-CvgBlockRule -Name $spec.Name -Group $script:CvgGroup -DisplayName $spec.DisplayName -Program $spec.Program -LocalAddress $spec.Local -RemoteAddress $spec.Remote -Enabled $Enabled
        Write-CvgLine ('      新建 {0}/{1}：{2}' -f $i, $missing.Count, $spec.DisplayName)
    }
    if ($removable.Count) {
        try { $removable | Remove-NetFirewallRule -ErrorAction Stop } catch { }
        Write-CvgLine ('      已清理 {0} 条多余规则（对应的程序文件已不存在）' -f $removable.Count)
    }
    if ($keptOrphans.Count) { Write-CvgLine ('      保留 {0} 条不在当前清单里、但程序文件仍存在的规则' -f $keptOrphans.Count) 'warn' }

    Write-CvgLine ('[3/4] {0}规则并核对……' -f $(if ($Enabled) { '启用' } else { '停用' }))
    $after = @(Set-CvgRulesEnabled $script:CvgPrefix $script:CvgGroup $Enabled $keep)
    $leftOrphans = @($after | Where-Object { $removableNames -contains $_.Name })
    if ($leftOrphans.Count) {
        foreach ($r in $leftOrphans) { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -ErrorAction Stop }
        $after = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    }
    $afterBy = @{}
    foreach ($r in $after) { $afterBy[$r.Name] = $r }
    foreach ($spec in $expected) {
        if (-not $afterBy.ContainsKey($spec.Name)) { throw ('规则没有创建成功：' + $spec.Name) }
        if ([string]$afterBy[$spec.Name].Enabled -ne [string]$Enabled) { throw ('规则启用状态不对：' + $spec.Name) }
    }
    if ($after.Count -ne ($expected.Count + $keptOrphans.Count)) { throw ('规则数量与预期不符：现有 {0} 条，应有 {1} 条。' -f $after.Count, ($expected.Count + $keptOrphans.Count)) }
    $j = 0
    foreach ($spec in $missing) {
        $j++
        $p = @(Get-CvgRuleProblems -Rule $afterBy[$spec.Name] -Spec $spec -ExpectEnabled $Enabled)
        if ($p.Count) { throw ('新建规则复核不符：' + $spec.Name + '：' + ($p -join '；')) }
        if (($j % 6) -eq 0 -or $j -eq $missing.Count) { Write-CvgLine ('      已核对新建规则 {0}/{1}' -f $j, $missing.Count) }
    }
    return [pscustomobject]@{ Created = $missing.Count; Removed = $removable.Count; Kept = $keptOrphans.Count; Total = $after.Count; Rules = $after }
}

function Invoke-CvgOn {
    Write-CvgLine '[1/4] 检查防火墙、VPN 和现有规则……'
    $note = Get-CvgFirewallNote
    if ($note) { throw $note }
    $vpn = Get-CvgVpnInfo
    $existing = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    $first = ($existing.Count -eq 0)
    Write-CvgLine ('      VPN：' + $vpn.Note)
    Write-CvgLine ('      现有规则：{0} 条' -f $existing.Count)
    if ($first -and -not $Force) {
        if (-not (Test-Path -LiteralPath $script:CvgMarkerFile)) { throw '还没有通过探针测试，不创建正式规则。请先双击「运行探针测试.cmd」。' }
        if (-not $vpn.Connected) { throw '首次开启需要 VPN 处于连接状态，这样才能确认 Claude 不受影响。请连接 VPN 后重试。' }
    }
    if (-not $vpn.Connected) { Write-CvgLine '注意：VPN 当前未连接，开启后 Claude 会立刻断网（这是防护的预期效果）。' 'warn' }

    try { $sync = Sync-CvgRules -Enabled $true -Existing $existing }
    catch {
        $err = $_
        if ($first) {
            Write-CvgLine '开启没有完成，正在撤销本次创建的规则……' 'warn'
            try {
                $n = Remove-CvgRulesByPrefix $script:CvgPrefix $script:CvgGroup
                Write-CvgLine ('已撤销 {0} 条规则，防火墙恢复到开启前的状态。' -f $n) 'warn'
            } catch { Write-CvgLine ('撤销时出错：' + $_.Exception.Message) 'err' }
        }
        throw $err
    }
    Write-CvgLog 'on' @{ First = $first; Created = $sync.Created; Removed = $sync.Removed; Kept = $sync.Kept; Total = $sync.Total }

    Write-CvgLine '[4/4] 确认生效状态……'
    $state = Get-CvgState -Persist $sync.Rules -Vpn $vpn
    Write-CvgLine ''
    Show-CvgStatus $state
    Write-CvgLine ''
    if ($state.Switch -eq 'On' -and @($state.ActiveProblems).Count -eq 0 -and @($state.Missing).Count -eq 0) {
        Write-CvgLine ('已开启：新建 {0} 条，清理 {1} 条，共 {2} 条规则。' -f $sync.Created, $sync.Removed, $sync.Total) 'ok'
    } else {
        Write-CvgLine '开启后的状态有异常，请把这个窗口的内容发给 Claude。' 'err'
        $script:CvgExitCode = 1
    }
    if ($first) {
        Write-CvgLine '这是首次开启：请到 Claude 发一条消息，确认它仍能正常使用。' 'warn'
        Write-CvgLine '如果 Claude 不能用了，双击「关闭防护.cmd」即可恢复（规则保留，可随时再开启）。' 'warn'
    }
}

function Invoke-CvgOff {
    Write-CvgLine '[1/3] 读取现有规则……'
    $rules = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    if ($rules.Count -eq 0) { Write-CvgLine '还没有安装任何规则，无需关闭。'; return }
    $enabledCount = @($rules | Where-Object { [string]$_.Enabled -eq 'True' }).Count
    if ($enabledCount -eq 0) { Write-CvgLine '防护已经是关闭状态，没有做任何改动。'; return }
    Write-CvgLine ('[2/3] 停用 {0} 条规则……' -f $enabledCount)
    $after = @(Set-CvgRulesEnabled $script:CvgPrefix $script:CvgGroup $false $rules)
    Write-CvgLog 'off' @{ Rules = $after.Count }
    Write-CvgLine '[3/3] 确认生效状态……'
    $state = Get-CvgState -Persist $after
    Write-CvgLine ''
    Show-CvgStatus $state
    Write-CvgLine ''
    if ($state.Switch -eq 'Off' -and @($state.ActiveProblems).Count -eq 0) {
        Write-CvgLine '已关闭：规则已停用并保留。现在 VPN 断开时 Claude 会直连；双击「开启防护.cmd」即可恢复。' 'warn'
    } else {
        Write-CvgLine '关闭后的状态有异常，请把这个窗口的内容发给 Claude。' 'err'
        $script:CvgExitCode = 1
    }
}

function Invoke-CvgSync {
    Write-CvgLine '[1/4] 读取现有规则……'
    $existing = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    if ($existing.Count -eq 0) { Write-CvgLine '还没有安装规则，同步不会创建规则。请先双击「开启防护.cmd」。'; return }
    $enabled = (@($existing | Where-Object { [string]$_.Enabled -eq 'True' }).Count -gt 0)
    $sync = Sync-CvgRules -Enabled $enabled -Existing $existing
    Write-CvgLog 'sync' @{ Enabled = $enabled; Created = $sync.Created; Removed = $sync.Removed; Kept = $sync.Kept; Total = $sync.Total }
    Write-CvgLine '[4/4] 确认生效状态……'
    $state = Get-CvgState -Persist $sync.Rules
    Write-CvgLine ''
    Show-CvgStatus $state
}

function Invoke-CvgRemove {
    Write-CvgLine '[1/2] 读取现有规则……'
    $rules = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    if ($rules.Count -eq 0) { Write-CvgLine '没有本工具创建的规则，无需卸载。'; return }
    Write-CvgLine ('[2/2] 删除 {0} 条规则，并确认两个策略存储里都没有残留……' -f $rules.Count)
    $n = Remove-CvgRulesByPrefix $script:CvgPrefix $script:CvgGroup $rules
    Write-CvgLog 'remove' @{ Removed = $n }
    Write-CvgLine ''
    Write-CvgLine ('已卸载：删除 {0} 条规则，没有残留。现在 VPN 断开时 Claude 会直连；需要时双击「开启防护.cmd」可重新创建。' -f $n) 'warn'
}

# ============================================================ 前台窗口与后台管理员进程

function Enter-CvgLock {
    # 防止两个开启/关闭/卸载操作同时进行。
    $mutex = New-Object System.Threading.Mutex($false, $script:CvgLockName)
    $held = $false
    try { $held = $mutex.WaitOne(2000) } catch [System.Threading.AbandonedMutexException] { $held = $true }
    if (-not $held) { $mutex.Dispose(); throw '另一个开启/关闭/卸载操作正在进行，请等它结束后再试。' }
    return $mutex
}

function Exit-CvgLock {
    param($Mutex)
    if ($null -ne $Mutex) {
        try { $Mutex.ReleaseMutex() } catch { }
        $Mutex.Dispose()
    }
}

function Confirm-CvgAction {
    # 关闭和卸载要在当前窗口按 Y 确认；开启和同步不需要确认。返回 $true 表示继续。
    if ($Yes -or $Worker -or $Action -notin @('Off', 'Remove')) { return $true }
    $rules = @(Get-CvgRules 'PersistentStore' ($script:CvgPrefix + '*') $script:CvgGroup)
    if ($rules.Count -eq 0) { Write-CvgLine '还没有安装任何规则，无需操作。'; return $false }
    $enabledCount = @($rules | Where-Object { [string]$_.Enabled -eq 'True' }).Count
    if ($Action -eq 'Off') {
        if ($enabledCount -eq 0) { Write-CvgLine '防护已经是关闭状态，无需操作。'; return $false }
        Write-CvgLine ('当前有 {0} 条规则，其中 {1} 条启用。关闭后规则保留但不生效：VPN 断开时 Claude 会直连。' -f $rules.Count, $enabledCount) 'warn'
        Write-CvgLine '按 Y 确认关闭，其他键取消（30 秒无操作自动取消）。'
    } else {
        Write-CvgLine ('将删除本工具创建的全部 {0} 条规则；之后 VPN 断开时 Claude 会直连。' -f $rules.Count) 'warn'
        Write-CvgLine '按 Y 确认卸载，其他键取消（30 秒无操作自动取消）。'
    }
    if ((Read-CvgKey 30) -eq 'Y') { return $true }
    Write-CvgLine '已取消，没有做任何改动。'
    return $false
}

function Watch-CvgProgress {
    # 前台窗口：持续读取后台进程写入的进度文件并显示，直到读到结束标记。返回后台进程报告的退出码。
    param([string]$Path, $Process, [int]$TimeoutSeconds = 300)
    $printed = 0
    $code = $null
    $started = Get-Date
    $exitSeen = $null
    $encoding = New-Object System.Text.UTF8Encoding($false)
    while ($null -eq $code) {
        $text = ''
        try {
            $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            try { $text = (New-Object System.IO.StreamReader($stream, $encoding)).ReadToEnd() } finally { $stream.Dispose() }
        } catch { }
        $end = $text.LastIndexOf([char]10)
        if ($end -ge 0) {
            $lines = $text.Substring(0, $end).Split([char]10)
            for ($i = $printed; $i -lt $lines.Count; $i++) {
                $line = $lines[$i].TrimEnd([char]13)
                if ($line.StartsWith('DONE' + "`t")) {
                    $parsed = 1
                    if (-not [int]::TryParse($line.Substring(5), [ref]$parsed)) { $parsed = 1 }
                    $code = $parsed
                    break
                }
                $parts = $line -split "`t", 2
                if ($parts.Count -gt 1) {
                    Write-CvgColored $parts[1] $parts[0]
                    # 需要你动手的步骤（act）响两声提醒
                    if ($parts[0] -eq 'act') { try { [Console]::Beep(988, 250); [Console]::Beep(1319, 300) } catch { } }
                } else { Write-CvgColored $line 'info' }
            }
            $printed = $lines.Count
        }
        if ($null -ne $code) { break }
        $exited = $false
        try { if ($null -ne $Process) { $exited = [bool]$Process.HasExited } } catch { }
        if ($exited) {
            if ($null -eq $exitSeen) { $exitSeen = Get-Date }
            elseif (((Get-Date) - $exitSeen).TotalSeconds -ge 3) {
                Write-CvgColored '后台的管理员进程已经结束，但没有报告结果。请把这个窗口的内容发给 Claude。' 'err'
                $code = 1
                break
            }
        }
        if (((Get-Date) - $started).TotalSeconds -ge $TimeoutSeconds) {
            Write-CvgColored ('等了 {0} 秒仍没有完成。后台进程可能还在运行，请稍后双击「查看状态.cmd」确认结果。' -f $TimeoutSeconds) 'err'
            $code = 1
            break
        }
        Start-Sleep -Milliseconds 300
    }
    return $code
}

function Invoke-CvgViaWorker {
    # 前台窗口没有管理员权限：在后台启动一个隐藏的管理员进程执行，并把它的进度显示在当前窗口。
    $logDir = $script:CvgRunDir
    if (-not $logDir) { throw '找不到当前用户的 AppData 目录，无法显示后台进度。' }
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $id = ([guid]::NewGuid().ToString('N')).Substring(0, 12)
    $progress = $logDir + '\run-' + $id + '.txt'
    [System.IO.File]::WriteAllText($progress, '', (New-Object System.Text.UTF8Encoding($false)))
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Action {1} -Worker -RunId {2}' -f $PSCommandPath, $Action, $id
    if ($Force) { $argLine += ' -Force' }
    Write-CvgLine '正在以管理员身份在后台执行，进度会显示在这个窗口里（不会另外弹出窗口）……'
    try {
        $proc = Start-Process -FilePath ($env:SystemRoot + '\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $argLine -Verb RunAs -WindowStyle Hidden -PassThru -ErrorAction Stop
    } catch {
        throw ('无法以管理员身份启动：' + $_.Exception.Message)
    }
    $code = Watch-CvgProgress -Path $progress -Process $proc
    try {
        Get-ChildItem -LiteralPath $logDir -Filter 'run-*.txt' -File | Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
    return $code
}

function Invoke-CvgMain {
    $titles = @{ Status = '查看状态'; Plan = '规则预览'; On = '开启防护'; Off = '关闭防护'; Sync = '同步程序清单'; Remove = '卸载防护' }
    $changing = $Action -in @('On', 'Off', 'Sync', 'Remove')
    if (-not $Worker) {
        try { $Host.UI.RawUI.WindowTitle = 'Claude VPN 防护 - ' + $titles[$Action] } catch { }
        Write-CvgLine ''
        Write-CvgLine ('===== Claude VPN 防护：' + $titles[$Action] + ' =====')
    }
    if ($changing) {
        if (-not $Worker) {
            if (-not (Confirm-CvgAction)) { return }
            if (-not (Test-CvgAdmin)) {
                $code = Invoke-CvgViaWorker
                $script:CvgExitCode = [int](@($code)[-1])
                return
            }
        } elseif (-not (Test-CvgAdmin)) {
            throw '后台进程没有拿到管理员权限。'
        }
        $lock = Enter-CvgLock
        try {
            switch ($Action) {
                'On' { Invoke-CvgOn }
                'Off' { Invoke-CvgOff }
                'Sync' { Invoke-CvgSync }
                'Remove' { Invoke-CvgRemove }
            }
        } finally { Exit-CvgLock $lock }
        return
    }
    switch ($Action) {
        'Status' {
            Write-CvgLine '正在读取规则和 VPN 状态……'
            $state = Get-CvgState -Full
            Write-CvgLine ''
            Show-CvgStatus $state
            Write-CvgLine ''
            $installed = ($PSScriptRoot -ieq $script:CvgInstallDir)
            Write-CvgLine ('脚本位置 : {0}{1}' -f $PSScriptRoot, $(if ($installed) { '（受保护的安装目录）' } else { '' }))
            Write-CvgLine ('程序清单 : 按{0}查找' -f $script:CvgPatternSource)
            if ($script:CvgConfigError) { Write-CvgLine ('配置问题 : ' + $script:CvgConfigError) 'warn' }
            Write-CvgLine ('自动补登记 : ' + (Get-CvgAutoSyncInfo))
        }
        'Plan' { Show-CvgPlan }
    }
}

# 被其他脚本以 ". Guard.ps1" 方式引用时只提供函数，不执行任何动作。
if ($MyInvocation.InvocationName -ne '.') {
    if ($Worker) {
        if ($RunId -notmatch '^[0-9a-f]{12}$' -or -not $script:CvgRunDir) { exit 2 }
        $script:CvgProgressFile = $script:CvgRunDir + '\run-' + $RunId + '.txt'
    }
    try { Invoke-CvgMain | Out-Null }
    catch {
        Write-CvgLine ('错误：' + $_.Exception.Message) 'err'
        $script:CvgExitCode = 1
        # 修改类操作出错时记一笔，计划任务在后台运行出错也能事后查到
        if ($Action -in @('On', 'Off', 'Sync', 'Remove')) { Write-CvgLog 'error' @{ Action = $Action; Message = $_.Exception.Message } }
    }
    finally {
        if ($Worker) { Add-CvgProgress ("DONE`t" + [string]$script:CvgExitCode) }
    }
    exit $script:CvgExitCode
}
