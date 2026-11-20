#Requires -Version 5.1
<#
Claude VPN Guard v2 - 阶段 2：探针测试（Windows PowerShell 5.1）

作用：在创建任何 Claude 规则之前，用一个临时编译的探针程序验证规则写法和「开/关」开关是否有效。
范围：所有临时规则只绑定探针程序自己的路径（分组 ClaudeVpnGuard-v2-PROBE，名称以 CVG2T- 开头），
      不涉及 Claude，也不影响其他程序；测试结束（包括中途出错）时全部删除。
流量：探针只会连接 你的 VPS、1.1.1.1、本机回环、以及 IP 回显服务（经 VPN）。不连接 Anthropic。

用法：
  powershell -NoProfile -ExecutionPolicy Bypass -File ProbeTest.ps1            正式测试（需要管理员）
  powershell -NoProfile -ExecutionPolicy Bypass -File ProbeTest.ps1 -DryRun    预演：只编译探针并做本机回环自测，不建规则、不发外网流量

结果写入本目录下的 outputs\claude-guard-v2-probe-<时间>\；全部必过项通过后，会写入 state\probe-passed.json，
Guard.ps1 才允许首次开启防护。
#>
[CmdletBinding()]
param(
    # 你 VPN 服务器的公网 IPv4 地址（也就是经 VPN 上网时的出口 IP），例如 '203.0.113.10'。正式测试前必须填写。
    [string]$VpsAddress = '',
    [int]$VpsPort = 443,
    [string]$EchoUrl = 'https://api.ipify.org/',
    [switch]$DryRun,
    [switch]$IsElevated
)

$ErrorActionPreference = 'Stop'

# Guard.ps1 有自己的参数，先把本脚本的参数另存，再引用它的函数（引用时它不会执行任何动作）。
$ptVps = $VpsAddress; $ptPort = $VpsPort; $ptEcho = $EchoUrl; $ptDry = [bool]$DryRun; $ptElevated = [bool]$IsElevated
# 正式测试必须先填 VPN 服务器地址（预演不需要）；没填时直接停下，不做任何改动。
$ptVpsIp = $null
if (-not $ptDry -and -not ([System.Net.IPAddress]::TryParse($ptVps, [ref]$ptVpsIp) -and [string]$ptVpsIp.AddressFamily -eq 'InterNetwork')) {
    Write-Host ('还没有填 VPN 服务器地址，或者格式不对（当前为「{0}」）。' -f $ptVps) -ForegroundColor Red
    Write-Host '请用记事本打开 ProbeTest.ps1，在开头 $VpsAddress 一行填上你 VPN 服务器的公网 IPv4 地址，保存后重新运行。' -ForegroundColor Red
    exit 1
}
. ($PSScriptRoot + '\Guard.ps1')

$ptGroup = 'ClaudeVpnGuard-v2-PROBE'
$ptPrefix = 'CVG2T-'
$ptStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$ptRunDir = $PSScriptRoot + '\probe-run-' + $ptStamp
$ptOutDir = $PSScriptRoot + '\outputs\claude-guard-v2-probe-' + $ptStamp
$ptResults = New-Object 'System.Collections.Generic.List[object]'

# 探针源码（C# 5 语法，用系统自带编译器编译）。只做最小的连接动作，不发送任何账号或业务数据。
$ptProbeSource = @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

public static class CvgProbe
{
    static string Q(string s)
    {
        if (s == null) s = "";
        StringBuilder b = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c == '\\' || c == '"') { b.Append('\\').Append(c); }
            else if (c < ' ') { b.Append(' '); }
            else { b.Append(c); }
        }
        return b.Append('"').ToString();
    }

    static void Print(string mode, bool ok, string local, string target, int nativeError, int status, string detail)
    {
        Console.WriteLine("{\"mode\":" + Q(mode) + ",\"ok\":" + (ok ? "true" : "false") + ",\"local\":" + Q(local)
            + ",\"target\":" + Q(target) + ",\"nativeError\":" + nativeError + ",\"status\":" + status + ",\"detail\":" + Q(detail) + "}");
    }

    static void BindIfAsked(Socket s, IPAddress target, string source, int ifIndex)
    {
        // 31 = IP_UNICAST_IF：把套接字固定到指定网卡，和上一轮验收用的探针保持一致。
        if (ifIndex > 0 && target.AddressFamily == AddressFamily.InterNetwork)
            s.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(ifIndex));
        if (source != "any") s.Bind(new IPEndPoint(IPAddress.Parse(source), 0));
    }

    public static int Main(string[] a)
    {
        string mode = a.Length > 0 ? a[0] : "";
        try
        {
            if (mode == "tcp") return Tcp(a[1], int.Parse(a[2]), a[3], a.Length > 4 ? int.Parse(a[4]) : 0);
            if (mode == "udp") return Udp(a[1], int.Parse(a[2]), a[3], a.Length > 4 ? int.Parse(a[4]) : 0);
            if (mode == "dns") return Dns(a[1], a[2]);
            if (mode == "http") return Http(a[1]);
            Print(mode, false, "", "", -2, 0, "unknown mode");
            return 2;
        }
        catch (SocketException e) { Print(mode, false, "", "", e.NativeErrorCode, 0, e.SocketErrorCode.ToString()); return 1; }
        catch (Exception e) { Print(mode, false, "", "", -1, 0, e.GetType().Name + ": " + e.Message); return 3; }
    }

    // 只建立 TCP 连接，不发送任何应用数据。
    static int Tcp(string target, int port, string source, int ifIndex)
    {
        IPAddress ip = IPAddress.Parse(target);
        string t = target + " port " + port;
        using (Socket s = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
        {
            try
            {
                BindIfAsked(s, ip, source, ifIndex);
                IAsyncResult ar = s.BeginConnect(new IPEndPoint(ip, port), null, null);
                if (!ar.AsyncWaitHandle.WaitOne(6000)) { Print("tcp", false, "", t, 10060, 0, "TimedOut"); return 1; }
                s.EndConnect(ar);
                Print("tcp", true, s.LocalEndPoint.ToString(), t, 0, 0, "connected");
                return 0;
            }
            catch (SocketException e) { Print("tcp", false, "", t, e.NativeErrorCode, 0, e.SocketErrorCode.ToString()); return 1; }
        }
    }

    // 发送 1 个字节的 UDP 数据报，只记录发送是否被系统拒绝。
    static int Udp(string target, int port, string source, int ifIndex)
    {
        IPAddress ip = IPAddress.Parse(target);
        string t = target + " port " + port;
        using (Socket s = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
        {
            try
            {
                BindIfAsked(s, ip, source, ifIndex);
                int n = s.SendTo(new byte[] { 0 }, new IPEndPoint(ip, port));
                Print("udp", true, s.LocalEndPoint.ToString(), t, 0, 0, "sent " + n + " byte");
                return 0;
            }
            catch (SocketException e) { Print("udp", false, "", t, e.NativeErrorCode, 0, e.SocketErrorCode.ToString()); return 1; }
        }
    }

    // 用 UDP 向 DNS 服务器查询 example.com，收到应答才算成功。
    static int Dns(string server, string source)
    {
        IPAddress ip = IPAddress.Parse(server);
        string t = server + " port 53";
        byte[] q = new byte[] {
            0x43, 0x56, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0x03, (byte)'c', (byte)'o', (byte)'m', 0x00, 0x00, 0x01, 0x00, 0x01 };
        using (Socket s = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
        {
            try
            {
                if (source != "any") s.Bind(new IPEndPoint(IPAddress.Parse(source), 0));
                s.ReceiveTimeout = 4000;
                s.SendTo(q, new IPEndPoint(ip, 53));
                byte[] buf = new byte[512];
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int n = s.ReceiveFrom(buf, ref from);
                bool match = n >= 12 && buf[0] == 0x43 && buf[1] == 0x56;
                Print("dns", match, s.LocalEndPoint.ToString(), t, 0, 0, "reply " + n + " bytes");
                return match ? 0 : 1;
            }
            catch (SocketException e) { Print("dns", false, "", t, e.NativeErrorCode, 0, e.SocketErrorCode.ToString()); return 1; }
        }
    }

    // 不指定源地址、不使用代理，向回显服务发一次 HTTPS GET；detail 是服务返回的文本（对方看到的出口 IP）。
    static int Http(string url)
    {
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
        req.Proxy = null;
        req.Timeout = 15000;
        req.ReadWriteTimeout = 15000;
        req.AllowAutoRedirect = false;
        req.KeepAlive = false;
        req.UserAgent = "cvg-probe/1";
        try
        {
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader r = new StreamReader(resp.GetResponseStream()))
            {
                string body = r.ReadToEnd().Trim();
                if (body.Length > 64) body = body.Substring(0, 64);
                Print("http", true, "", url, 0, (int)resp.StatusCode, body);
                return 0;
            }
        }
        catch (WebException e)
        {
            int code = -1;
            SocketException se = e.InnerException as SocketException;
            if (se != null) code = se.NativeErrorCode;
            Print("http", false, "", url, code, 0, e.Status.ToString() + ": " + e.Message);
            return 1;
        }
    }
}
'@

# ============================================================ 辅助函数

function Format-PtObserved {
    param($Observed)
    if ($null -eq $Observed) { return '' }
    $names = @($Observed.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names -contains 'mode') {
        if ($Observed.ok -eq $true) { return ('成功 ' + ((@([string]$Observed.local, [string]$Observed.detail) | Where-Object { $_ }) -join ' ')) }
        return ('未成功（错误码 {0}，{1}）' -f $Observed.nativeError, $Observed.detail)
    }
    if ($names -contains 'Problems') {
        if (@($Observed.Problems).Count) { return ('问题：' + (@($Observed.Problems) -join '；')) }
        if ($names -contains 'ActiveStatus' -and $Observed.ActiveStatus) { return ('符合预期（生效状态 ' + $Observed.ActiveStatus + '）') }
        return '符合预期'
    }
    return [string]$Observed
}

function Add-PtResult {
    # Gate=$true 表示必过项；Gate=$false 表示仅供参考，不影响总结论。
    param([string]$Id, [string]$What, [bool]$Gate, [bool]$Passed, $Observed)
    $text = Format-PtObserved $Observed
    $ptResults.Add([pscustomobject]@{ Id = $Id; What = $What; Gate = $Gate; Passed = $Passed; ObservedText = $text; Observed = $Observed; Time = (Get-Date).ToString('o') })
    $tag = if ($Passed) { '[通过]' } elseif ($Gate) { '[失败]' } else { '[参考]' }
    $color = if ($Passed) { 'Green' } elseif ($Gate) { 'Red' } else { 'Yellow' }
    Write-Host ('{0} {1} {2} -> {3}' -f $tag, $Id, $What, $text) -ForegroundColor $color
}

function Invoke-PtProbe {
    param([string]$Exe, [string[]]$ProbeArgs)
    $raw = @(& $Exe @ProbeArgs)
    $code = $LASTEXITCODE
    $obj = $null
    foreach ($line in $raw) {
        if ([string]$line -match '^\{') { try { $obj = ([string]$line | ConvertFrom-Json) } catch { } }
    }
    if ($null -eq $obj) {
        $obj = [pscustomobject]@{ mode = $ProbeArgs[0]; ok = $false; local = ''; target = ''; nativeError = -9; status = 0; detail = ('探针没有输出：' + ($raw -join ' ')) }
    }
    $obj | Add-Member -NotePropertyName exitCode -NotePropertyValue $code -Force
    return $obj
}

function Test-PtConnected { param($R) return ($R.ok -eq $true) }

# 10013 = WSAEACCES，被防火墙拒绝时的错误码（上一轮验收实测也是这个值）。
function Test-PtBlocked { param($R) return ($R.ok -ne $true -and [int]$R.nativeError -eq 10013) }

function Wait-PtRulesEnabled {
    # 等生效策略里的探针规则全部变成指定的启用状态。
    param([bool]$Enabled)
    $want = [string]$Enabled
    for ($i = 0; $i -lt 25; $i++) {
        $active = @(Get-CvgRules 'ActiveStore' ($ptPrefix + '*') $ptGroup)
        if ($active.Count -gt 0 -and @($active | Where-Object { [string]$_.Enabled -ne $want }).Count -eq 0) { Start-Sleep -Milliseconds 500; return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function New-PtRule {
    # 用和正式部署相同的函数创建一条只针对探针程序的规则，然后回读核对。
    param([string]$Suffix, [string]$Program, [string[]]$Local, [string[]]$Remote, [string]$InterfaceType)
    $name = $ptPrefix + $Suffix
    $spec = [pscustomobject]@{ Name = $name; Program = $Program; Local = $Local; Remote = $Remote; InterfaceType = $InterfaceType }
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $activeStatus = ''
    try {
        # 显示名称用和正式规则相同的函数生成，这样名称格式也会在这里得到验证。
        New-CvgBlockRule -Name $name -Group $ptGroup -DisplayName (Get-CvgDisplayName 'TEST' ((Get-CvgShortPath $Program) + ' ' + $Suffix)) -Program $Program -LocalAddress $Local -RemoteAddress $Remote -InterfaceType $InterfaceType -Enabled $true
        $rule = @(Get-CvgRules 'PersistentStore' $name $ptGroup)
        if ($rule.Count -ne 1) { $problems.Add('创建后没有找到规则') }
        else { foreach ($p in @(Get-CvgRuleProblems -Rule $rule[0] -Spec $spec -ExpectEnabled $true)) { $problems.Add($p) } }
        $seen = $false
        for ($i = 0; $i -lt 25 -and -not $seen; $i++) {
            $a = @(Get-CvgRules 'ActiveStore' $name $ptGroup)
            if ($a.Count -eq 1 -and [string]$a[0].Enabled -eq 'True') { $seen = $true } else { Start-Sleep -Milliseconds 200 }
        }
        if (-not $seen) { $problems.Add('没有出现在生效策略中') }
        else {
            # 「查看状态」在防护开启时要求生效状态为 OK，这里提前核对同样的条件。
            $activeStatus = [string]$a[0].PrimaryStatus + ' / ' + ((@($a[0].EnforcementStatus) | ForEach-Object { [string]$_ }) -join ',')
            if ([string]$a[0].PrimaryStatus -ne 'OK') { $problems.Add('生效状态为 ' + $activeStatus) }
        }
        Start-Sleep -Milliseconds 500
    } catch {
        $problems.Add('创建失败：' + $_.Exception.Message)
    }
    return [pscustomobject]@{ Name = $name; Problems = $problems.ToArray(); ActiveStatus = $activeStatus }
}

function Get-PtPhysicalSource {
    # VPN 的外层连接是从物理网卡发往 VPS 的，用它找出当前的物理网卡地址。
    if ([string]::IsNullOrWhiteSpace($ptVps)) { return $null }
    $conns = @(Get-NetTCPConnection -State Established -RemoteAddress $ptVps -RemotePort $ptPort -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -ne $script:CvgTunAddress -and $_.LocalAddress -notmatch ':' })
    if ($conns.Count -eq 0) { return $null }
    $ip = [string](@($conns | Group-Object LocalAddress | Sort-Object Count -Descending)[0].Name)
    $addr = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $ip })
    if ($addr.Count -ne 1) { return $null }
    $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $addr[0].InterfaceIndex })
    return [pscustomobject]@{
        Address = $ip; IfIndex = [int]$addr[0].InterfaceIndex; Alias = [string]$addr[0].InterfaceAlias
        IfType = $(if ($adapter.Count -eq 1) { [int]$adapter[0].InterfaceType } else { 0 }); OuterConnections = $conns.Count
    }
}

function Get-PtFirewallFingerprint {
    # 除探针规则外，全部持久规则的名称、启用状态、方向、动作的摘要，用于确认测试前后其他规则没有变化。
    $rows = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -notlike ($ptPrefix + '*') } |
        ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.Enabled, $_.Direction, $_.Action } | Sort-Object)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($rows -join "`n"))))).Replace('-', '') } finally { $sha.Dispose() }
    return [pscustomobject]@{ Count = $rows.Count; Hash = $hash }
}

# ============================================================ 开始

$ptIsAdmin = Test-CvgAdmin
if (-not $ptDry -and -not $ptIsAdmin) {
    if ($ptElevated) { Write-Host '错误：提权后仍然没有管理员权限。' -ForegroundColor Red; exit 1 }
    Write-Host '探针测试需要管理员权限，正在请求提权...'
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -VpsAddress {1} -VpsPort {2} -EchoUrl "{3}" -IsElevated' -f $PSCommandPath, $ptVps, $ptPort, $ptEcho
    Start-Process -FilePath ($env:SystemRoot + '\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $argLine -Verb RunAs | Out-Null
    exit 0
}

$ptFatal = $null; $ptCancelled = $false; $ptCompleted = $false
$ptListener4 = $null; $ptListener6 = $null
$ptVpn = $null; $ptPhys = $null; $ptFwNote = ''; $ptFpBefore = $null; $ptFpAfter = $null

Write-Host ''
Write-Host ('===== Claude VPN Guard v2 探针测试{0} =====' -f $(if ($ptDry) { '（预演：不建规则、不发外网流量）' } else { '' }))

try {
    # ---------- 预检（只读）
    $ptVpn = Get-CvgVpnInfo
    $ptFwNote = Get-CvgFirewallNote
    $ptPhys = Get-PtPhysicalSource
    Write-Host ('管理员权限 : ' + $(if ($ptIsAdmin) { '是' } else { '否' }))
    Write-Host ('VPN 隧道   : ' + $ptVpn.Note)
    Write-Host ('防火墙     : ' + $(if ($ptFwNote) { $ptFwNote } else { '正常' }))
    if ($ptPhys) { Write-Host ('物理网卡   : {0}（{1}，到 VPS 的外层连接 {2} 条）' -f $ptPhys.Alias, $ptPhys.Address, $ptPhys.OuterConnections) }
    else { Write-Host ('物理网卡   : 没有发现到 VPS {0} 端口 {1} 的外层连接' -f $ptVps, $ptPort) }

    if (-not $ptDry) {
        if ($ptFwNote) { throw $ptFwNote }
        if (-not $ptVpn.Connected) { throw 'VPN 没有连接，探针测试需要在 VPN 连接状态下进行。' }
        if ($null -eq $ptPhys) { throw '没有发现到 VPS 的外层连接，无法确定物理网卡地址。' }
        Write-Host ''
        Write-Host '接下来会：编译一个临时探针程序；创建只针对该探针的临时防火墙规则；发送少量测试连接；最后删除全部临时规则。' -ForegroundColor Yellow
        Write-Host '不涉及 Claude，不改动其他规则。按 Y 开始，其他键取消（60 秒无操作自动取消）。' -ForegroundColor Yellow
        if ((Read-CvgKey 60) -ne 'Y') { $ptCancelled = $true; throw '已取消，没有做任何改动。' }
        $leftover = @(Get-CvgRules 'PersistentStore' ($ptPrefix + '*') $ptGroup)
        if ($leftover.Count) { Write-Host ('发现上次残留的探针规则 {0} 条，先清理。' -f $leftover.Count); [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup) }
        $ptFpBefore = Get-PtFirewallFingerprint
    }

    # ---------- 编译探针，并复制成两个不同路径的程序
    New-Item -ItemType Directory -Path $ptRunDir -Force | Out-Null
    $exe0 = $ptRunDir + '\cvg-probe.exe'
    $exeA = $ptRunDir + '\cvg-probe-a.exe'    # 规则针对的程序
    $exeB = $ptRunDir + '\cvg-probe-b.exe'    # 对照程序：内容相同、路径不同，不受规则约束
    Add-Type -TypeDefinition $ptProbeSource -Language CSharp -OutputAssembly $exe0 -OutputType ConsoleApplication -IgnoreWarnings -ErrorAction Stop
    Copy-Item -LiteralPath $exe0 -Destination $exeA
    Copy-Item -LiteralPath $exe0 -Destination $exeB
    Write-Host ('探针已编译 : ' + $exe0)

    # ---------- 本机回环监听（供回环测试用）
    $ptListener4 = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::Loopback), 0
    $ptListener4.Start()
    $port4 = ([System.Net.IPEndPoint]$ptListener4.LocalEndpoint).Port
    $port6 = 0
    try {
        $ptListener6 = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::IPv6Loopback), 0
        $ptListener6.Start()
        $port6 = ([System.Net.IPEndPoint]$ptListener6.LocalEndpoint).Port
    } catch { $ptListener6 = $null; $port6 = 0 }

    Write-Host ''
    if ($ptDry) {
        # ---------- 预演：只做回环自测，确认探针程序和结果解析工作正常
        $r = Invoke-PtProbe $exeA @('tcp', '127.0.0.1', [string]$port4, 'any')
        Add-PtResult 'DRY1' '探针连本机 IPv4 回环' $true (Test-PtConnected $r) $r
        if ($port6 -gt 0) {
            $r = Invoke-PtProbe $exeA @('tcp', '::1', [string]$port6, 'any')
            Add-PtResult 'DRY2' '探针连本机 IPv6 回环' $false (Test-PtConnected $r) $r
        }
        $r = Invoke-PtProbe $exeA @('nosuchmode')
        Add-PtResult 'DRY3' '探针对未知参数给出可解析的失败结果' $true ($r.ok -ne $true -and [int]$r.nativeError -eq -2) $r
        $ptCompleted = $true
    } else {
        $local = @(Get-CvgV4Complement $script:CvgTunAddress)
        $physArgs = @($ptPhys.Address, [string]$ptPhys.IfIndex)

        # ---------- B：基线（没有任何探针规则）
        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'B1' '基线：探针从物理网卡地址直连 VPS 应成功' $true (Test-PtConnected $r) $r
        if (-not (Test-PtConnected $r)) { throw '基线 B1 没有通过，无法用它区分规则效果，测试中止（没有创建任何规则）。' }
        $r = Invoke-PtProbe $exeA @('http', $ptEcho)
        $b2 = ((Test-PtConnected $r) -and ([string]$r.detail -eq $ptVps))
        Add-PtResult 'B2' '基线：探针经 VPN 访问回显服务，应返回 VPS 地址' $true $b2 $r
        if (-not $b2) { throw '基线 B2 没有通过，测试中止（没有创建任何规则）。' }
        $r = Invoke-PtProbe $exeA @('dns', '1.1.1.1', 'any')
        $udpBaseline = (Test-PtConnected $r)
        Add-PtResult 'B3' '基线：探针经 VPN 发 UDP 查询应收到应答' $false $udpBaseline $r
        $r = Invoke-PtProbe $exeA @('tcp', '127.0.0.1', [string]$port4, 'any')
        Add-PtResult 'B4' '基线：探针连本机 IPv4 回环应成功' $true (Test-PtConnected $r) $r
        $v6Loop = $false
        if ($port6 -gt 0) {
            $r = Invoke-PtProbe $exeA @('tcp', '::1', [string]$port6, 'any')
            $v6Loop = (Test-PtConnected $r)
            Add-PtResult 'B5' '基线：探针连本机 IPv6 回环应成功' $false $v6Loop $r
        }

        # ---------- P：按程序的规则（和正式 P 层写法相同，只是程序换成探针）
        Write-Host ''
        $c = New-PtRule -Suffix 'P-v4' -Program $exeA -Local $local
        Add-PtResult 'P0a' '创建规则：探针从非隧道地址发出的 IPv4 一律阻止，并回读核对' $true (@($c.Problems).Count -eq 0) $c
        $c = New-PtRule -Suffix 'P-v6' -Program $exeA -Remote $script:CvgAllV6
        Add-PtResult 'P0b' '创建规则：探针的 IPv6 一律阻止，并回读核对' $true (@($c.Problems).Count -eq 0) $c

        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'P1' '加规则后：从物理网卡地址直连 VPS 应被防火墙拒绝' $true (Test-PtBlocked $r) $r
        $r = Invoke-PtProbe $exeB (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'P2' '对照：另一路径下的相同程序不受影响' $true (Test-PtConnected $r) $r
        $r = Invoke-PtProbe $exeA @('http', $ptEcho)
        Add-PtResult 'P3' '加规则后：经 VPN 访问回显服务仍成功，出口仍是 VPS' $true ((Test-PtConnected $r) -and ([string]$r.detail -eq $ptVps)) $r
        $r = Invoke-PtProbe $exeA @('tcp', '1.1.1.1', '443', $script:CvgTunAddress)
        Add-PtResult 'P4' '加规则后：显式使用隧道地址连公网仍成功' $true (Test-PtConnected $r) $r
        if ($udpBaseline) {
            $r = Invoke-PtProbe $exeA @('dns', '1.1.1.1', 'any')
            Add-PtResult 'P5' '加规则后：经 VPN 的 UDP 查询仍有应答' $true (Test-PtConnected $r) $r
        }
        $r = Invoke-PtProbe $exeA (@('udp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'P6' '加规则后：从物理网卡地址发 UDP 是否被系统拒绝（仅记录）' $false (Test-PtBlocked $r) $r
        $r = Invoke-PtProbe $exeA @('tcp', '127.0.0.1', [string]$port4, 'any')
        Add-PtResult 'P7' '加规则后：本机 IPv4 回环不受影响' $true (Test-PtConnected $r) $r
        if ($v6Loop) {
            $r = Invoke-PtProbe $exeA @('tcp', '::1', [string]$port6, 'any')
            Add-PtResult 'P8' '加规则后：本机 IPv6 回环不受影响' $true (Test-PtConnected $r) $r
        }

        # ---------- S：开关演练（和正式开关用同一个函数）
        Write-Host ''
        [void](Set-CvgRulesEnabled $ptPrefix $ptGroup $false)
        $w = Wait-PtRulesEnabled $false
        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'S1' '开关演练：关闭（停用规则）后，直连 VPS 恢复成功' $true ($w -and (Test-PtConnected $r)) $r
        [void](Set-CvgRulesEnabled $ptPrefix $ptGroup $true)
        $w = Wait-PtRulesEnabled $true
        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'S2' '开关演练：重新开启后，直连 VPS 再次被拒绝' $true ($w -and (Test-PtBlocked $r)) $r
        [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup)
        Start-Sleep -Milliseconds 500
        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'R1' '卸载（删除规则）后：直连 VPS 恢复成功' $true (Test-PtConnected $r) $r

        # ---------- D：按目的地的规则（和正式 D 层写法相同；为安全起见仍绑定探针程序，目的地用 VPS 代替 Anthropic）
        Write-Host ''
        $c = New-PtRule -Suffix 'D-v4' -Program $exeA -Local $local -Remote @($ptVps)
        Add-PtResult 'D0' '创建规则：「目的地址 + 非隧道源地址」组合条件，并回读核对' $true (@($c.Problems).Count -eq 0) $c
        $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
        Add-PtResult 'D1' '组合规则：从物理网卡地址连名单内的目的地应被拒绝' $true (Test-PtBlocked $r) $r
        $r = Invoke-PtProbe $exeA @('tcp', '1.1.1.1', '443', 'any')
        Add-PtResult 'D2' '组合规则：经 VPN 连名单外的目的地不受影响' $true (Test-PtConnected $r) $r
        [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup)
        $c = New-PtRule -Suffix 'D-v4s' -Program $exeA -Local $local -Remote $script:CvgAnthropicV4
        Add-PtResult 'D3' 'Anthropic IPv4 网段写法：创建并回读核对（不发流量）' $true (@($c.Problems).Count -eq 0) $c
        $c = New-PtRule -Suffix 'D-v6s' -Program $exeA -Remote $script:CvgAnthropicV6
        Add-PtResult 'D4' 'Anthropic IPv6 网段写法：创建并回读核对（不发流量）' $true (@($c.Problems).Count -eq 0) $c
        [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup)

        # ---------- W：可选加固「禁止走无线网卡」（仅供参考，不影响总结论）
        Write-Host ''
        $c = New-PtRule -Suffix 'W' -Program $exeA -InterfaceType 'Wireless'
        Add-PtResult 'W0' '可选加固：创建「探针禁止走无线网卡」规则' $false (@($c.Problems).Count -eq 0) $c
        if ($ptPhys.IfType -eq 71) {
            $r = Invoke-PtProbe $exeA (@('tcp', $ptVps, [string]$ptPort) + $physArgs)
            Add-PtResult 'W1' '可选加固：从无线网卡直连 VPS 被拒绝' $false (Test-PtBlocked $r) $r
        }
        $r = Invoke-PtProbe $exeA @('http', $ptEcho)
        Add-PtResult 'W2' '可选加固：经 VPN 访问回显服务不受影响' $false ((Test-PtConnected $r) -and ([string]$r.detail -eq $ptVps)) $r

        # ---------- C：清理与复核
        Write-Host ''
        [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup)
        $left = @(Get-CvgRules 'PersistentStore' ($ptPrefix + '*') $ptGroup).Count + @(Get-CvgRules 'ActiveStore' ($ptPrefix + '*') $ptGroup).Count
        Add-PtResult 'C1' '清理：探针规则已全部删除' $true ($left -eq 0) ('残留 {0} 条' -f $left)
        $ptFpAfter = Get-PtFirewallFingerprint
        $same = ($ptFpBefore.Count -eq $ptFpAfter.Count -and $ptFpBefore.Hash -eq $ptFpAfter.Hash)
        Add-PtResult 'C2' '清理：其他防火墙规则与测试前一致' $true $same ('测试前 {0} 条，测试后 {1} 条' -f $ptFpBefore.Count, $ptFpAfter.Count)
        $ptCompleted = $true
    }
} catch {
    $ptFatal = $_.Exception.Message
    Write-Host ''
    Write-Host ($(if ($ptCancelled) { '' } else { '中止：' }) + $ptFatal) -ForegroundColor $(if ($ptCancelled) { 'Yellow' } else { 'Red' })
} finally {
    # 无论成功、失败还是中途出错，都删除探针规则、停止监听、删除探针程序。
    if ($ptIsAdmin -and -not $ptDry -and -not $ptCancelled) {
        try { [void](Remove-CvgRulesByPrefix $ptPrefix $ptGroup) } catch { Write-Host ('清理探针规则时出错：' + $_.Exception.Message) -ForegroundColor Red }
    }
    foreach ($l in @($ptListener4, $ptListener6)) { if ($l) { try { $l.Stop() } catch { } } }
    if (Test-Path -LiteralPath $ptRunDir) { try { Remove-Item -LiteralPath $ptRunDir -Recurse -Force } catch { } }
}

# ============================================================ 结论与记录

$ptGateFailed = @($ptResults | Where-Object { $_.Gate -and -not $_.Passed })
$ptPassed = ($ptCompleted -and $null -eq $ptFatal -and $ptGateFailed.Count -eq 0)

Write-Host ''
if ($ptCancelled) {
    Write-Host '测试没有运行。'
} elseif ($ptDry) {
    if ($ptPassed) { Write-Host '预演通过：探针可以编译和运行，结果可以解析。没有创建规则，没有发出外网流量。' -ForegroundColor Green }
    else { Write-Host '预演没有通过，请先解决上面的问题。' -ForegroundColor Red }
} else {
    $leftNow = -1
    try { $leftNow = @(Get-CvgRules 'PersistentStore' ($ptPrefix + '*') $ptGroup).Count + @(Get-CvgRules 'ActiveStore' ($ptPrefix + '*') $ptGroup).Count } catch { }
    if ($ptPassed) { Write-Host '结论：全部必过项通过。规则写法和开关均有效，可以进入阶段 3（开启防护）。' -ForegroundColor Green }
    else { Write-Host ('结论：没有通过（必过项失败 {0} 项{1}）。请不要开启防护，把结果交给 Claude 分析。' -f $ptGateFailed.Count, $(if ($ptFatal) { '，并且测试中止' } else { '' })) -ForegroundColor Red }
    Write-Host ('探针规则残留：{0} 条' -f $leftNow) -ForegroundColor $(if ($leftNow -eq 0) { 'Green' } else { 'Red' })

    try {
        New-Item -ItemType Directory -Path $ptOutDir -Force | Out-Null
        $report = [ordered]@{
            Time = (Get-Date).ToString('o'); Passed = $ptPassed; Completed = $ptCompleted; Fatal = $ptFatal
            VpsAddress = $ptVps; VpsPort = $ptPort; EchoUrl = $ptEcho
            Vpn = $ptVpn; PhysicalSource = $ptPhys
            FirewallBefore = $ptFpBefore; FirewallAfter = $ptFpAfter; ProbeRulesLeft = $leftNow
            Results = $ptResults.ToArray()
        }
        [System.IO.File]::WriteAllText($ptOutDir + '\result.json', ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $lines.Add('Claude VPN Guard v2 探针测试  ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
        $lines.Add('结论：' + $(if ($ptPassed) { '全部必过项通过' } else { '没有通过' }))
        if ($ptFatal) { $lines.Add('中止原因：' + $ptFatal) }
        $lines.Add('探针规则残留：' + $leftNow + ' 条')
        $lines.Add('')
        foreach ($x in $ptResults) {
            $tag = if ($x.Passed) { '通过' } elseif ($x.Gate) { '失败' } else { '参考' }
            $lines.Add(('[{0}] {1} {2} -> {3}' -f $tag, $x.Id, $x.What, $x.ObservedText))
        }
        [System.IO.File]::WriteAllLines($ptOutDir + '\summary.txt', $lines.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ('结果已保存：' + $ptOutDir)
        if ($ptPassed) {
            $stateDir = Split-Path -Parent $script:CvgMarkerFile
            if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
            $marker = [ordered]@{ Time = (Get-Date).ToString('o'); Result = $ptOutDir + '\result.json'; TunAddress = $script:CvgTunAddress }
            [System.IO.File]::WriteAllText($script:CvgMarkerFile, ($marker | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
        }
    } catch {
        Write-Host ('保存结果时出错：' + $_.Exception.Message) -ForegroundColor Red
    }
}

if ($ptElevated) { Write-Host ''; [void](Read-Host '按回车键关闭窗口') }
if ($ptPassed) { exit 0 } else { exit 1 }
