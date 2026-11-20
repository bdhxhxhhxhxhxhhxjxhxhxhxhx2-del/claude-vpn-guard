#Requires -Version 5.1
<#
Claude VPN Guard v2 - 阶段 4：真实断线验收（Windows PowerShell 5.1）

在你手动断开、再重新连接 VPN 的过程中，自动记录并判定：
  1. 断开期间 Claude 有没有从非隧道地址联网（应该没有）；
  2. 同一时间，不受规则约束的对照程序能不能直连（证明网络本身是通的）；
  3. 受约束的探针程序发 TCP 和 UDP 是否都被拦住（UDP 用有应答的 DNS 查询判断）；
  4. 重连后 Claude 能否自动恢复联网，防护规则是否仍完整生效。
另外记录 Claude 启动的其他程序（例如 node）断开期间有没有直连——它们不在规则范围内，只作参考。

范围：临时规则只绑定探针程序自己的路径（名称以 CVG2T-S4- 开头），测试结束时删除；
      探针只连接你的 VPS、1.1.1.1、223.5.5.5 和本地网络的 DNS 服务器，不连接 Anthropic。
      测试期间占用防护开关的锁，避免同时开关防护。

用法：
  双击「断线验收.cmd」：确认在当前窗口完成，随后在后台以管理员身份执行，进度实时显示在当前窗口。
  powershell -NoProfile -ExecutionPolicy Bypass -File DisconnectTest.ps1 -DryRun
      预演：只编译探针、做本机回环自测和判定逻辑自测；不建规则、不发外网流量、不需要断开 VPN。
结果写入本目录下的 outputs\claude-guard-v2-disconnect-<时间>\。

注意：脚本里的中文只用于显示。文件须保存为带 BOM 的 UTF-8，否则中文会显示成乱码（不影响逻辑）。
#>
[CmdletBinding()]
param(
    [switch]$Worker,
    [string]$RunId = '',
    [switch]$DryRun,
    [int]$RecordSeconds = 45
)

$ErrorActionPreference = 'Stop'

# Guard.ps1 也有 -Worker、-RunId 参数：引用它之前，先把本脚本的参数和调用信息另存。
$dtWorker = [bool]$Worker
$dtRunId = $RunId
$dtDry = [bool]$DryRun
$dtRecord = [int][math]::Max(30, $RecordSeconds)
$dtInvocation = $MyInvocation.InvocationName
$dtScriptPath = $PSCommandPath
. ($PSScriptRoot + '\Guard.ps1')

# ============================================================ 配置

$dtGroup = 'ClaudeVpnGuard-v2-PROBE'
$dtPrefix = 'CVG2T-S4-'
$dtVps = ''                      # 填你 VPN 服务器的公网 IPv4 地址，例如 '203.0.113.10'：断开 VPN 后，用作从本地网络直连的 TCP 测试目标
$dtVpsPort = 443
$dtWebTarget = '223.5.5.5'       # 参考：普通外网地址
$dtTunnelTarget = '1.1.1.1'      # VPN 连接时经隧道测试用
$dtWaitDisconnect = 180          # 最多等你断开 VPN 的秒数
$dtWaitReconnect = 300           # 最多等你重新连接 VPN 的秒数
$dtRecoverySeconds = 120         # 重连后最多等 Claude 恢复联网的秒数
$dtMinRounds = 5                 # 断开期间至少测几轮

# 探针源码（与阶段 2 相同；C# 5 语法，用系统自带编译器编译）。只做最小的连接动作，不发送任何账号或业务数据。
$dtProbeSource = @'
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
        // 31 = IP_UNICAST_IF：把套接字固定到指定网卡。
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

    // 不指定源地址、不使用代理，向回显服务发一次 HTTPS GET；detail 是服务返回的文本。
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

# ============================================================ 采集

function Test-DtNonTunnelAddress {
    # 隧道地址、回环地址和未绑定地址以外的本地地址，都算「非隧道」。
    param([string]$Address)
    if ([string]::IsNullOrEmpty($Address)) { return $false }
    if ($Address -eq $script:CvgTunAddress) { return $false }
    if ($Address -in @('0.0.0.0', '::', '::1')) { return $false }
    if ($Address.StartsWith('127.')) { return $false }
    return $true
}

function Test-DtTunnelUp {
    $a = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $script:CvgTunAddress -ErrorAction SilentlyContinue)
    return (@($a | Where-Object { [string]$_.AddressState -eq 'Preferred' }).Count -ge 1)
}

function Get-DtClaudeSnapshot {
    # 记录 Claude 各进程（以及它们启动的子进程）当前的 TCP 连接，区分隧道地址和非隧道地址。
    param([string]$Phase, [switch]$KeepKeys)
    $programs = @{}
    foreach ($p in @(Get-CvgProgramPaths)) { $programs[$p.ToLowerInvariant()] = $true }
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate)
    $claude = @{}
    $names = @{}
    $created = @{}
    foreach ($p in $all) {
        $names[[int]$p.ProcessId] = [string]$p.Name
        $created[[int]$p.ProcessId] = $p.CreationDate
        $path = [string]$p.ExecutablePath
        if ([string]$p.Name -eq 'claude.exe' -or ($path -and $programs.ContainsKey($path.ToLowerInvariant()))) { $claude[[int]$p.ProcessId] = $true }
    }
    # 子孙进程（例如 Claude 启动的 node）：不在规则范围内，只作参考记录
    $children = @{}
    foreach ($p in $all) {
        $parent = [int]$p.ParentProcessId
        if (-not $children.ContainsKey($parent)) { $children[$parent] = New-Object 'System.Collections.Generic.List[int]' }
        $children[$parent].Add([int]$p.ProcessId)
    }
    $desc = @{}
    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    foreach ($id in @($claude.Keys)) { $queue.Enqueue([int]$id) }
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($children.ContainsKey($cur)) {
            foreach ($c in $children[$cur]) {
                # 子进程不可能比父进程早启动；早于父进程的是进程号被重复使用的无关进程
                $older = ($null -ne $created[$c] -and $null -ne $created[$cur] -and $created[$c] -lt $created[$cur])
                if ($c -ne $cur -and -not $older -and -not $claude.ContainsKey($c) -and -not $desc.ContainsKey($c)) { $desc[$c] = $true; $queue.Enqueue($c) }
            }
        }
    }
    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -in @('Established', 'SynSent') -and ($claude.ContainsKey([int]$_.OwningProcess) -or $desc.ContainsKey([int]$_.OwningProcess)) })
    $mine = @($tcp | Where-Object { $claude.ContainsKey([int]$_.OwningProcess) })
    $kids = @($tcp | Where-Object { $desc.ContainsKey([int]$_.OwningProcess) })
    $tunnel = @($mine | Where-Object { [string]$_.LocalAddress -eq $script:CvgTunAddress })
    $bad = @($mine | Where-Object { Test-DtNonTunnelAddress ([string]$_.LocalAddress) } | ForEach-Object {
        [pscustomobject]@{ Process = $names[[int]$_.OwningProcess]; Pid = [int]$_.OwningProcess; Local = ('{0}:{1}' -f $_.LocalAddress, $_.LocalPort); Remote = ('{0}:{1}' -f $_.RemoteAddress, $_.RemotePort); State = [string]$_.State }
    })
    $kidDirect = @($kids | Where-Object { Test-DtNonTunnelAddress ([string]$_.LocalAddress) } | ForEach-Object {
        [pscustomobject]@{ Process = $names[[int]$_.OwningProcess]; Pid = [int]$_.OwningProcess; Local = ('{0}:{1}' -f $_.LocalAddress, $_.LocalPort); Remote = ('{0}:{1}' -f $_.RemoteAddress, $_.RemotePort); State = [string]$_.State }
    })
    $keys = @()
    if ($KeepKeys) { $keys = @($tunnel | ForEach-Object { '{0}:{1}>{2}:{3}' -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort }) }
    return [pscustomobject]@{
        Phase = $Phase; Time = (Get-Date).ToString('o')
        ClaudeProcesses = $claude.Count; ChildProcesses = $desc.Count
        TunnelCount = $tunnel.Count; TunnelKeys = $keys
        Bad = $bad; ChildDirect = $kidDirect
    }
}

function Get-DtUdpServer {
    # 选一个按当前路由可直接到达的 DNS 服务器：优先默认出口网卡上设置的 DNS，其次 223.5.5.5。
    try {
        $choice = @(Find-NetRoute -RemoteIPAddress $dtWebTarget -ErrorAction Stop)
        $src = @($choice | Where-Object { $null -ne $_.IPAddress })
        if ($src.Count) {
            $servers = @((Get-DnsClientServerAddress -InterfaceIndex $src[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
            $pick = @($servers | Where-Object { $_ -and $_ -ne $script:CvgTunAddress -and $_ -notlike '127.*' })
            $server = if ($pick.Count) { [string]$pick[0] } else { $dtWebTarget }
            return [pscustomobject]@{ Server = $server; Source = [string]$src[0].IPAddress; Alias = [string]$src[0].InterfaceAlias }
        }
    } catch { }
    return [pscustomobject]@{ Server = $dtWebTarget; Source = ''; Alias = '' }
}

function Get-DtFirewallFingerprint {
    # 除临时探针规则外，全部持久规则的名称、启用状态、方向、动作的摘要，用于确认测试前后其他规则没有变化。
    $rows = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -notlike 'CVG2T-*' } |
        ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.Enabled, $_.Direction, $_.Action } | Sort-Object)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($rows -join "`n"))))).Replace('-', '') } finally { $sha.Dispose() }
    return [pscustomobject]@{ Count = $rows.Count; Hash = $hash }
}

# ============================================================ 探针

function Invoke-DtProbe {
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

function Test-DtBlockedTcp {
    # 10013 = WSAEACCES：被防火墙拒绝（阶段 2 实测也是这个值）。
    param($R)
    return ($null -ne $R -and $R.ok -ne $true -and [int]$R.nativeError -eq 10013)
}

function Format-DtProbe {
    param($R, [string]$Kind)
    if ($null -eq $R) { return '未运行' }
    if ($R.ok -eq $true) {
        if ($Kind -eq 'dns') { return '有应答' }
        return ('成功（本地 ' + [string]$R.local + '）')
    }
    if ([int]$R.nativeError -eq 10013) { return '被防火墙拒绝（10013）' }
    if ($Kind -eq 'dns' -and [int]$R.nativeError -eq 10060) { return '无应答' }
    return ('失败（错误码 {0}，{1}）' -f $R.nativeError, $R.detail)
}

function New-DtProbeRule {
    # 用和正式 P 层规则相同的写法，创建只针对探针程序的临时规则，并回读核对、等它生效。
    param([string]$Suffix, [string]$Program, [string[]]$Local, [string[]]$Remote)
    $name = $dtPrefix + $Suffix
    $spec = [pscustomobject]@{ Name = $name; Program = $Program; Local = $Local; Remote = $Remote; InterfaceType = $null }
    New-CvgBlockRule -Name $name -Group $dtGroup -DisplayName (Get-CvgDisplayName 'TEST' ((Get-CvgShortPath $Program) + ' ' + $Suffix)) -Program $Program -LocalAddress $Local -RemoteAddress $Remote -Enabled $true
    $rule = @(Get-CvgRules 'PersistentStore' $name $dtGroup)
    if ($rule.Count -ne 1) { throw ('临时规则没有创建成功：' + $name) }
    $problems = @(Get-CvgRuleProblems -Rule $rule[0] -Spec $spec -ExpectEnabled $true)
    if ($problems.Count) { throw ('临时规则复核不符：' + $name + '：' + ($problems -join '；')) }
    for ($i = 0; $i -lt 10; $i++) {
        $active = @(Get-CvgRules 'ActiveStore' $name $dtGroup)
        if ($active.Count -eq 1 -and [string]$active[0].Enabled -eq 'True' -and [string]$active[0].PrimaryStatus -eq 'OK') { Start-Sleep -Milliseconds 500; return }
        Start-Sleep -Milliseconds 300
    }
    throw ('临时规则没有生效：' + $name)
}

function Write-DtAct {
    # 需要你动手的步骤：青色显示并响两声（后台运行时由前台窗口负责响）。
    param([string]$Text)
    Write-CvgLine $Text 'act'
    if (-not $script:CvgProgressFile) { try { [Console]::Beep(988, 250); [Console]::Beep(1319, 300) } catch { } }
}

# ============================================================ 判定（纯计算，不读写系统）

function New-DtItem {
    param([string]$Id, [string]$What, [string]$Status, [string]$Detail)
    return [pscustomobject]@{ Id = $Id; What = $What; Status = $Status; Detail = $Detail }
}

function Get-DtVerdict {
    param($D)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $rounds = @($D.Rounds | Where-Object { $null -ne $_ })
    $off = @($D.OffSamples | Where-Object { $null -ne $_ })

    if ($D.DisconnectSeen) { $items.Add((New-DtItem 'V1' '检测到 VPN 断开' '通过' '')) }
    else { $items.Add((New-DtItem 'V1' '检测到 VPN 断开' '无法判定' '等待时间内没有检测到断开')) }

    $badTotal = 0
    foreach ($s in $off) { $badTotal += @($s.Bad | Where-Object { $null -ne $_ }).Count }
    $what = '断开期间 Claude 没有从非隧道地址联网'
    if ($badTotal -gt 0) { $items.Add((New-DtItem 'V2' $what '未通过' ('发现 {0} 个非隧道连接' -f $badTotal))) }
    elseif ($off.Count -ge 5) { $items.Add((New-DtItem 'V2' $what '通过' ('采样 {0} 次，每次都是 0 个' -f $off.Count))) }
    else { $items.Add((New-DtItem 'V2' $what '无法判定' ('只采样了 {0} 次' -f $off.Count))) }

    $ctlOk = @($rounds | Where-Object { $_.ControlTcp.ok -eq $true })
    $what = '断开期间网络本身是通的（对照程序能直连 VPS）'
    if ($ctlOk.Count -gt 0) { $items.Add((New-DtItem 'V3' $what '通过' ('{0}/{1} 轮直连成功' -f $ctlOk.Count, $rounds.Count))) }
    else { $items.Add((New-DtItem 'V3' $what '无法判定' '对照程序也连不上，分不清是规则还是网络本身的原因')) }

    $boundOk = @($rounds | Where-Object { $_.BoundTcp.ok -eq $true })
    $blocked = @($ctlOk | Where-Object { Test-DtBlockedTcp $_.BoundTcp })
    $what = '断开期间受约束探针的 TCP 被防火墙拒绝'
    if ($boundOk.Count -gt 0) { $items.Add((New-DtItem 'V4' $what '未通过' ('受约束探针有 {0} 轮直连成功' -f $boundOk.Count))) }
    elseif ($ctlOk.Count -ge 2 -and $blocked.Count -eq $ctlOk.Count) { $items.Add((New-DtItem 'V4' $what '通过' ('对照能直连的 {0} 轮里，全部被拒绝（10013）' -f $blocked.Count))) }
    else { $items.Add((New-DtItem 'V4' $what '无法判定' ('有效轮次 {0}，其中被拒绝 {1}' -f $ctlOk.Count, $blocked.Count))) }

    $dnsCtl = @($rounds | Where-Object { $_.ControlDns.ok -eq $true })
    $dnsBound = @($rounds | Where-Object { $_.BoundDns.ok -eq $true })
    $what = '断开期间受约束探针的 UDP 也被拦住（DNS 收不到应答）'
    if ($dnsBound.Count -gt 0) { $items.Add((New-DtItem 'V5' $what '未通过' ('受约束探针有 {0} 轮收到了应答' -f $dnsBound.Count))) }
    elseif ($dnsCtl.Count -ge 2) { $items.Add((New-DtItem 'V5' $what '通过' ('对照有应答的 {0} 轮里，受约束探针都没有收到应答' -f $dnsCtl.Count))) }
    else { $items.Add((New-DtItem 'V5' $what '无法判定' ('对照只有 {0} 轮收到应答，不足以判断' -f $dnsCtl.Count))) }

    if ($D.ReconnectSeen) { $items.Add((New-DtItem 'V6' '检测到 VPN 重新连接' '通过' '')) }
    else { $items.Add((New-DtItem 'V6' '检测到 VPN 重新连接' '无法判定' '等待时间内没有检测到重连')) }

    $what = '重连后 Claude 自动恢复联网'
    if (-not $D.ReconnectSeen) { $items.Add((New-DtItem 'V7' $what '无法判定' '没有检测到重连')) }
    elseif ([int]$D.RecoveryNewConnections -gt 0) { $items.Add((New-DtItem 'V7' $what '通过' ('重连后约 {0} 秒出现 {1} 个新的隧道连接' -f $D.RecoverySeconds, $D.RecoveryNewConnections))) }
    else { $items.Add((New-DtItem 'V7' $what '无法判定' ('{0} 秒内没有看到新的隧道连接（Claude 可能处于空闲）' -f $dtRecoverySeconds))) }

    $ra = $D.RulesAfter
    $what = '测试结束时防护规则仍完整生效'
    if ($null -eq $ra) { $items.Add((New-DtItem 'V8' $what '无法判定' '没有读取到')) }
    else {
        $missing = @($ra.Missing | Where-Object { $null -ne $_ }).Count
        $activeBad = @($ra.ActiveProblems | Where-Object { $null -ne $_ }).Count
        if ($ra.Switch -eq 'On' -and $missing -eq 0 -and $activeBad -eq 0) { $items.Add((New-DtItem 'V8' $what '通过' '')) }
        else { $items.Add((New-DtItem 'V8' $what '未通过' ('开关为 {0}，缺少 {1} 条，生效异常 {2} 条' -f $ra.Switch, $missing, $activeBad))) }
    }

    $what = '重连后受约束探针经隧道正常（规则不影响隧道流量）'
    if (-not $D.ReconnectSeen) { $items.Add((New-DtItem 'V9' $what '无法判定' '没有检测到重连')) }
    else {
        $tcpOk = ($null -ne $D.RecoveryTcp -and $D.RecoveryTcp.ok -eq $true)
        $dnsOk = ((-not $D.BaselineDnsOk) -or ($null -ne $D.RecoveryDns -and $D.RecoveryDns.ok -eq $true))
        $controlDnsOk = ($null -ne $D.RecoveryControlDns -and $D.RecoveryControlDns.ok -eq $true)
        if ($tcpOk -and $dnsOk) { $items.Add((New-DtItem 'V9' $what '通过' '')) }
        elseif ($tcpOk -and $controlDnsOk) { $items.Add((New-DtItem 'V9' $what '未通过' '对照程序能经隧道查 DNS，受约束探针不能：规则可能挡住了隧道里的 UDP')) }
        elseif ($tcpOk) { $items.Add((New-DtItem 'V9' $what '无法判定' '重连后经隧道的 DNS 查询，对照和探针都没有应答（隧道的 UDP 可能还没就绪）')) }
        else { $items.Add((New-DtItem 'V9' $what '无法判定' '重连后探针经隧道没有连通')) }
    }

    $childList = @($off | ForEach-Object { @($_.ChildDirect) } | Where-Object { $null -ne $_ })
    $what = 'Claude 启动的其他程序（如 node）断开期间没有直连（不在规则范围内，仅供参考）'
    if ($childList.Count -eq 0) { $items.Add((New-DtItem 'V10' $what '通过' '')) }
    else {
        $distinct = @($childList | ForEach-Object { [string]$_.Process + ' -> ' + [string]$_.Remote } | Sort-Object -Unique)
        $items.Add((New-DtItem 'V10' $what '注意' ('{0} 条记录：{1}' -f $childList.Count, (($distinct | Select-Object -First 6) -join '；'))))
    }

    if ([int]$D.TempRulesLeft -eq 0) { $items.Add((New-DtItem 'C1' '临时探针规则已删除' '通过' '')) }
    elseif ([int]$D.TempRulesLeft -lt 0) { $items.Add((New-DtItem 'C1' '临时探针规则已删除' '无法判定' '没有读取到')) }
    else { $items.Add((New-DtItem 'C1' '临时探针规则已删除' '未通过' ('残留 {0} 条，可用使用说明里的紧急回滚命令删除' -f $D.TempRulesLeft))) }

    if ($D.FingerprintSame -eq $true) { $items.Add((New-DtItem 'C2' '其他防火墙规则与测试前一致' '通过' '')) }
    elseif ($null -eq $D.FingerprintSame) { $items.Add((New-DtItem 'C2' '其他防火墙规则与测试前一致' '无法判定' '没有比较')) }
    else { $items.Add((New-DtItem 'C2' '其他防火墙规则与测试前一致' '注意' '测试前后有变化（可能是其他软件改的）')) }

    $byId = @{}
    foreach ($it in $items) { $byId[$it.Id] = $it.Status }
    $hardFail = @(@('V2', 'V4', 'V5', 'V8') | Where-Object { $byId[$_] -eq '未通过' }).Count
    $gateMiss = @(@('V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7', 'V8', 'V9') | Where-Object { $byId[$_] -ne '通过' }).Count
    if ($hardFail -gt 0) { $verdict = '未通过' }
    elseif ($byId['V1'] -ne '通过' -or $byId['V3'] -ne '通过' -or $byId['V4'] -ne '通过') { $verdict = '证据不足' }
    elseif ($gateMiss -eq 0) { $verdict = '通过' }
    else { $verdict = '部分通过' }
    return [pscustomobject]@{ Verdict = $verdict; Items = $items.ToArray() }
}

# ============================================================ 正式测试（需要管理员）

function Invoke-DtTest {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $runDir = $PSScriptRoot + '\disconnect-run-' + $stamp
    $outDir = $PSScriptRoot + '\outputs\claude-guard-v2-disconnect-' + $stamp
    $exeA = $runDir + '\cvg-probe-a.exe'   # 受临时规则约束的探针
    $exeB = $runDir + '\cvg-probe-b.exe'   # 对照：内容相同、路径不同，不受约束
    $D = @{
        DisconnectSeen = $false; ReconnectSeen = $false; OffSamples = @(); Rounds = @()
        RecoveryNewConnections = 0; RecoverySeconds = $dtRecoverySeconds; RulesAfter = $null
        RecoveryTcp = $null; RecoveryDns = $null; RecoveryControlDns = $null; BaselineDnsOk = $false
        TempRulesLeft = -1; FingerprintSame = $null; Fatal = $null
    }
    $samples = New-Object 'System.Collections.Generic.List[object]'
    $rounds = New-Object 'System.Collections.Generic.List[object]'
    $baseline = $null
    $times = [ordered]@{ Start = (Get-Date).ToString('o'); Disconnected = $null; Reconnected = $null; End = $null }
    $udp = $null
    $fpBefore = $null
    $lock = $null
    try {
        $lock = Enter-CvgLock

        # ---------- 1. 检查（只读）
        Write-CvgLine '[1/6] 检查防护、VPN 和 Claude……'
        $state = Get-CvgState
        if ($state.Switch -ne 'On' -or @($state.Missing).Count -or @($state.ActiveProblems).Count) {
            throw '防护没有完整开启。请先双击「开启防护.cmd」，看到「规则齐全且已生效」后再做断线验收。'
        }
        if (-not $state.Vpn.Connected) { throw 'VPN 没有连接。请先在 Amnezia 里连接 VPN。' }
        $snap = Get-DtClaudeSnapshot 'baseline' -KeepKeys
        for ($i = 0; $i -lt 5 -and $snap.ClaudeProcesses -gt 0 -and $snap.TunnelCount -eq 0; $i++) { Start-Sleep -Seconds 2; $snap = Get-DtClaudeSnapshot 'baseline' -KeepKeys }
        $samples.Add($snap)
        if ($snap.ClaudeProcesses -eq 0) { throw '没有发现正在运行的 Claude。请先打开 Claude 再做断线验收。' }
        Write-CvgLine ('      VPN：{0}' -f $state.Vpn.Note)
        Write-CvgLine ('      Claude 进程 {0} 个；经隧道的连接 {1} 个；非隧道连接 {2} 个' -f $snap.ClaudeProcesses, $snap.TunnelCount, @($snap.Bad).Count)
        if ($snap.TunnelCount -eq 0) { Write-CvgLine '      注意：Claude 目前没有连接，重连后的恢复检查可能看不到结果。' 'warn' }
        $baselineKeys = @{}
        foreach ($k in @($snap.TunnelKeys)) { $baselineKeys[$k] = $true }

        # ---------- 2. 探针和临时规则
        Write-CvgLine '[2/6] 编译探针，并创建只针对探针的临时规则……'
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
        $exe0 = $runDir + '\cvg-probe.exe'
        Add-Type -TypeDefinition $dtProbeSource -Language CSharp -OutputAssembly $exe0 -OutputType ConsoleApplication -IgnoreWarnings -ErrorAction Stop
        Copy-Item -LiteralPath $exe0 -Destination $exeA
        Copy-Item -LiteralPath $exe0 -Destination $exeB
        $leftover = @(Get-CvgRules 'PersistentStore' ($dtPrefix + '*') $dtGroup)
        if ($leftover.Count) { [void](Remove-CvgRulesByPrefix $dtPrefix $dtGroup $leftover) }
        $fpBefore = Get-DtFirewallFingerprint
        $local = @(Get-CvgV4Complement $script:CvgTunAddress)
        New-DtProbeRule -Suffix 'P-v4' -Program $exeA -Local $local -Remote $null
        New-DtProbeRule -Suffix 'P-v6' -Program $exeA -Local $null -Remote $script:CvgAllV6
        Write-CvgLine '      临时规则已创建并生效（只约束探针 cvg-probe-a.exe）'

        # ---------- 3. 基线（VPN 连接时）
        Write-CvgLine '[3/6] 基线测试（VPN 连接时，经隧道）……'
        $b1 = Invoke-DtProbe $exeB @('tcp', $dtTunnelTarget, '443', 'any')
        $b2 = Invoke-DtProbe $exeA @('tcp', $dtTunnelTarget, '443', 'any')
        $b3 = Invoke-DtProbe $exeB @('dns', $dtTunnelTarget, 'any')
        $b4 = Invoke-DtProbe $exeA @('dns', $dtTunnelTarget, 'any')
        $baseline = [ordered]@{ ControlTcp = $b1; BoundTcp = $b2; ControlDns = $b3; BoundDns = $b4 }
        Write-CvgLine ('      TCP：对照 {0}；受约束探针 {1}' -f (Format-DtProbe $b1 'tcp'), (Format-DtProbe $b2 'tcp'))
        Write-CvgLine ('      UDP：对照查 DNS {0}；受约束探针查 DNS {1}' -f (Format-DtProbe $b3 'dns'), (Format-DtProbe $b4 'dns'))
        if ($b1.ok -ne $true -or $b2.ok -ne $true) { throw '基线没有通过：VPN 连接时探针经隧道连不上外网，无法区分断线后的结果。' }
        if ($b3.ok -eq $true -and $b4.ok -ne $true) { throw '基线没有通过：VPN 连接时受约束探针经隧道的 DNS 查询没有应答。' }
        $D.BaselineDnsOk = ($b3.ok -eq $true -and $b4.ok -eq $true)

        # ---------- 4. 等你断开 VPN
        Write-DtAct '[4/6] 现在请切到 Amnezia，断开 VPN 连接（只断开 VPN，不要关 Wi-Fi）。'
        Write-CvgLine ('      断开后这里会自动开始记录，最多等 {0} 秒……' -f $dtWaitDisconnect)
        $t0 = Get-Date
        $lastNote = $t0
        while ((Test-DtTunnelUp) -and ((Get-Date) - $t0).TotalSeconds -lt $dtWaitDisconnect) {
            Start-Sleep -Milliseconds 500
            if (((Get-Date) - $lastNote).TotalSeconds -ge 15) { $lastNote = Get-Date; Write-CvgLine ('      仍在等待 VPN 断开（已等 {0} 秒）……' -f [int]((Get-Date) - $t0).TotalSeconds) }
        }
        if (Test-DtTunnelUp) { throw ('{0} 秒内没有检测到 VPN 断开，测试结束。' -f $dtWaitDisconnect) }
        $D.DisconnectSeen = $true
        $tOff = Get-Date
        $times.Disconnected = $tOff.ToString('o')
        Write-CvgLine ('检测到 VPN 已断开（{0}）。开始记录约 {1} 秒；这期间 Claude 会断网，这是预期的。' -f $tOff.ToString('HH:mm:ss'), $dtRecord) 'warn'
        Start-Sleep -Seconds 3
        $udp = Get-DtUdpServer
        Write-CvgLine ('      当前出口网卡：{0}（{1}）；UDP 测试用的 DNS 服务器：{2}' -f $udp.Alias, $udp.Source, $udp.Server)
        $n = 0
        while ($true) {
            $n++
            $s1 = Get-DtClaudeSnapshot 'disconnected'
            $samples.Add($s1)
            $r = [ordered]@{ Round = $n; Seconds = [int]((Get-Date) - $tOff).TotalSeconds }
            $r.ControlTcp = Invoke-DtProbe $exeB @('tcp', $dtVps, [string]$dtVpsPort, 'any')
            $r.BoundTcp = Invoke-DtProbe $exeA @('tcp', $dtVps, [string]$dtVpsPort, 'any')
            $r.Web = Invoke-DtProbe $exeB @('tcp', $dtWebTarget, '443', 'any')
            $r.ControlDns = Invoke-DtProbe $exeB @('dns', $udp.Server, 'any')
            $r.BoundDns = Invoke-DtProbe $exeA @('dns', $udp.Server, 'any')
            $s2 = Get-DtClaudeSnapshot 'disconnected'
            $samples.Add($s2)
            $r.ClaudeBad = @($s1.Bad).Count + @($s2.Bad).Count
            $rounds.Add([pscustomobject]$r)
            Write-CvgLine ('      第 {0} 轮（断开后 {1} 秒）：Claude 非隧道连接 {2} 个' -f $n, $r.Seconds, $r.ClaudeBad) $(if ($r.ClaudeBad) { 'err' } else { 'info' })
            Write-CvgLine ('            TCP：对照直连 VPS {0}；受约束探针 {1}；对照直连 {2} {3}' -f (Format-DtProbe $r.ControlTcp 'tcp'), (Format-DtProbe $r.BoundTcp 'tcp'), $dtWebTarget, (Format-DtProbe $r.Web 'tcp'))
            Write-CvgLine ('            UDP：对照查 DNS {0}；受约束探针查 DNS {1}' -f (Format-DtProbe $r.ControlDns 'dns'), (Format-DtProbe $r.BoundDns 'dns'))
            if (Test-DtTunnelUp) { Write-CvgLine '      VPN 已经重新连上，提前结束记录。' 'warn'; break }
            if ($n -ge $dtMinRounds -and ((Get-Date) - $tOff).TotalSeconds -ge $dtRecord) { break }
            Start-Sleep -Seconds 1
        }

        # ---------- 5. 等你重新连接
        if (-not (Test-DtTunnelUp)) {
            Write-DtAct '[5/6] 记录完成。现在请在 Amnezia 里重新连接 VPN。'
            Write-CvgLine ('      最多等 {0} 秒；这期间继续记录 Claude 的连接……' -f $dtWaitReconnect)
            $t1 = Get-Date
            $lastNote = $t1
            $lastSample = [datetime]::MinValue
            while ((-not (Test-DtTunnelUp)) -and ((Get-Date) - $t1).TotalSeconds -lt $dtWaitReconnect) {
                if (((Get-Date) - $lastSample).TotalSeconds -ge 3) { $samples.Add((Get-DtClaudeSnapshot 'wait-reconnect')); $lastSample = Get-Date }
                Start-Sleep -Milliseconds 500
                if (((Get-Date) - $lastNote).TotalSeconds -ge 15) { $lastNote = Get-Date; Write-CvgLine ('      仍在等待 VPN 重新连接（已等 {0} 秒）……' -f [int]((Get-Date) - $t1).TotalSeconds) }
            }
        }
        if (Test-DtTunnelUp) {
            $D.ReconnectSeen = $true
            $tOn = Get-Date
            $times.Reconnected = $tOn.ToString('o')
            Write-CvgLine ('[6/6] 检测到 VPN 已恢复（{0}），正在确认 Claude 恢复联网，最多等 {1} 秒……' -f $tOn.ToString('HH:mm:ss'), $dtRecoverySeconds)
            Start-Sleep -Seconds 5
            for ($i = 0; $i -lt 3; $i++) {
                $D.RecoveryTcp = Invoke-DtProbe $exeA @('tcp', $dtTunnelTarget, '443', 'any')
                if ($D.RecoveryTcp.ok -eq $true) { break }
                Start-Sleep -Seconds 3
            }
            if ($D.BaselineDnsOk) {
                # 重连后隧道里的 UDP 可能要过一会儿才就绪：最多试 3 次；仍不通时让对照程序也查一次，用来区分原因。
                for ($i = 0; $i -lt 3; $i++) {
                    $D.RecoveryDns = Invoke-DtProbe $exeA @('dns', $dtTunnelTarget, 'any')
                    if ($D.RecoveryDns.ok -eq $true) { break }
                    Start-Sleep -Seconds 3
                }
                if ($D.RecoveryDns.ok -ne $true) { $D.RecoveryControlDns = Invoke-DtProbe $exeB @('dns', $dtTunnelTarget, 'any') }
            }
            $dnsText = ''
            if ($D.BaselineDnsOk) {
                $dnsText = '；DNS ' + (Format-DtProbe $D.RecoveryDns 'dns')
                if ($null -ne $D.RecoveryControlDns) { $dnsText += '（对照 ' + (Format-DtProbe $D.RecoveryControlDns 'dns') + '）' }
            }
            Write-CvgLine ('      受约束探针经隧道：TCP {0}{1}' -f (Format-DtProbe $D.RecoveryTcp 'tcp'), $dnsText)
            $newCount = 0
            while (((Get-Date) - $tOn).TotalSeconds -lt $dtRecoverySeconds) {
                $s = Get-DtClaudeSnapshot 'recovery' -KeepKeys
                $samples.Add($s)
                $new = @(@($s.TunnelKeys) | Where-Object { -not $baselineKeys.ContainsKey($_) })
                if ($new.Count -gt 0) { $newCount = $new.Count; $D.RecoverySeconds = [int]((Get-Date) - $tOn).TotalSeconds; break }
                Start-Sleep -Seconds 2
            }
            $D.RecoveryNewConnections = $newCount
            if ($newCount -gt 0) { Write-CvgLine ('      Claude 已恢复联网：重连后约 {0} 秒出现 {1} 个新的隧道连接' -f $D.RecoverySeconds, $newCount) 'ok' }
            else { Write-CvgLine ('      {0} 秒内没有看到 Claude 新的隧道连接' -f $dtRecoverySeconds) 'warn' }
        } else {
            Write-CvgLine ('{0} 秒内没有检测到 VPN 重新连接。' -f $dtWaitReconnect) 'warn'
        }

        $after = Get-CvgState
        $D.RulesAfter = [pscustomobject]@{
            Switch = $after.Switch
            Missing = @(@($after.Missing) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Name })
            ActiveProblems = @(@($after.ActiveProblems) | Where-Object { $null -ne $_ })
        }
        Write-CvgLine ('      防护规则：开关 {0}；缺少 {1} 条；生效异常 {2} 条' -f $after.Switch, @($D.RulesAfter.Missing).Count, @($D.RulesAfter.ActiveProblems).Count)
    } catch {
        $D.Fatal = $_.Exception.Message
        Write-CvgLine ('中止：' + $D.Fatal) 'err'
    } finally {
        Write-CvgLine '正在清理临时规则和探针程序……'
        try { [void](Remove-CvgRulesByPrefix $dtPrefix $dtGroup) } catch { Write-CvgLine ('清理临时规则时出错：' + $_.Exception.Message) 'err' }
        try { $D.TempRulesLeft = @(Get-CvgRules 'PersistentStore' ($dtPrefix + '*') $dtGroup).Count + @(Get-CvgRules 'ActiveStore' ($dtPrefix + '*') $dtGroup).Count } catch { $D.TempRulesLeft = -1 }
        if ($null -ne $fpBefore) {
            try { $fpAfter = Get-DtFirewallFingerprint; $D.FingerprintSame = ($fpAfter.Count -eq $fpBefore.Count -and $fpAfter.Hash -eq $fpBefore.Hash) } catch { }
        }
        if (Test-Path -LiteralPath $runDir) { try { Remove-Item -LiteralPath $runDir -Recurse -Force } catch { } }
        Exit-CvgLock $lock
    }

    # ---------- 判定、显示、保存
    $times.End = (Get-Date).ToString('o')
    $D.OffSamples = @($samples | Where-Object { $_.Phase -in @('disconnected', 'wait-reconnect') })
    $D.Rounds = $rounds.ToArray()
    $v = Get-DtVerdict $D
    $level = switch ($v.Verdict) { '通过' { 'ok' } '部分通过' { 'warn' } default { 'err' } }
    Write-CvgLine ''
    Write-CvgLine ('===== 结论：' + $v.Verdict + ' =====') $level
    if ($D.Fatal) { Write-CvgLine ('中止原因：' + $D.Fatal) 'err' }
    if ($D.Fatal -and -not $D.DisconnectSeen) {
        Write-CvgLine '没有进入断线阶段，未做逐项判定。'
        Write-CvgLine ('临时规则残留：{0} 条' -f $D.TempRulesLeft) $(if ($D.TempRulesLeft -eq 0) { 'ok' } else { 'err' })
    } else {
        foreach ($it in $v.Items) {
            $lv = switch ($it.Status) { '通过' { 'ok' } '未通过' { 'err' } default { 'warn' } }
            $line = '[{0}] {1} {2}' -f $it.Status, $it.Id, $it.What
            if ($it.Detail) { $line += '：' + $it.Detail }
            Write-CvgLine $line $lv
        }
    }
    try {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $report = [ordered]@{
            Verdict = $v.Verdict; Items = $v.Items; Fatal = $D.Fatal; Times = $times
            RecordSeconds = $dtRecord; Vps = $dtVps; WebTarget = $dtWebTarget; TunnelTarget = $dtTunnelTarget; UdpServer = $udp
            Baseline = $baseline; Rounds = $D.Rounds
            RecoveryTcp = $D.RecoveryTcp; RecoveryDns = $D.RecoveryDns; RecoveryControlDns = $D.RecoveryControlDns; RecoveryNewConnections = $D.RecoveryNewConnections; RecoverySeconds = $D.RecoverySeconds
            RulesAfter = $D.RulesAfter; TempRulesLeft = $D.TempRulesLeft; FingerprintSame = $D.FingerprintSame
            Samples = $samples.ToArray()
        }
        [System.IO.File]::WriteAllText($outDir + '\result.json', ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $lines.Add('Claude VPN Guard v2 断线验收  ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
        $lines.Add('结论：' + $v.Verdict)
        if ($D.Fatal) { $lines.Add('中止原因：' + $D.Fatal) }
        $lines.Add(('时间：开始 {0}；断开 {1}；重连 {2}；结束 {3}' -f $times.Start, $times.Disconnected, $times.Reconnected, $times.End))
        if ($udp) { $lines.Add(('断开时出口网卡：{0}（{1}）；UDP 测试 DNS 服务器：{2}' -f $udp.Alias, $udp.Source, $udp.Server)) }
        $lines.Add('')
        foreach ($it in $v.Items) { $lines.Add(('[{0}] {1} {2}{3}' -f $it.Status, $it.Id, $it.What, $(if ($it.Detail) { '：' + $it.Detail } else { '' }))) }
        $lines.Add('')
        $lines.Add('逐轮记录：')
        foreach ($r in $D.Rounds) {
            $lines.Add(('第 {0} 轮（断开后 {1} 秒）：Claude 非隧道连接 {2} 个；TCP 对照 {3}，受约束 {4}，对照直连 {5} {6}；UDP 对照 {7}，受约束 {8}' -f $r.Round, $r.Seconds, $r.ClaudeBad, (Format-DtProbe $r.ControlTcp 'tcp'), (Format-DtProbe $r.BoundTcp 'tcp'), $dtWebTarget, (Format-DtProbe $r.Web 'tcp'), (Format-DtProbe $r.ControlDns 'dns'), (Format-DtProbe $r.BoundDns 'dns')))
        }
        [System.IO.File]::WriteAllLines($outDir + '\summary.txt', $lines.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
        Write-CvgLine ('结果已保存：' + $outDir)
    } catch {
        Write-CvgLine ('保存结果时出错：' + $_.Exception.Message) 'err'
    }
    if (-not (Test-DtTunnelUp)) { Write-DtAct 'VPN 目前仍是断开状态：请在 Amnezia 里重新连接。' }
    if ($v.Verdict -in @('通过', '部分通过')) { return 0 }
    return 1
}

# ============================================================ 预演（不需要管理员）

function New-DtFakeProbe {
    param([bool]$Ok, [int]$Err)
    return [pscustomobject]@{ mode = 'fake'; ok = $Ok; local = ''; target = ''; nativeError = $Err; status = 0; detail = '' }
}

function New-DtFakeData {
    # 生成判定逻辑自测用的模拟数据。
    param([int]$Rounds = 6, [bool]$ControlTcp = $true, [bool]$BoundTcpOk = $false, [bool]$ControlDns = $true, [bool]$BoundDnsOk = $false,
          [int]$ClaudeBad = 0, [bool]$Disconnect = $true, [bool]$Reconnect = $true, [int]$Recovered = 3,
          [bool]$RecoveryDnsOk = $true, [bool]$RecoveryControlDnsOk = $false)
    $rs = @(for ($i = 1; $i -le $Rounds; $i++) {
        [pscustomobject]@{
            Round = $i; Seconds = $i * 7; ClaudeBad = 0
            ControlTcp = (New-DtFakeProbe $ControlTcp $(if ($ControlTcp) { 0 } else { 10060 }))
            BoundTcp = (New-DtFakeProbe $BoundTcpOk $(if ($BoundTcpOk) { 0 } else { 10013 }))
            Web = (New-DtFakeProbe $true 0)
            ControlDns = (New-DtFakeProbe $ControlDns $(if ($ControlDns) { 0 } else { 10060 }))
            BoundDns = (New-DtFakeProbe $BoundDnsOk $(if ($BoundDnsOk) { 0 } else { 10060 }))
        }
    })
    $ss = @(for ($i = 1; $i -le ($Rounds * 2); $i++) {
        $bad = @()
        if ($ClaudeBad -gt 0 -and $i -eq 2) { $bad = @([pscustomobject]@{ Process = 'claude.exe'; Pid = 1; Local = '10.0.0.5:5000'; Remote = '203.0.113.9:443'; State = 'Established' }) }
        [pscustomobject]@{ Phase = 'disconnected'; Time = ''; ClaudeProcesses = 3; ChildProcesses = 0; TunnelCount = 0; TunnelKeys = @(); Bad = $bad; ChildDirect = @() }
    })
    if (-not $Disconnect) { $rs = @(); $ss = @() }
    return @{
        DisconnectSeen = $Disconnect; ReconnectSeen = $Reconnect; OffSamples = $ss; Rounds = $rs
        RecoveryNewConnections = $Recovered; RecoverySeconds = 8
        RulesAfter = [pscustomobject]@{ Switch = 'On'; Missing = @(); ActiveProblems = @() }
        RecoveryTcp = (New-DtFakeProbe $true 0)
        RecoveryDns = (New-DtFakeProbe $RecoveryDnsOk $(if ($RecoveryDnsOk) { 0 } else { 10060 }))
        RecoveryControlDns = $(if ($RecoveryDnsOk) { $null } else { New-DtFakeProbe $RecoveryControlDnsOk $(if ($RecoveryControlDnsOk) { 0 } else { 10060 }) })
        BaselineDnsOk = $true
        TempRulesLeft = 0; FingerprintSame = $true; Fatal = $null
    }
}

function Get-DtSelfTestCases {
    return @(
        [pscustomobject]@{ Name = '全部正常'; Expect = '通过'; Data = (New-DtFakeData) },
        [pscustomobject]@{ Name = 'Claude 出现非隧道连接'; Expect = '未通过'; Data = (New-DtFakeData -ClaudeBad 1) },
        [pscustomobject]@{ Name = '受约束探针 TCP 直连成功'; Expect = '未通过'; Data = (New-DtFakeData -BoundTcpOk $true) },
        [pscustomobject]@{ Name = '受约束探针收到 DNS 应答'; Expect = '未通过'; Data = (New-DtFakeData -BoundDnsOk $true) },
        [pscustomobject]@{ Name = '对照 DNS 全都没有应答'; Expect = '部分通过'; Data = (New-DtFakeData -ControlDns $false) },
        [pscustomobject]@{ Name = '对照 TCP 也连不上'; Expect = '证据不足'; Data = (New-DtFakeData -ControlTcp $false) },
        [pscustomobject]@{ Name = '没有检测到断开'; Expect = '证据不足'; Data = (New-DtFakeData -Disconnect $false) },
        [pscustomobject]@{ Name = '重连后没看到 Claude 新连接'; Expect = '部分通过'; Data = (New-DtFakeData -Recovered 0) },
        [pscustomobject]@{ Name = '断开时间太短（只测了 1 轮）'; Expect = '证据不足'; Data = (New-DtFakeData -Rounds 1) },
        [pscustomobject]@{ Name = '没有等到重连'; Expect = '部分通过'; Data = (New-DtFakeData -Reconnect $false) },
        [pscustomobject]@{ Name = '重连后探针 DNS 不通、对照通'; Expect = '部分通过'; Data = (New-DtFakeData -RecoveryDnsOk $false -RecoveryControlDnsOk $true) },
        [pscustomobject]@{ Name = '重连后 DNS 对照和探针都不通'; Expect = '部分通过'; Data = (New-DtFakeData -RecoveryDnsOk $false -RecoveryControlDnsOk $false) }
    )
}

function Invoke-DtDryRun {
    Write-CvgLine ''
    Write-CvgLine '===== 断线验收：预演（不建规则、不发外网流量、不需要断开 VPN） ====='
    $ok = $true
    $vpn = Get-CvgVpnInfo
    Write-CvgLine ('VPN：' + $vpn.Note)
    Write-CvgLine ('隧道地址检测：' + $(if (Test-DtTunnelUp) { '在' } else { '不在' }))
    $snap = Get-DtClaudeSnapshot 'dry' -KeepKeys
    Write-CvgLine ('Claude 进程 {0} 个，子进程 {1} 个；经隧道的连接 {2} 个；非隧道连接 {3} 个；子进程非隧道连接 {4} 个' -f $snap.ClaudeProcesses, $snap.ChildProcesses, $snap.TunnelCount, @($snap.Bad).Count, @($snap.ChildDirect).Count)
    foreach ($c in @(@($snap.ChildDirect) | Select-Object -First 5)) { Write-CvgLine ('      子进程非隧道连接：{0} {1} -> {2}' -f $c.Process, $c.Local, $c.Remote) 'warn' }
    $udp = Get-DtUdpServer
    Write-CvgLine ('按当前路由，UDP 测试会用的 DNS 服务器：{0}（{1}，{2}）' -f $udp.Server, $udp.Alias, $udp.Source)

    $dir = $PSScriptRoot + '\disconnect-dry-' + (Get-Date).ToString('yyyyMMdd-HHmmss')
    $listener = $null
    try {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $exe0 = $dir + '\cvg-probe.exe'
        Add-Type -TypeDefinition $dtProbeSource -Language CSharp -OutputAssembly $exe0 -OutputType ConsoleApplication -IgnoreWarnings -ErrorAction Stop
        Copy-Item -LiteralPath $exe0 -Destination ($dir + '\cvg-probe-a.exe')
        Copy-Item -LiteralPath $exe0 -Destination ($dir + '\cvg-probe-b.exe')
        $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::Loopback), 0
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        foreach ($name in @('cvg-probe-a.exe', 'cvg-probe-b.exe')) {
            $r = Invoke-DtProbe ($dir + '\' + $name) @('tcp', '127.0.0.1', [string]$port, 'any')
            $pass = ($r.ok -eq $true)
            if (-not $pass) { $ok = $false }
            Write-CvgLine ('{0} 连本机回环：{1}' -f $name, (Format-DtProbe $r 'tcp')) $(if ($pass) { 'ok' } else { 'err' })
        }
    } catch {
        $ok = $false
        Write-CvgLine ('探针自测出错：' + $_.Exception.Message) 'err'
    } finally {
        if ($listener) { try { $listener.Stop() } catch { } }
        if (Test-Path -LiteralPath $dir) { try { Remove-Item -LiteralPath $dir -Recurse -Force } catch { } }
    }

    Write-CvgLine '判定逻辑自测（模拟数据）：'
    foreach ($case in @(Get-DtSelfTestCases)) {
        $v = Get-DtVerdict $case.Data
        $pass = ($v.Verdict -eq $case.Expect)
        if (-not $pass) { $ok = $false }
        Write-CvgLine ('      {0}：预期「{1}」，得到「{2}」' -f $case.Name, $case.Expect, $v.Verdict) $(if ($pass) { 'ok' } else { 'err' })
    }
    if ($ok) { Write-CvgLine '预演通过：没有创建规则，没有发出外网流量。' 'ok'; return 0 }
    Write-CvgLine '预演没有通过。' 'err'
    return 1
}

# ============================================================ 前台窗口

function Confirm-DtStart {
    Write-CvgLine '这个测试会真实断开一次 VPN，验证 Claude 会不会跟着断网、重连后能否自动恢复。全程约 3 到 6 分钟。'
    Write-CvgLine ''
    Write-CvgLine '  1. 开始前请确认：VPN 已连接，Claude 正在运行。'
    Write-CvgLine '  2. 按 Y 后，窗口会提示你去 Amnezia 里断开 VPN（只断开 VPN，不要关 Wi-Fi）。'
    Write-CvgLine ('  3. 断开后脚本自动记录约 {0} 秒，然后窗口会响两声，提示你重新连接 VPN。' -f $dtRecord)
    Write-CvgLine '  4. 断开期间 Claude（包括正在和你对话的 Claude）会掉线，这是预期效果；重连后会自动恢复。'
    Write-CvgLine '  5. 测试过程中请不要关闭这个窗口。'
    Write-CvgLine ''
    $vpn = Get-CvgVpnInfo
    if (-not $vpn.Connected) { Write-CvgLine 'VPN 现在没有连接。请先在 Amnezia 里连接 VPN，再重新运行。' 'err'; return $false }
    Write-CvgLine '按 Y 开始，其他键取消（60 秒无操作自动取消）。' 'warn'
    if ((Read-CvgKey 60) -eq 'Y') { return $true }
    Write-CvgLine '已取消，没有做任何改动。'
    return $false
}

function Invoke-DtViaWorker {
    # 前台窗口没有管理员权限：在后台启动隐藏的管理员进程执行测试，并把它的进度显示在当前窗口。
    $logDir = $script:CvgRunDir
    if (-not $logDir) { throw '找不到当前用户的 AppData 目录，无法显示后台进度。' }
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $id = ([guid]::NewGuid().ToString('N')).Substring(0, 12)
    $progress = $logDir + '\run-' + $id + '.txt'
    [System.IO.File]::WriteAllText($progress, '', (New-Object System.Text.UTF8Encoding($false)))
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Worker -RunId {1} -RecordSeconds {2}' -f $dtScriptPath, $id, $dtRecord
    Write-CvgLine '正在以管理员身份在后台执行，进度会显示在这个窗口里（不会另外弹出窗口）……'
    try {
        $proc = Start-Process -FilePath ($env:SystemRoot + '\System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $argLine -Verb RunAs -WindowStyle Hidden -PassThru -ErrorAction Stop
    } catch {
        throw ('无法以管理员身份启动：' + $_.Exception.Message)
    }
    $code = Watch-CvgProgress -Path $progress -Process $proc -TimeoutSeconds 1500
    try {
        Get-ChildItem -LiteralPath $logDir -Filter 'run-*.txt' -File | Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
    return $code
}

# 被其他脚本以 ". DisconnectTest.ps1" 方式引用时只提供函数，不执行任何动作。
if ($dtInvocation -ne '.') {
    if ($dtWorker) {
        if ($dtRunId -notmatch '^[0-9a-f]{12}$') { exit 2 }
        if (-not $script:CvgRunDir) { exit 2 }
        $script:CvgProgressFile = $script:CvgRunDir + '\run-' + $dtRunId + '.txt'
    }
    $dtCode = 0
    try {
        # 正式测试必须先填 VPN 服务器地址（预演不需要）；没填时直接停下，不做任何改动。
        $dtVpsIp = $null
        if (-not $dtDry -and -not ([System.Net.IPAddress]::TryParse($dtVps, [ref]$dtVpsIp) -and [string]$dtVpsIp.AddressFamily -eq 'InterNetwork')) {
            throw ('还没有填 VPN 服务器地址，或者格式不对（当前为「{0}」）。请用记事本打开 DisconnectTest.ps1，在开头 $dtVps 一行填上你 VPN 服务器的公网 IPv4 地址，保存后重新运行。' -f $dtVps)
        }
        if ($dtDry) {
            $dtCode = [int](@(Invoke-DtDryRun)[-1])
        } elseif ($dtWorker) {
            if (-not (Test-CvgAdmin)) { throw '后台进程没有拿到管理员权限。' }
            $dtCode = [int](@(Invoke-DtTest)[-1])
        } else {
            try { $Host.UI.RawUI.WindowTitle = 'Claude VPN 防护 - 断线验收' } catch { }
            Write-CvgLine ''
            Write-CvgLine '===== Claude VPN 防护：断线验收（阶段 4） ====='
            if (Confirm-DtStart) {
                if (Test-CvgAdmin) { $dtCode = [int](@(Invoke-DtTest)[-1]) }
                else { $dtCode = [int](@(Invoke-DtViaWorker)[-1]) }
            }
        }
    } catch {
        Write-CvgLine ('错误：' + $_.Exception.Message) 'err'
        $dtCode = 1
    } finally {
        if ($dtWorker) { Add-CvgProgress ("DONE`t" + [string]$dtCode) }
    }
    exit $dtCode
}
