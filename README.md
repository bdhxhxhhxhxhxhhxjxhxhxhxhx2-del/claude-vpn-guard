# Claude VPN Guard（Claude 断网防护）

用 Windows 防火墙让 Claude 桌面端和 Claude Code 只能经 VPN 隧道联网。VPN 断开时，Claude 的连接会被直接拦下，不会退回本地网络直连。

*A Windows Firewall kill switch that keeps Claude Desktop and Claude Code on your VPN tunnel. Scripts and docs are in Chinese.*

> 非 Anthropic 官方项目，与 Anthropic 无关。

## 工作原理

两层出站阻止规则，由 Windows 防火墙执行，没有常驻进程。规则一直在防火墙里，Claude 开着、关着、电脑重启都有效。

| 层 | 对谁 | 拦什么 |
|---|---|---|
| 按程序 | 每个 Claude 程序：桌面端、更新程序、桌面端内置的 Claude Code、独立安装的 Claude Code（`%USERPROFILE%\.local\bin\claude.exe`） | 本机地址不是隧道地址（或回环地址）的全部 IPv4 连接；全部 IPv6 连接 |
| 按目的地 | 本机所有程序 | 从非隧道地址连接 [Anthropic 公布的网段](https://platform.claude.com/docs/en/api/ip-addresses) |

- VPN 断开时隧道地址随之消失，Claude 的新连接在建立时就被拒绝，没有空窗。
- 规则不限网卡和网络类型，换 Wi-Fi、热点、网线都有效。
- 只操作名称以 `CVG2-` 开头的规则，不碰其他防火墙规则。

## 适用范围

这是作者给自己的电脑写的，只在下面这套环境里测试过：

- Windows 11，系统自带的 Windows PowerShell 5.1，管理员账户
- AmneziaVPN，Xray 协议：隧道网卡 `tun2socks Tunnel`，固定地址 `10.33.0.2`

其他 VPN 需要自己改配置并重新测试，见[用于其他 VPN](#用于其他-vpn)。脚本界面是中文的。

## 快速开始

1. 下载 zip 后，先右键 zip →「属性」→ 勾选「解除锁定」，再解压。不然双击 `.cmd` 时会弹安全警告。
2. 用记事本打开 `ProbeTest.ps1`，在开头的 `$VpsAddress` 填上你 VPN 服务器的公网 IPv4 地址（也就是经 VPN 上网时的出口 IP）。要做断线验收的话，`DisconnectTest.ps1` 开头的 `$dtVps` 也要填。保存时保持「带 BOM 的 UTF-8」编码。
3. 连上 VPN，双击 `查看状态.cmd`，确认「VPN 隧道」一行显示已连接。
4. 双击 `运行探针测试.cmd`。它编译一个临时探针程序来验证规则写法，只给探针加临时规则，结束时全部删除，不涉及 Claude。通过后才能开启防护。
5. 双击 `开启防护.cmd`。然后到 Claude 发一条消息，确认仍能正常使用；如果不能用，双击 `关闭防护.cmd` 即可恢复。
6. 双击 `安装自动补登记.cmd`。Claude 每次更新都会装到新路径，它会注册一个以系统身份运行的计划任务，登录 2 分钟后运行一次、之后每 30 分钟运行一次，把新路径登记进规则。
7. 可选：双击 `断线验收.cmd`，按提示手动断开、再重连一次 VPN，验证 Claude 会跟着断网、重连后自动恢复。

修改防火墙的操作会弹出 UAC 确认框，点「是」即可。

## 日常使用

| 文件 | 作用 |
|---|---|
| `查看状态.cmd` | 显示开关和 VPN 状态，逐条核对规则（只读） |
| `开启防护.cmd` | 开启；同时补登记 Claude 更新后的新程序 |
| `关闭防护.cmd` | 关闭：只停用规则，可随时再开启 |
| `卸载防护.cmd` | 删除本工具创建的全部规则 |
| `安装自动补登记.cmd` / `卸载自动补登记.cmd` | 安装或删除自动补登记计划任务 |

更多细节见 [使用说明.md](使用说明.md)。

## 用于其他 VPN

前提是 VPN 用 TUN 模式，并且隧道网卡上的本机 IPv4 地址固定不变。只开系统代理、不开 TUN 的用法不支持。

改 `Guard.ps1` 开头这两行：

```powershell
$script:CvgTunAddress  = '10.33.0.2'            # 隧道网卡上的本机 IPv4 地址
$script:CvgTunDesc     = 'tun2socks Tunnel'     # 隧道网卡的设备描述
```

改完后：

1. 重新运行探针测试。
2. 如果装过自动补登记，再运行一次 `安装自动补登记.cmd`。启动器优先使用 `C:\ProgramData\ClaudeVpnGuardV2` 里的副本，不更新的话改动不生效。
3. 如果已经开启过防护，先「卸载防护」再「开启防护」。开启只补建缺少的规则，不会按新地址重建已有规则。

探针测试和断线验收假设 VPN 服务器地址就是出口 IP（自建服务器一般如此）。

## 已知边界

- **DNS 查询**：由 Windows 的 DNS 服务代查。VPN 断开时，查询会发给当前网络的 DNS 服务器，对方能看到查询的域名，但 Claude 仍连不上。
- **系统代理**：如果开着其他代理软件作为系统代理，Claude 会经本机代理端口出去，规则管不到。
- **其他程序**：Claude 启动的子程序（例如 node）和用 npm 安装的 Claude Code 不在按程序拦截的范围内，只拦它们连 Anthropic 网段。
- **更新空窗**：Claude 新版本最多约 30 分钟后才被自动补登记。期间它连不上 Anthropic，但能连第三方服务。
- **地址碰撞**：如果某个网络恰好把隧道地址分给了本机网卡，会被当成隧道放行。
- **非管理员账户**：提权后脚本在另一个账户下运行，找不到当前用户的 Claude。
- **防火墙被接管**：如果第三方安全软件关闭或接管了 Windows 防火墙，规则不会生效。「查看状态」会检查防火墙服务和配置文件是否启用。
- **测试范围**：IPv6 拦截只验证到规则层面；断线验收只在一种网络环境下做过。
- **网段更新**：Anthropic 网段写在 `Guard.ps1` 开头（2026 年 11 月核对），有变化需要手动更新。

## 卸载和紧急回滚

正常卸载：依次双击 `卸载自动补登记.cmd` 和 `卸载防护.cmd`。

紧急情况下不依赖任何脚本，在管理员 PowerShell 里运行：

```powershell
Get-NetFirewallRule -Name 'CVG2*' | Remove-NetFirewallRule
Unregister-ScheduledTask -TaskPath '\ClaudeVpnGuardV2\' -TaskName 'AutoSync' -Confirm:$false
```

第一行删除本工具的全部防火墙规则，第二行删除计划任务。安装目录 `C:\ProgramData\ClaudeVpnGuardV2` 可以手动删除。

## 免责声明

本项目按原样提供，不保证在所有环境下有效。它会修改 Windows 防火墙和计划任务，请先读懂脚本再使用。使用者需自行遵守所用服务的条款和当地法律。

## 许可证

[MIT](LICENSE)
