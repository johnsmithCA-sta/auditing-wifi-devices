# 局域网设备审计（auditing-wifi-devices）

扫描本地网段 → 识别每台接入设备 → 与历史台账对比 → 输出以「变化 + 可疑项」为主的报告。

用于排查：网速突然变慢想先排除被蹭网 ｜ 路由器后台出现不认识的设备 ｜ 收到账号异地登录通知。

## 特点

- **默认只读**：不踢设备、不拉黑、不改密码与固件。仅在用户逐条确认后，可代改两类设置——上网限时名单增删、IP-MAC 绑定增删改
- **写前过闸**：先读后写、逐条确认、回读留痕；缺当前值、确认不明确、设备未知、回读不符，一律不动
- **零依赖**：仅 Python 标准库，无第三方包
- **本地处理**：设备清单与主机名不出本机；在线查厂商默认关闭，需显式开启且只外发单个 MAC
- **自动适配网络**：网段按当前默认路由出口探测，换 WiFi、多网卡、挂 VPN 都不必改参数
- **可复核**：每台设备都给出判定依据与置信度，不是黑盒结论
- **分清「幽灵条目」**：ARP 里有 MAC 不等于有实体（路由器会替已离网设备代答）；长期零响应的条目只点名、不判离线
- **厂商库可扩展**：一键获取社区厂商注册表到本地，支持 24/28/36 位前缀匹配，不联网也能定厂商

## 用法

```bash
python3 skills/auditing-wifi-devices/scripts/lan_scan.py --out report.md
```

首次运行会在当前工作目录建立该网段的设备台账；再次运行只报告「新出现 / 已消失 / IP 变更」。

首次使用可先获取厂商库（下载公开注册数据到本机，不外发任何设备信息）：

```bash
python3 skills/auditing-wifi-devices/scripts/fetch_oui.py
```

两条命令要在**同一个目录**执行：厂商库缓存与台账都按当前工作目录找，分开跑会退回「厂商全空」。

报告打开后先看开头一行：

```text
- 结论（有没有陌生设备在网）：无 —— 12 台均能对应到已知设备，无新增 MAC
```

完整说明（触发场景、分步流程、边界与红线）见 [`skills/auditing-wifi-devices/SKILL.md`](skills/auditing-wifi-devices/SKILL.md)。

## 依赖

- Python 3.8+
- 可选命令：`fping`（更快的存活探测，缺失时自动降级为 ping）、`dns-sd`（macOS；mDNS 浏览目前仅 macOS 支持）

## 目录

```text
skills/auditing-wifi-devices/
├── SKILL.md                        # 行为规范：触发、流程、边界
├── scripts/
│   ├── lan_scan.py                 # 扫描脚本（纯标准库）
│   ├── fetch_oui.py                # 一键获取本地厂商库
│   └── write_guard.py              # 受控写的两段式校验（prepare / verify）
├── references/
│   ├── device-fingerprints.md      # 识别判据、厂商映射、路由器后台入口
│   ├── router-console.md           # 接管路由器后台：读页面与受控写
│   └── Changelog.md                # 版本说明
└── evals/                          # 回归用例（run_all / mutation_check）
```

## 开发与回归

改动后跑 `python3 skills/auditing-wifi-devices/evals/run_all.py`，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可

MIT
