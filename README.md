# 局域网设备审计（auditing-wifi-devices）

扫描本地网段 → 识别每台接入设备 → 与历史台账对比 → 输出只含「变化 + 可疑项」的报告。

用于排查：网速突然变慢想先排除被蹭网 ｜ 路由器后台出现不认识的设备 ｜ 收到账号异地登录通知。

## 特点

- **只读**：不踢设备、不改路由器配置、不动白名单
- **零依赖**：仅 Python 标准库，无第三方包
- **本地处理**：设备清单与主机名不出本机；在线查厂商默认关闭，需显式开启且只外发单个 MAC
- **自动适配网络**：网段按当前默认路由出口探测，换 WiFi、多网卡、挂 VPN 都不必改参数
- **可复核**：每台设备都给出判定依据与置信度，不是黑盒结论

## 用法

```bash
python3 skills/auditing-wifi-devices/scripts/lan_scan.py --out report.md
```

首次运行会在当前目录建立该网段的设备台账；再次运行只报告「新出现 / 已消失 / IP 变更」。

完整说明（触发场景、分步流程、边界与红线）见 [`skills/auditing-wifi-devices/SKILL.md`](skills/auditing-wifi-devices/SKILL.md)。

## 依赖

- Python 3.8+
- 可选命令：`fping`（更快的存活探测，缺失时自动降级为 ping）、`dns-sd`（macOS，mDNS 浏览）、`avahi-browse`（Linux）

## 目录

```
skills/auditing-wifi-devices/
├── SKILL.md                        # 行为规范：触发、流程、边界
├── scripts/lan_scan.py             # 扫描脚本（纯标准库）
├── references/
│   ├── device-fingerprints.md      # 厂商映射、主机名获取、路由器后台入口
│   └── Changelog.md                # 版本说明
└── evals/
    ├── smoke_test.py               # 回归自检（改动脚本后运行）
    └── trigger_eval.json           # 触发用例
```

## 许可

MIT
