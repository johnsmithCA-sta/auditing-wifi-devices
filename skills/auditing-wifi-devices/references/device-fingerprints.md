---
加载条件: 需要把某个 MAC / 服务自报判定为具体设备类型，或需要拿到设备主机名，或要对接路由器后台核对设备列表时
核心主题: 识别判据优先级 / OUI 数据来源与前缀位数 / 常见厂商 OUI → 设备类型映射 / 随机 MAC 处理 / 主机名获取路径 / 常见路由器后台入口 / 服务自报指纹
命中标签: OUI 库, manuf, IEEE, MA-M, MA-S, 28 位, 36 位, 端口指纹, SSDP, mDNS, 随机 MAC, 主机名, 路由器后台
不回答: 扫描与台账的流程步骤（改看 `../SKILL.md`）
---

> **本文件目录**：[一、识别判据优先级](#一识别判据优先级) ｜ [二、常见厂商 OUI → 设备类型](#二常见厂商-oui--设备类型) ｜ [三、服务自报指纹（SSDP / mDNS）](#三服务自报指纹ssdp--mdns) ｜ [四、随机 MAC](#四随机-mac) ｜ [五、主机名获取路径](#五主机名获取路径) ｜ [六、常见家用路由器后台入口](#六常见家用路由器后台入口) ｜ [七、隐私与合规](#七隐私与合规)

## 一、识别判据优先级

设备类型判定按下列顺序取**首个命中的高置信判据**，不要凭 MAC 前缀猜具体型号。

| 优先级 | 判据 | 置信 | 说明 |
|---|---|---|---|
| 1 | SSDP/UPnP 自报的设备类型（NT 字段） | 高 | 设备自己声明，可信度高于其他判据 |
| 2 | SSDP 的 SERVER 字段（含型号串） | 高 | 常直接带设备型号 |
| 3 | 端口指纹（专有端口） | 中高 | 见 [§三 端口指纹表](#端口指纹主动全端口扫描)；对**随机 MAC 尤其有用**——OUI 走不通时它是主要的主动判据 |
| — | mDNS 服务实例名 | 辅助 | **不参与自动判定**，脚本只作佐证列出；能拿到可读名称，但不一定能对应到 IP |
| 4 | MAC 的 OUI 厂商 | 中 | 只到厂商级，整机型号不可见；随机 MAC 查不到 |
| 5 | 未知（含随机 MAC） | 低 | 列入待确认，转 §五 取主机名 |

**写入报告时必须带判据来源**：同一台设备同时有 SSDP 与 OUI 时，取 SSDP 并注明「SSDP 自报」，置信度高。

## 二、常见厂商 OUI → 设备类型

下表为**厂商级**判定，只回答「谁造的」，不回答「什么型号」。型号要靠 SSDP SERVER 串或设备自报。

| 设备类别 | OUI 厂商（关键词） | 常见设备类型 |
|---|---|---|
| 手机 / 平板 | Apple | iPhone / iPad / Mac / HomePod / Apple TV |
| | Guangdong OPPO / OnePlus / realme | OPPO 系手机 |
| | Xiaomi Communications | 小米手机 |
| | vivo Mobile / Dongguan | vivo 手机 |
| | Huawei / Honor | 华为、荣耀手机 |
| | Samsung Electronics | 三星手机 / 平板 / 电视 |
| | HMD Global | Nokia 手机 |
| 电视 / 影音 | Hisense / TCL / Skyworth / Changhong / Konka | 国产电视与电视盒子 |
| | Sony / LG | 电视、影音与游戏主机 |
| | Amlogic (Xiamen) | 电视盒子主控 |
| 智能音箱 / 助手 | Baidu Online Network | 小度音箱与智能屏 |
| | Alibaba / TmallGenie | 天猫精灵音箱 |
| | Amazon Technologies | Echo 音箱 / Kindle / Fire TV |
| | Google / Nest | Chromecast / Nest 系列 |
| | Sonos | Sonos 音箱 |
| 路由器 / 网关 | TP-Link / Shenzhen Mercury (Mercusys) | TP-Link、水星路由器与网卡 |
| | Huawei / Xiaomi / ASUS / Netgear / ZTE | 各品牌家用路由器与网关 |
| 安防摄像头 | Hikvision / Dahua / Uniview / EZVIZ | 安防摄像头与 NVR |
| 智能家居 | 米家 Xiaomi / 绿米 Aqara / 涂鸦 Tuya / ORVIBO 欧瑞博 | 智能插座、开关、传感器、灯具 |
| | Haier / Midea / Yeelight | 智能家电与照明 |
| | Tianjin Hualai Technology | 智能家居 / 消费类电子设备 |
| | Cloud Network Technology (Singapore) | 消费类电子设备 |
| IoT 模组 | Quectel / Fibocom | 蜂窝与 IoT 模组设备（智能插座、追踪器、CPE） |
| | Espressif | ESP8266 / ESP32 类 IoT 模组 |
| 打印机 | HP / Epson / Canon / Brother | 打印机（配合 9100 端口更准） |
| 电脑 / 网卡 | Intel Corporate | 网卡级——只能判定为「搭载 Intel 网卡的电脑」 |
| | Dell / Lenovo / HP / Apple | 各品牌电脑整机 |
| | Realtek / Broadcom | 网卡级模组，不指示整机品牌 |
| 游戏机 | Nintendo / Sony / Microsoft (Xbox) | Switch / PlayStation / Xbox |
| 开发板 | Raspberry Pi Foundation | 树莓派 |
| 芯片方案 | HiSilicon / MediaTek / Qualcomm | 芯片方案商——只能判定模组，不能定整机 |

**注意**：路由器自身的 MAC 与它的 LAN 侧 MAC 可能不同；整机厂商用 Intel / Realtek 网卡时，OUI 只能定到网卡厂商，报告中应写作「网卡级」而非具体品牌电脑。

### OUI 数据来源与前缀位数

本地库一键获取（在技能根目录执行）：`python3 scripts/fetch_oui.py`（落运行目录 `oui-vendors/`，只下载公开注册数据，不碰本机 MAC；`--check` 可随时核对实际条数）。

| 来源 | 条目量级 | 说明 |
|---|---|---|
| Wireshark manuf（默认） | 约 5.8 万 | 社区主流单文件：合并 IEEE 三表 + IAB + Patton 清单，每条含短名与全名，周更 |
| IEEE 官方 oui.csv / mam.csv / oui36.csv（`--ieee`） | 合计约 5.4 万 | 权威源，作补充；官网下载慢（分钟级） |

**前缀位数（查库必须是最长前缀匹配）**：

| 位宽 | hex 位数 | 注册表 | 说明 |
|---|---|---|---|
| 24 位 | 6 | MA-L（传统 OUI） | 老设备主流 |
| 28 位 | 7 | MA-M | 2015 年后新增，小批量厂商 |
| 36 位 | 9 | MA-S | 更小的块，IoT/模组常见 |

manuf 里的写法：`00:55:DA:00/28`（7 位）、`00:1B:C5:00:00/36`（9 位）——脚本按掩码截断后入表，查找按 9→7→6 顺序命中即返回。**只查前 6 位会把 28/36 位块设备误判成「未收录」**（例：`40:ED:98:3A:00:01` → Knox Company，只能靠 MA-M 命中）。

## 三、服务自报指纹（SSDP / mDNS）

### SSDP 的 NT 字段

| NT 值 | 设备类型 |
|---|---|
| `urn:schemas-upnp-org:device:InternetGatewayDevice:1` | 路由器 / 网关 |
| `urn:schemas-upnp-org:device:MediaRenderer:1` | 音箱、电视、投屏接收端 |
| `urn:schemas-upnp-org:device:MediaServer:1` | NAS / DLNA 媒体服务器 |
| `urn:schemas-upnp-org:device:Printer:1` 或含 `printer` / `ipp` | 打印机 |
| `urn:schemas-upnp-org:device:Basic:1` | 通用 UPnP 设备（多为 IoT） |

SSDP 的 `SERVER` 字段常直接带型号，例如 `vxWorks/5.5 UPnP/1.0 <型号>/1.0` —— 这类字符串可直接作为高置信判据。

### mDNS 服务类型

| 服务类型 | 设备类型 |
|---|---|
| `_airplay._tcp` / `_raop._tcp` | AirPlay 接收端（Apple 设备、音箱、电视） |
| `_companion-link._tcp` | Apple 设备 |
| `_ipp._tcp` / `_printer._tcp` | 打印机 |
| `_smb._tcp` | 开启文件共享的电脑 / NAS |
| `_hap._tcp` | HomeKit 配件 |
| `_googlecast._tcp` | Chromecast / Google 音箱 |
| `_mi-connect._udp` | 小米设备 |
| `_workstation._tcp` | Windows 工作站 |

**mDNS 实例名无法直接反查 IP**（需额外两步查询），报告中作为辅助佐证列出即可，不要强行绑定到某台主机。

### 端口指纹（主动全端口扫描）

脚本首轮已内置**精选强特征端口**的探测（判定优先级见 §一），几秒即可完成。当 SSDP 自报拿不到、OUI 也查不到（**随机 MAC 设备几乎必然如此**）、且首轮端口未命中时，再对目标做全端口 1–65535 扫描（并发 `connect_ex` 即可，无需 nmap），并对开放端口发 banner 探测。

| 端口 | 含义 | 可判定为 |
|---|---|---|
| **62078** | Apple **lockdownd**（设备同步/配对服务） | **iOS 设备（iPhone / iPad / iPod）**——截至常见系统版本，macOS 不监听此口，可与 Apple OUI 设备区分开 |
| 49152+ | 系统动态端口，iOS 常见 AirPlay/服务端口 | 与 62078 同现时佐证 iOS |
| 7000 | AirTunes / AirPlay 音频 | AirPlay 接收端（HomePod、音箱、Apple TV） |
| 9100 | JetDirect 打印 | 打印机 |
| 554 / 8554 | RTSP 流 | 网络摄像头 / NVR |
| 8009 | Cast 协议 | Chromecast / Google TV |
| 445 / 139 | SMB | Windows 电脑 / NAS |
| 3389 | RDP | Windows 电脑 |
| 5353 / 1900 | mDNS / SSDP | 系统服务，不区分设备 |

**响应行为也是判据**：
- **TCP 握手成功但任何写入立即 `Connection reset`** → 典型的「只接受已配对/白名单主机」，与 Apple lockdownd 行为一致；
- 握手成功但读超时无 banner → 客户端应用的监听 socket（私有协议），只能定到「带应用服务的智能设备」一级，不可再深挖。

**交叉验证是必须的**：把同一批端口探到已知设备上（如基线里的 Apple / 手机 / IoT），确认某端口确实是**该设备族独有**，再下结论。避免把某台设备偶开的高位端口当成厂商特征。

**交叉验证示例**：一台随机 MAC 设备，OUI 与 SSDP/mDNS 全部落空，全端口扫描仅 62078 + 49152 开放、建连即 RST；把同批端口探到同网两台 Apple（macOS）设备上，均不监听 62078 ⇒ 判定为 iOS 设备，中高置信。

## 四、随机 MAC

**判定**：MAC 首字节的 U/L 位（0x02 位）为 1 即为本地管理地址，也就是操作系统启用的私有 Wi-Fi 地址（iOS / Android / Windows 默认开启）。

**表现**：厂商库查不到（接口返回 Not Found 属正常），无开放端口，多数不回应 ICMP。

**处理原则**：**不标记为可疑**——隐私特性导致的不可查是设计使然，报告须写明原因。

**定性路径**（按成本从低到高，与 SKILL.md 一致）：

1. **端口指纹**（网络侧就能做完，成本低）：OUI 永远查不到，但设备仍会开监听端口——脚本内置的精选强特征端口首轮即可给出判据（见 §三 端口指纹表），需要更深线索再做全端口扫描 + banner 探测。
2. 取 §五 的 DHCP 客户端列表**主机名**（权威度高于其他判据，但需登录路由器后台）；
3. 引导用户在设备上关闭该网络的「私有 Wi-Fi 地址」后重连。

⚠️ **白名单注意**：**固定 MAC 白名单对随机 MAC 设备天然失效**——设备每次重连/换网络都可能生成新地址，白名单里的旧条目将永远匹配不到，「长期离线」很可能只是「地址轮换了」。核对白名单时遇到随机 MAC 条目查无，**先判断是真离线还是已换地址**，不要直接断言设备丢失；要让白名单稳定，必须在设备端关闭该网络的私有地址。

## 五、主机名获取路径

按优先级排列。主机名是定性随机 MAC 设备的**权威来源**。

| 路径 | 可行性 | 说明 |
|---|---|---|
| 路由器 DHCP 客户端列表 | ★ 首选 | 含主机名，且覆盖当前休眠的设备（只要租约未过期） |
| 设备端关闭私有地址后重连 | ★ 首选 | 真实 MAC 出现后可直接查厂商 |
| mDNS / Bonjour 自报 | 中 | 只覆盖会广播服务的设备 |
| NetBIOS 名称 | 中 | 主要覆盖 Windows |
| 路由器 DNS 反向解析（PTR） | 低 | 多数家用路由器不注册反向记录，常只返回 IP 反写 |
| 被动监听 DHCP 报文 | 低 | 需绑定 67/68 特权端口，普通权限下不可行 |

**实用手法**：设备只在 DHCP 注册时上报主机名。遇到主机名缺失或显示为未知时，让该设备**断开 Wi-Fi 再重连**（或重启设备）即可触发上报，随后刷新路由器列表。

**关键认知：开随机 MAC ≠ 拿不到主机名**。开着私有地址的随机 MAC 设备，照样可能在 DHCP 列表里上报主机名——**厂商私有命名规则与 MAC 随机化是两套独立机制**。因此 DHCP 列表始终是第一顺位，不要因为「MAC 是随机的」就跳过它直接下结论说无法定性；只有 DHCP 里显示「匿名主机」的（多为 iOS 与部分 IoT，不主动上报主机名）才需退到端口指纹、关闭私有地址或物理核对。

## 六、常见家用路由器后台入口

用于与扫描结果交叉核对（路径名因固件版本略有差异，以「已连接设备 / DHCP 客户端 / 客户端列表」为准）。

| 品牌 | 登录地址 | 设备列表位置 |
|---|---|---|
| 水星 MERCURY / Mercusys | `melogin.cn` 或路由器 LAN IP | 已连接设备 / DHCP 服务器-客户端列表 |
| TP-Link | `tplinkwifi.net` 或 `192.168.1.1` | 已连接设备 / DHCP 客户端列表 |
| 小米 / Redmi | `miwifi.com` 或 `192.168.31.1` | 终端设备 / 连接设备 |
| 华为 / 荣耀 | `192.168.3.1`（部分 `192.168.8.1`） | 终端管理 / 已连接设备 |
| 华硕 ASUS | `router.asus.com` | 网络地图 / 客户端列表 |
| 电信天翼网关（TEWA 系列） | `192.168.1.1` | 已连接设备 / LAN 侧信息 |

**核对时的两类差异**：
- 路由器有、扫描没有 → 设备休眠或用了静态地址，属正常漏报；
- 扫描有、路由器没有 → 该设备可能在上级网关之下（双层 NAT），或使用了静态地址。

**注意**：部分路由器后台的登录态为内存态令牌，无法用浏览器自动化接管。遇到这种情况，请用户在自己已登录的浏览器中查看设备列表并抄录主机名，不要索取密码。

## 七、隐私与合规

- MAC 地址、主机名、设备清单均属个人信息，**设备清单与主机名全程本地处理**，不上传、不外发。
- 查询厂商时只发送**单个 MAC 地址本身**（不发送设备清单、主机名或其他数据），且仅在用户允许在线查询时才发；本地 OUI 库匹配全程不联网。
- 只对本人拥有或管理的网络执行扫描。
- 报告文件写入用户指定的工作目录，不含凭据与口令。
