#!/usr/bin/env python3
"""LAN / WiFi 设备审计：扫描 → 识别 → 建台账 → 差分 → 出报告。

纯标准库，无第三方依赖。只读扫描，不做任何网络修改操作。

用法:
    python3 lan_scan.py --out report.md                    # 网段自动探测，换网络无需改参数
    python3 lan_scan.py --subnet 192.168.1.0/24 --out report.md   # 自动探测失败时显式指定
    python3 lan_scan.py --db ./my-net.db                    # 指定台账；默认按网段分库
    python3 lan_scan.py --ssdp-listen 40                    # 延长 SSDP 监听(默认 30s)
    python3 lan_scan.py --online-vendor                      # 允许联网查厂商（默认关闭）
    python3 lan_scan.py --oui-file /path/oui.txt            # 指定 IEEE OUI 库

退出码: 0 成功 / 2 参数或环境错误
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

# ---------- 工具 ----------

def run(cmd, timeout=60):
    """执行命令，返回 stdout；失败返回空串。"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""


def detect_subnet():
    """探测本机当前所在网段，随网络环境自适应，不依赖任何固定网段。

    优先取「默认路由出口网卡」的地址——换网络、多网卡、VPN 并存时，
    只有它才是流量真正走的那一张。返回 '192.168.1.0/24' 形式；失败返回 ''。
    """
    ip, mask = "", ""

    if sys.platform == "darwin":
        iface = run("route -n get default 2>/dev/null | awk '/interface:/{print $2}'").strip()
        if iface:
            ip = run(f"ipconfig getifaddr {iface}").strip()
            mask = run(f"ipconfig getoption {iface} subnet_mask").strip()
        if not ip:  # 默认路由拿不到时退到常见接口
            for cand in ("en0", "en1", "en2"):
                ip = run(f"ipconfig getifaddr {cand}").strip()
                if ip:
                    mask = run(f"ipconfig getoption {cand} subnet_mask").strip()
                    break
    else:
        out = run("ip -4 route get 8.8.8.8 2>/dev/null")
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            ip = m.group(1)
            got = run(f"ip -o -4 addr show 2>/dev/null | grep -F '{ip}/'")
            m2 = re.search(re.escape(ip) + r"/(\d+)", got)
            if m2:
                mask = str(ipaddress.IPv4Network(f"{ip}/{m2.group(1)}").netmask)
            else:
                mask = ""
        if not ip:
            out2 = run("ip -4 addr show scope global 2>/dev/null | grep -m1 inet")
            m3 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out2)
            if m3:
                ip = m3.group(1)
                mask = str(ipaddress.IPv4Network(f"{m3.group(1)}/{m3.group(2)}").netmask)

    if not ip:
        return ""
    if not mask:
        mask = "255.255.255.0"
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
    except Exception:
        return ""


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


# ---------- 采集层 ----------

def discover_hosts(subnet):
    """存活探测 + ARP 判活。返回 {ip: mac}（mac 可能为空）。

    关键：多数手机/IoT 不回 ICMP 但会回应 ARP。ping 只用于触发 ARP 学习，
    在网判定以「ARP 表里有真实 MAC」为准。
    """
    # 1) 先触发一次 ARP 学习
    if run("command -v fping").strip():
        run(f"fping -a -g -r 1 -t 400 {subnet}", timeout=120)
    else:
        net = ipaddress.ip_network(subnet)
        # 无 fping 时用 ping 兜底，仅抽样前 254 个地址
        for host in list(net.hosts())[:254]:
            run(f"ping -c 1 -W 1 {host}", timeout=3)
    # 2) 读 ARP
    return parse_arp()


def parse_arp():
    """解析 arp -a，兼容 macOS 与 Linux 输出格式。"""
    out = run("arp -a")
    table = {}
    mac_re = re.compile(r"(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", re.I)
    for line in out.splitlines():
        m_ip = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line) or re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        if "incomplete" in line.lower() or "(none)" in line.lower():
            table[ip] = ""
            continue
        m_mac = mac_re.search(line)
        if m_mac:
            table[ip] = m_mac.group(0).lower()
    # 去掉广播与组播（224.0.0.0–239.255.255.255 不是真实设备）
    keep = {}
    for ip, mac in table.items():
        try:
            if ipaddress.ip_address(ip).is_multicast or ip.endswith(".255"):
                continue
        except Exception:
            continue
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            keep[ip] = mac
    return keep


def sniff_ssdp(seconds=30):
    """被动监听 SSDP/UPnP 广播。返回 {ip: {'server':..,'nt':..,'location':..}}。

    这是识别 IoT 性价比最高的手段：设备会自报 SERVER 与设备类型。
    """
    import struct
    result = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("239.255.255.250", 1900))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     struct.pack("4sl", socket.inet_aton("239.255.255.250"),
                                 socket.INADDR_ANY))
        s.settimeout(1.0)
    except Exception:
        return result
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break
        txt = data.decode("utf8", "ignore")
        ip = addr[0]
        info = result.setdefault(ip, {})
        for key, pat in (("server", r"(?im)^SERVER:\s*(.+)$"),
                         ("nt", r"(?im)^NT:\s*(.+)$"),
                         ("location", r"(?im)^LOCATION:\s*(.+)$")):
            m = re.search(pat, txt)
            if m:
                val = m.group(1).strip()
                prev = info.get(key, "")
                vals = set(prev.split(" | ")) if prev else set()
                vals.add(val)
                info[key] = " | ".join(sorted(vals))
    try:
        s.close()
    except Exception:
        pass
    return {ip: v for ip, v in result.items() if v.get("server") or v.get("nt")}


MDNS_SERVICES = ["_airplay._tcp", "_raop._tcp", "_companion-link._tcp",
                 "_http._tcp", "_workstation._tcp", "_ipp._tcp"]


def browse_mdns(per_service=3):
    """浏览常见 mDNS 服务，收集设备自报实例名。

    实例名无法直接反查 IP（需额外 -L/-G 两步），故只作为辅助佐证列出。
    """
    names = set()
    if sys.platform != "darwin" and not run("command -v avahi-browse").strip():
        return {}
    for svc in MDNS_SERVICES:
        try:
            p = subprocess.Popen(f"dns-sd -B {svc} local.", shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True)
        except Exception:
            continue
        try:
            time.sleep(per_service)
            p.terminate()
            out = p.stdout.read() or ""
        except Exception:
            out = ""
        for line in out.splitlines():
            if re.search(r"\bAdd\b", line):
                # 实例名在最后一列之后
                m = re.search(r"local\.\s+(\S.*)$", line)
                if m:
                    name = m.group(1).strip()
                    if name and not name.startswith("_"):
                        names.add(name)
    return {"instances": sorted(names)}


# ---------- 识别层 ----------

def is_random_mac(mac):
    """随机/私有 MAC 判定：首字节 U/L 位(0x02)为 1 即本地管理地址。"""
    try:
        first = int(mac.split(":")[0], 16)
    except Exception:
        return False
    return bool(first & 0x02)


def load_oui(path):
    """加载 IEEE OUI 库（oui.txt 或 oui.csv）。返回 {前缀6位: 厂商名}。"""
    table = {}
    if not path or not os.path.isfile(path):
        return table
    try:
        with open(path, encoding="utf8", errors="ignore") as f:
            for line in f:
                if "(base 16)" in line:
                    m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(base 16\)\s+(.+)$",
                                 line.strip(), re.I)
                    if m:
                        table[m.group(1).replace("-", "").upper()] = m.group(2).strip()
                elif path.lower().endswith(".csv"):
                    parts = line.split(",")
                    if len(parts) >= 3 and re.match(r"^[0-9A-F]{6}$", parts[1].strip(), re.I):
                        table[parts[1].strip().upper()] = parts[2].strip().strip('"')
    except Exception:
        pass
    return table


def online_vendor(mac, timeout=6):
    """在线查厂商。注意：本机若有 HTTP_PROXY 需绕开，否则会连接失败。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac}", headers={"User-Agent": "curl/8"})
        with opener.open(req, timeout=timeout) as r:
            v = r.read().decode("utf8", "ignore").strip()
            return "" if v.startswith("{") else v  # 接口对未收录返回 JSON
    except Exception:
        return ""


# ---------- 端口指纹 ----------

# 只探测「强特征」端口：开放即可当判据。通用端口(22/80/443)只作辅助信息，不定类型。
FEATURE_PORTS = {
    62078: ("Apple iOS 设备", "Apple lockdownd 同步/配对专有端口", "高"),
    9100: ("打印机", "JetDirect 打印端口", "高"),
    554: ("网络摄像头 / 影音设备", "RTSP 流媒体", "高"),
    1883: ("IoT 智能设备", "MQTT 消息总线", "高"),
    32400: ("媒体服务器", "Plex", "高"),
    8123: ("家庭自动化主机", "Home Assistant", "高"),
    3689: ("Apple 音乐共享", "DAAP", "高"),
    7000: ("投屏 / 音响设备", "AirPlay", "高"),
    7100: ("投屏 / 音响设备", "AirPlay", "高"),
    445: ("Windows / 文件共享设备", "SMB", "中"),
    139: ("Windows 设备", "NetBIOS", "中"),
    22: ("Linux / 路由器 / 树莓派", "SSH", "中"),
    3389: ("Windows 远程桌面", "RDP", "中"),
}
# 全端口集合仅用于「是否还有未知监听」的提示，不做类型判据
AUX_PORTS = (80, 443, 8080, 8443, 5000, 5001, 49152)


def probe_ports(ip, ports, timeout=0.5, workers=60):
    """并发 TCP 探测，返回按端口号排序的开放列表。"""
    import concurrent.futures as cf
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe, ip, p, timeout): p for p in ports}
        for f in cf.as_completed(futs):
            if f.result():
                open_ports.append(futs[f])
    return sorted(open_ports)


def _probe(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def sanitize(s, limit=120):
    """清洗来自网络的自报字符串。

    设备自报内容（SSDP SERVER/NT、mDNS 实例名、厂商名、主机名）是**外部数据**，
    可能被恶意设备构造以污染报告 —— 例如塞入 markdown 表格分隔符、代码围栏或
    指令性文本，进而在报告被阅读时被当作指令。这里在写报告前统一做数据化处理：
    去控制字符、拆掉 markdown 结构符、压缩空白、限制长度。
    """
    if not s:
        return ""
    s = str(s)
    s = re.sub(r"[\x00-\x1f\x7f]", " ", s)        # 控制字符与换行
    s = s.replace("|", "/").replace("`", "'")      # 表格分隔符与代码围栏
    s = re.sub(r"[<>\[\]{}]", "", s)               # 角度/方/花括号
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def classify(mac, vendor, ssdp, ports=None):
    """综合判据给设备类型。优先级：SSDP 自报 > 端口强特征 > OUI 厂商 > 随机MAC兜底。"""
    if not mac:
        return ("未知", "低", "无 MAC")
    ports = ports or []
    # 1) SSDP 自报：设备自己声明，最强判据
    nt = (ssdp.get("nt", "") + " " + ssdp.get("server", "")).lower()
    if "internetgatewaydevice" in nt:
        return ("路由器/网关", "高", "SSDP 自报 InternetGatewayDevice")
    if "mediarenderer" in nt or "mediaserver" in nt:
        return ("投屏/音箱/媒体设备", "高",
                f"SSDP 自报 {sanitize(ssdp.get('nt', ''), 60)}")
    if "printer" in nt or "ipp" in nt:
        return ("打印机", "高", "SSDP 自报打印服务")
    # 2) 端口强特征：OUI 查不到的随机 MAC 靠这条定性
    for p in ports:
        if p in FEATURE_PORTS:
            dtype, desc, conf = FEATURE_PORTS[p]
            return (dtype, conf, f"端口 {p} 开放（{desc}）")
    # 3) OUI 厂商（随机 MAC 查不到，跳过）
    if vendor and not is_random_mac(mac):
        return (sanitize(vendor, 40), "中", f"OUI 厂商 = {sanitize(vendor, 40)}")
    # 4) 兜底
    if is_random_mac(mac):
        return ("未知(随机MAC)", "低",
                "MAC 为私有/随机地址，厂商与型号均不可查")
    return ("未知", "低", "OUI 库未收录且无服务自报")


# ---------- 台账层 ----------

def init_db(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE IF NOT EXISTS devices(
        mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, dtype TEXT, confidence TEXT,
        evidence TEXT, is_random INTEGER, ssdp TEXT,
        first_seen TEXT, last_seen TEXT, note TEXT DEFAULT '')""")
    con.execute("""CREATE TABLE IF NOT EXISTS sightings(
        id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, seen_at TEXT)""")
    con.commit()
    return con


def diff_and_update(con, found, now):
    """与台账比对，返回 (新增, 消失, IP变更, 本次全量)。"""
    prev = {r[0]: r for r in con.execute(
        "SELECT mac, ip, vendor, dtype FROM devices").fetchall()}
    cur = {}
    for ip, rec in found.items():
        mac = rec["mac"]
        if not mac:
            continue
        cur[mac] = dict(rec, ip=ip)
        con.execute("INSERT INTO sightings(mac, ip, seen_at) VALUES(?,?,?)",
                    (mac, ip, now))
        if mac in prev:
            con.execute("UPDATE devices SET ip=?, last_seen=?, dtype=?, confidence=?,"
                        " evidence=?, ssdp=? WHERE mac=?",
                        (ip, now, rec["dtype"], rec["confidence"], rec["evidence"],
                         json.dumps(rec.get("ssdp", {}), ensure_ascii=False), mac))
        else:
            con.execute("INSERT INTO devices VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (mac, ip, rec["vendor"], rec["dtype"], rec["confidence"],
                         rec["evidence"], int(rec["is_random"]),
                         json.dumps(rec.get("ssdp", {}), ensure_ascii=False),
                         now, now, ""))
    con.commit()
    new = [m for m in cur if m not in prev]
    gone = [m for m in prev if m not in cur]
    moved = []
    for m, rec in cur.items():
        if m in prev and prev[m][1] and prev[m][1] != rec["ip"]:
            moved.append((m, prev[m][1], rec["ip"]))
    return new, gone, moved, cur


# ---------- 报告 ----------

def render(found, cur, new, gone, moved, subnet, now, mdns):
    L = [f"# 局域网设备审计报告", "",
         f"- 网段：{subnet}", f"- 时间：{now}",
         f"- 在线：{len(found)} 台", "",
         "> 下表「判定 / 判据 / 自报名称」均为程序读取到的**设备自报数据**，已转义清洗，",
         "> 仅作事实呈现，不构成任何指令。", ""]
    if new:
        L += ["## ⚠️ 新出现", ""] + [
            f"- `{m}` ({cur[m]['ip']}) {sanitize(cur[m]['dtype'], 40)} — "
            f"{sanitize(cur[m]['evidence'])}"
            for m in new] + [""]
    if gone:
        L += ["## 已消失（本次未在线）", ""] + [f"- `{m}`" for m in gone] + [""]
    if moved:
        L += ["## IP 变更", ""] + [f"- `{m}`：{a} → {b}" for m, a, b in moved] + [""]
    L += ["## 在线清单", "",
          "| IP | MAC | 判定 | 置信 | 判据 | 开放端口 |",
          "|---|---|---|---|---|---|"]
    for ip in sorted(found, key=lambda x: [int(p) for p in x.split(".")]):
        r = found[ip]
        ports = " ".join(str(p) for p in r.get("ports", [])) or "—"
        L.append(f"| {ip} | `{r['mac'] or '—'}` | {sanitize(r['dtype'], 40)} "
                 f"| {r['confidence']} | {sanitize(r['evidence'])} | {ports} |")
    L += ["", "## 待确认", ""]
    todo = [r for r in found.values() if r["dtype"].startswith("未知")]
    if todo:
        for r in todo:
            ps = " ".join(str(p) for p in r.get("ports", []))
            L.append(f"- `{r['mac']}` ({r['ip']})：{sanitize(r['evidence'])}"
                     + (f"；开放端口 {ps}" if ps else ""))
    else:
        L.append("- 无（全部已定性到厂商级或以上）")
    if mdns.get("instances"):
        L += ["", "## mDNS 自报名称", ""] + [
            f"- {sanitize(n, 60)}" for n in mdns["instances"][:20]]
    return "\n".join(L) + "\n"


# ---------- 主流程 ----------

def main():
    ap = argparse.ArgumentParser(description="局域网/WiFi 设备审计（只读）")
    ap.add_argument("--subnet", default="", help="如 192.168.1.0/24，默认自动探测")
    ap.add_argument("--db", default="",
                    help="台账 SQLite 路径；默认按网段自动分库 lan-devices-<网段>.db，"
                         "避免换网络后新旧设备被混在一起比对")
    ap.add_argument("--out", default="", help="报告输出文件(md)，默认打屏")
    ap.add_argument("--oui-file", default=os.environ.get("OUI_FILE", ""),
                    help="IEEE OUI 库路径(oui.txt/oui.csv)")
    ap.add_argument("--ssdp-listen", type=int, default=30, help="SSDP 监听秒数")
    ap.add_argument("--online-vendor", action="store_true",
                    help="允许联网查厂商（向公共厂商库发送单个 MAC）；默认关闭，只用本地 OUI 库")
    ap.add_argument("--no-ssdp", action="store_true", help="跳过 SSDP 监听")
    ap.add_argument("--no-ports", action="store_true", help="跳过端口指纹探测")
    args = ap.parse_args()

    subnet = args.subnet or detect_subnet()
    if not subnet:
        print("错误：未能探测网段，请用 --subnet 指定（如 192.168.1.0/24）", file=sys.stderr)
        return 2
    # 台账默认按网段分库：换网络时各自独立，互不污染
    db_path = args.db or f"./lan-devices-{subnet.replace('/', '-').replace('.', '_')}.db"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write(f"[1/5] 探测存活 {subnet} ...\n")
    hosts = discover_hosts(subnet)
    sys.stderr.write(f"      ARP 表中有 MAC 的主机 {len(hosts)} 台\n")

    if args.no_ssdp:
        sys.stderr.write("[2/5] 跳过 SSDP 监听（--no-ssdp）\n")
        ssdp = {}
    else:
        sys.stderr.write(f"[2/5] SSDP 被动监听 {args.ssdp_listen}s ...\n")
        ssdp = sniff_ssdp(args.ssdp_listen)
        sys.stderr.write(f"      捕获自报 {len(ssdp)} 台\n")

    sys.stderr.write("[3/5] mDNS 浏览 ...\n")
    mdns = browse_mdns()

    sys.stderr.write("[4/5] 端口指纹 + 厂商与类型识别 ...\n")
    plist = sorted(set(FEATURE_PORTS) | set(AUX_PORTS))
    ports_map = {}
    if args.no_ports:
        ports_map = {ip: [] for ip in hosts}
    else:
        for ip in hosts:
            ports_map[ip] = probe_ports(ip, plist)
            if ports_map[ip]:
                sys.stderr.write(f"      {ip} 开放 {ports_map[ip]}\n")

    oui = load_oui(args.oui_file)
    me = local_ip()
    found = {}
    for ip, mac in hosts.items():
        if ip == me:  # 本机优先，避免被其开放的服务端口误判成别的设备
            found[ip] = {"ip": ip, "mac": mac, "vendor": "", "dtype": "本机",
                         "confidence": "高", "evidence": "当前执行扫描的主机",
                         "ports": ports_map.get(ip, []),
                         "is_random": is_random_mac(mac) if mac else False,
                         "ssdp": {}}
            continue
        vendor = ""
        if mac and not is_random_mac(mac):
            vendor = oui.get(mac.replace(":", "").upper()[:6], "")
            if not vendor and args.online_vendor:
                vendor = online_vendor(mac)
                time.sleep(1.1)  # 公共接口限速，勿并发
        ports = ports_map.get(ip, [])
        dtype, conf, ev = classify(mac, vendor, ssdp.get(ip, {}), ports)
        found[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "dtype": dtype,
                     "confidence": conf, "evidence": ev, "ports": ports,
                     "is_random": is_random_mac(mac) if mac else False,
                     "ssdp": ssdp.get(ip, {})}

    unknown = [r for r in found.values() if not r["vendor"] and not r["is_random"]]
    if unknown:
        sys.stderr.write(
            f"提示：{len(unknown)} 台未能自动定厂商。"
            f"优先用 --oui-file 指定本地 IEEE OUI 库（全程不联网）；"
            f"确需在线查询时显式加 --online-vendor，或用网页抓取工具（WebFetch）"
            f"访问 https://api.macvendors.com/<MAC> 逐个补齐。\n")

    sys.stderr.write(f"[5/5] 台账差分（库: {db_path}）...\n")
    con = init_db(db_path)
    new, gone, moved, cur = diff_and_update(con, found, now)
    con.close()

    report = render(found, cur, new, gone, moved, subnet, now, mdns)
    if args.out:
        with open(args.out, "w", encoding="utf8") as f:
            f.write(report)
        sys.stderr.write(f"报告已写入 {args.out}\n")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
