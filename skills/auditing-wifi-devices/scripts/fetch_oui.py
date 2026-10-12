#!/usr/bin/env python3
"""一键获取 / 更新本地 OUI 厂商库（公开数据库，**不含任何本机 MAC 信息**）。

数据源（按推荐序）：
  1. Wireshark manuf —— 社区主流单文件库（约 5.8 万条）：
     合并 IEEE MA-L(24位)/MA-M(28位)/MA-S(36位) + IAB + Michael Patton
     社区清单，每条含 8 字符短名与全名/注释。默认只下这个。
     https://www.wireshark.org/download/automated/data/manuf
  2. IEEE 官方三表（--ieee 追加下载，权威源，按需补漏）：
     https://standards-oui.ieee.org/oui/oui.csv      (MA-L, 24位)
     https://standards-oui.ieee.org/oui28/mam.csv    (MA-M, 28位)
     https://standards-oui.ieee.org/oui36/oui36.csv  (MA-S, 36位)

落点：默认运行目录下的 oui-vendors/（--out 或 OUI_CACHE_DIR 环境变量可改）。
之后在同一目录运行 lan_scan.py 不传 --oui-file 也会自动使用该缓存；
也可以显式 --oui-file 传任意路径/多文件。

用法:
    python3 fetch_oui.py            # 下载 Wireshark manuf（推荐默认）
    python3 fetch_oui.py --ieee     # 追加 IEEE 官方三表
    python3 fetch_oui.py --out DIR  # 自定义落点目录
    python3 fetch_oui.py --check    # 只查看现有库的状态，不下载

隐私说明：本脚本只下载公开的厂商注册数据（相当于下载一本字典），
不会读取、上传本机 ARP 表或任何 MAC 地址。
退出码: 0 成功 / 1 下载失败 / 2 参数错误
"""
import argparse
import os
import sys
import time
import urllib.request

SOURCES = {
    "manuf": ("https://www.wireshark.org/download/automated/data/manuf",
              "Wireshark manuf（IEEE 三表 + IAB + 社区清单合并）"),
    "oui.csv": ("https://standards-oui.ieee.org/oui/oui.csv", "IEEE MA-L 24位"),
    "mam.csv": ("https://standards-oui.ieee.org/oui28/mam.csv", "IEEE MA-M 28位"),
    "oui36.csv": ("https://standards-oui.ieee.org/oui36/oui36.csv", "IEEE MA-S 36位"),
}
def default_dir():
    """默认落点：运行目录下的 oui-vendors/，OUI_CACHE_DIR 可覆盖。

    刻意不用绝对路径作默认值——技能要能在任何机器、任何 harness 下运行，
    不假设本机存在某个特定目录。运行时求值，环境变量改动即时生效。
    """
    return os.environ.get("OUI_CACHE_DIR") or os.path.join(".", "oui-vendors")


def fetch(url, dest, timeout=120):
    """下载到 dest；成功返回字节数，失败返回 -1。"""
    tmp = dest + ".part"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=timeout) as r, \
                open(tmp, "wb") as f:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
        if os.path.getsize(tmp) < 1024:  # 正常库至少几十 KB，防止落到错误页
            os.remove(tmp)
            return -1
        os.replace(tmp, dest)
        return os.path.getsize(dest)
    except KeyboardInterrupt:
        if os.path.exists(tmp):
            os.remove(tmp)  # 用户中断不留残file
        print("\n  已取消", file=sys.stderr)
        raise
    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        print(f"  下载失败: {e}", file=sys.stderr)
        return -1


def count_entries(path):
    """粗算有效条目数（跳过注释/空行）。"""
    n = 0
    try:
        with open(path, encoding="utf8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    n += 1
    except Exception:
        pass
    return n


def main():
    ap = argparse.ArgumentParser(description="获取本地 OUI 厂商库（公开数据，不含本机 MAC）")
    ap.add_argument("--ieee", action="store_true",
                    help="追加下载 IEEE 官方三表（oui.csv / mam.csv / oui36.csv）")
    ap.add_argument("--out", default=default_dir(), help=f"落点目录（默认 {default_dir()}）")
    ap.add_argument("--check", action="store_true", help="只查看现有库状态，不下载")
    args = ap.parse_args()

    names = ["manuf"] + (["oui.csv", "mam.csv", "oui36.csv"] if args.ieee else [])

    if args.check:  # 只读查看，不创建目录
        for name in names:
            p = os.path.join(args.out, name)
            if os.path.isfile(p):
                st = os.stat(p)
                age = (time.time() - st.st_mtime) / 86400
                print(f"  {name}: {count_entries(p)} 条, "
                      f"{st.st_size/1024:.0f} KB, {age:.1f} 天前更新")
            else:
                print(f"  {name}: 缺失")
        return 0

    os.makedirs(args.out, exist_ok=True)

    rc = 0
    for name in names:
        url, desc = SOURCES[name]
        dest = os.path.join(args.out, name)
        print(f"下载 {name} —— {desc}")
        print(f"  {url}")
        n = fetch(url, dest)
        if n < 0:
            rc = 1
        else:
            print(f"  已保存 {dest}（{n/1024:.0f} KB, {count_entries(dest)} 条）")
    if rc == 0:
        print(f"\n完成。lan_scan.py 会自动使用 {args.out} 下的库；"
              f"也可显式 --oui-file 传路径（可重复多个）。")
        print("建议每月更新一次（厂商分配表持续增长）。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
