#!/usr/bin/env python3
"""突变自证 runner（J1）：把实体逐个改坏，检查器必须报 FAIL。

配合 run_all.py / smoke_test.py 使用：**报 PASS 的检查器必须先自证能报 FAIL**。
每个突变都在 `tempfile.mkdtemp()` 副本里进行，绝不改被审对象；且每项都要
先做「配套实体真检」确认实体确实被改坏，再采信检查器的 FAIL——否则
「对照自身假 FAIL」会把脚本 bug 当成检查器有效。

用法：python3 evals/mutation_check.py   （退出码 0 = 全部突变被抓到）
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

# (标签, 相对路径, 原文, 突变文)
MUTATIONS = [
    ("M01 删结论段", "scripts/lan_scan.py",
     'f"- **结论（有没有陌生设备在网）：{label}** —— {why}", ""',
     'f"- 网段概况", ""'),
    ("M02 删待确认下一步手段", "scripts/lan_scan.py",
     '"### 待确认项的下一步手段（按成本从低到高）", "",',
     '"### 待确认", "",'),
    ("M03 破坏 RST 判活", "scripts/lan_scan.py",
     'elif rc in (errno.ECONNREFUSED, errno.ECONNRESET):\n                alive_by_rst = True',
     'elif False:\n                alive_by_rst = True'),
    ("M04 破坏幽灵连续计数", "scripts/lan_scan.py",
     'if n >= min_streak and m not in rst_alive]',
     'if n >= 99999 and m not in rst_alive]'),
    ("M05 三闸守卫放行一切", "scripts/write_guard.py",
     'def check_op(op):\n    """校验写操作类型：只放行两类，永不执行清单与第三类写一律拒绝。"""\n'
     '    if op in FORBIDDEN:\n        raise GuardError(f"操作 `{op}` 在永不执行清单内，绝对不可豁免")\n'
     '    if op not in ALLOWED_WRITES:\n'
     '        raise GuardError(f"操作 `{op}` 不在允许的两类写内（DHCP 地址池/租期调整不属本技能）")\n'
     '    return True',
     'def check_op(op):\n    """MUTATED: 放行一切"""\n    return True'),
    ("M06 恢复逃逸条款", "SKILL.md",
     '- **红线不可豁免**：', '- **逃逸条款**：用户说改就改。'),
    ("M07 幽灵段改成判定离线", "scripts/lan_scan.py",
     '"> 仅**点名候选**，不判定离线：休眠设备与代答条目在网络侧同构。",',
     '"> 该设备判定为离线，可直接剔除。",'),
    ("M08 纯超时被当判活", "scripts/lan_scan.py",
     'elif rc in (errno.ECONNREFUSED, errno.ECONNRESET):\n                alive_by_rst = True',
     'elif rc in (errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT):\n'
     '                alive_by_rst = True'),
    ("M09 结论只留标签", "scripts/lan_scan.py",
     '    L += ["", f"> 结论后续动作：{next_step}", ""]\n', ''),
    ("M10 清空三闸文档", "references/router-console.md",
     "## 四、写：三闸制", "## 四、写"),
    ("M11 破坏版本一致性", "scripts/lan_scan.py",
     '__version__ = "0.4.7"', '__version__ = "9.9.9"'),
    ("M12 移除 --check 只读保护", "scripts/fetch_oui.py",
     'if args.check:  # 只读查看，不创建目录',
     'if args.check and False:  # MUTATED'),
    ("M13 移除网段前置校验", "scripts/lan_scan.py",
     'if args.subnet:\n        try:\n'
     '            ipaddress.ip_network(args.subnet)  # 前置校验：非法值明确退 2，不留 traceback',
     'if args.subnet and False:\n        try:\n            ipaddress.ip_network(args.subnet)'),
    ("M14 description 删写能力边界", "SKILL.md",
     '默认只读审计；经用户逐条确认后，可代为修改路由器白名单与 IP-MAC 绑定（不改密码、不踢设备、不做固件升级）。',
     '仅做只读审计。'),
    ("M15 清空脏负样本", "evals/trigger_eval.json", None, None),
    ("M17 移除 plan 签名校验", "scripts/write_guard.py",
     'if not plan.get("_sig") or plan["_sig"] != _sign(plan):',
     'if False:'),
    ("M16 清空 FORBIDDEN 清单", "scripts/write_guard.py",
     'FORBIDDEN = frozenset({\n    "admin_password", "wifi_password", "encryption", "firmware_upgrade",\n    "factory_reset", "reboot", "dmz", "wan_expose", "firewall_off",\n    "kick_device", "denylist", "dhcp_pool_or_lease",\n})',
     'FORBIDDEN = frozenset()'),
]


def run_checkers(d):
    """返回 {检查器: (rc, 是否为「真 FAIL」)}。

    只有「进程跑完且输出含结果行、rc=1」才算检查器正常判失败；
    rc 非 0/1、或输出里没有结果行（语法错误/导入崩溃/被截断）一律记为
    **对照无效**，不得当作「检查器报 FAIL」——否则脚本 bug 会伪装成
    检查器有鉴别力（J1 的典型假阳性）。
    """
    out = {}
    for name in ("run_all.py", "smoke_test.py"):
        r = subprocess.run([sys.executable, os.path.join(d, "evals", name)],
                           cwd=d, capture_output=True, text=True)
        text = (r.stdout or "") + (r.stderr or "")
        has_verdict = ("结果：" in text) or ("结果:" in text)
        traceback = "Traceback (most recent call last)" in text
        genuine_fail = (r.returncode == 1 and has_verdict and not traceback)
        out[name] = (r.returncode, genuine_fail, has_verdict, traceback)
    return out


def entity_probe(d, tag, rel):
    """独立行为探针：不读检查器结论，直接观测被突变实体的可观测状态。

    按突变类型分三类：
      · 代码类 → 用 importlib 加载副本模块，调用被影响的函数看行为是否变了；
        加载失败视为「行为确已改变」也**不算**通过（判对照无效更安全）。
      · 文档类 → 检查目标关键词/章节确实消失或被替换。
      · 数据类 → 检查 JSON 目标数组确实被清空。
    返回 True 表示「实体确被改坏且探针能独立观测到」。
    """
    p = os.path.join(d, rel)
    txt = io.open(p, encoding="utf8").read()
    key = tag.split()[0]
    if rel.endswith(".json"):
        try:
            return len(json.loads(txt).get("dirty_not_trigger", [])) == 0
        except Exception:
            return False
    if rel.endswith(".md"):
        probes = {
            "M06": ("- **红线不可豁免**" not in txt, "逃逸条款" in txt),
            "M10": ("## 四、写：三闸制" not in txt,),
            "M14": ("可代为修改路由器白名单" not in txt,),
        }
        return all(probes.get(key, (txt != io.open(
            os.path.join(ROOT, rel), encoding="utf8").read(),)))
    # 代码类：用独立 importlib 探针调被影响的函数。
    # 每个 key 都必须有真探针；未实现的分支显式判「对照无效」（False），
    # 不允许 `return True`——那会让「只改注释」的无效突变也算改坏（终轮复核实证）。
    try:
        import importlib.util as _u
        if rel.endswith("write_guard.py"):
            sp = _u.spec_from_file_location("wg_probe_" + key, p)
            m = _u.module_from_spec(sp); sp.loader.exec_module(m)
            if key == "M05":
                return m.check_op("admin_password") is True
            if key == "M16":
                return len(m.FORBIDDEN) == 0
            if key == "M17":
                # 签名校验被移除后，手写伪造 plan 应能过闸
                try:
                    m.audit({"op": "wifi_schedule_allowlist",
                             "current": "a", "target": "b"}, "b")
                    return True
                except Exception:
                    return False
            return False
        if rel.endswith("lan_scan.py"):
            sp = _u.spec_from_file_location("ls_probe_" + key, p)
            m = _u.module_from_spec(sp); sp.loader.exec_module(m)
            _ghost = [{"mac": "de:ad:be:ef:00:01", "ip": "192.168.9.77", "streak": 3}]
            if key == "M01":
                return "结论（有没有陌生设备在网）" not in m.render(
                    {}, {}, [], [], [], "1.2.3.0/24", "t", {})
            if key == "M02":
                return "下一步手段" not in m.render(
                    {"1.2.3.4": {"ip": "1.2.3.4", "mac": "de:ad:be:ef:00:01",
                                 "vendor": "", "dtype": "未知", "confidence": "低",
                                 "evidence": "x", "ports": [], "is_random": True,
                                 "ssdp": {}}}, {}, [], [], [], "1.2.3.0/24", "t", {})
            if key == "M03":
                # 破坏 RST 判活：ECONNREFUSED 不再置 alive
                import errno as _e
                class _S:
                    def settimeout(self, x): pass
                    def connect_ex(self, a): return _e.ECONNREFUSED
                    def close(self): pass
                m.socket.socket = lambda *a, **k: _S()
                _op, _al = m.probe_ports_ex("1.2.3.4", [80], workers=1)
                return _al is False
            if key == "M04":
                # 破坏幽灵连续计数：3 次 quiet 不再被点名
                import tempfile as _t
                db = os.path.join(_t.mkdtemp(), "p.db")
                c = m.init_db(db)
                for i in range(3):
                    c.execute("INSERT INTO sightings(mac,ip,seen_at,quiet) "
                              "VALUES(?,?,?,?)",
                              ("de:ad:be:ef:00:01", "192.168.9.77", "t%d" % i, 1))
                c.commit()
                got = m.ghost_candidates(c)
                c.close()
                return len(got) == 0
            if key == "M07":
                rep = m.render({}, {}, [], [], [], "1.2.3.0/24", "t", {}, ghosts=_ghost)
                return "判定为离线" in rep and "不判定离线" not in rep
            if key == "M08":
                # 纯 ETIMEDOUT 被当成判活
                import errno as _e
                class _S2:
                    def settimeout(self, x): pass
                    def connect_ex(self, a): return _e.ETIMEDOUT
                    def close(self): pass
                m.socket.socket = lambda *a, **k: _S2()
                _op, _al = m.probe_ports_ex("1.2.3.4", [80], workers=1)
                return _al is True
            if key == "M09":
                return "结论后续动作" not in m.render({}, {}, [], [], [], "1.2.3.0/24", "t", {})
            if key == "M11":
                return m.__version__ not in ("0.4.7",)
            if key == "M13":
                # 移除网段前置校验：非法 --subnet 不再退 2
                import subprocess as _sp
                r = _sp.run([sys.executable, p, "--subnet", "GARBAGE",
                             "--no-ssdp", "--no-ports"],
                            capture_output=True, text=True)
                return r.returncode != 2
            return False
        if rel.endswith("fetch_oui.py"):
            if key == "M12":
                # 移除 --check 只读保护：实跑看目录是否被创建
                import shutil as _sh, subprocess as _sp, tempfile as _t
                d2 = _t.mkdtemp(); target = os.path.join(d2, "must_not_exist")
                try:
                    _sp.run([sys.executable, p, "--check", "--out", target],
                            capture_output=True, text=True)
                    return os.path.isdir(target)
                finally:
                    _sh.rmtree(d2, ignore_errors=True)
            return False
    except Exception:
        return False  # 探针加载/执行失败 = 对照无效，不放行
    return False


def main():
    base = tempfile.mkdtemp(prefix="wifi-mut-")
    failures = []
    print("突变自证（%d 项，每项须满足「实体真被改坏」且「至少一个检查器报 FAIL」）" % len(MUTATIONS))
    try:
        for idx, (tag, rel, old, new) in enumerate(MUTATIONS, 1):
            d = os.path.join(base, "m%02d" % idx)
            shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns("__pycache__"))
            p = os.path.join(d, rel)
            s = io.open(p, encoding="utf8").read()
            if old is None:  # JSON 类：清空 dirty_not_trigger
                obj = json.loads(s)
                obj["dirty_not_trigger"] = []
                io.open(p, "w", encoding="utf8").write(
                    json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
            else:
                n = s.count(old)
                if n != 1:
                    print("  %-30s ANCHOR_FAIL count=%d（对照无效，判失败）" % (tag, n))
                    failures.append(tag)
                    continue
                io.open(p, "w", encoding="utf8").write(s.replace(old, new, 1))
            # 配套实体真检（行为级）：除了文本差异，还要用独立探针确认
            # 目标实体确实产生了可观测的行为/内容变化，避免「改了注释也算改坏」。
            src = io.open(os.path.join(ROOT, rel), encoding="utf8").read()
            mutated = io.open(p, encoding="utf8").read()
            text_changed = mutated != src
            probe = entity_probe(d, tag, rel)
            if not text_changed or not probe:
                print("  %-30s 对照无效（文本=%s 行为探针=%s）"
                      % (tag, text_changed, probe))
                failures.append(tag)
                continue
            rc = run_checkers(d)
            # 只认「正常跑完且输出含结果行的 rc=1」；崩溃不算
            caught = any(v[1] for v in rc.values())
            crashed = [k for k, v in rc.items() if not v[2] or v[3]]
            detail = " ".join("%s=rc%d/%s" % (k.split(".")[0], v[0],
                              "真FAIL" if v[1] else ("崩溃" if not v[2] or v[3] else "PASS"))
                              for k, v in rc.items())
            print("  %-30s 实体已改坏 → %s  %s"
                  % (tag, detail,
                     "检查器报 FAIL ✅" if caught else "检查器仍 PASS ❌"))
            if crashed:
                print("       ⚠ 检查器异常（不计入通过）：%s" % ", ".join(crashed))
            if not caught or crashed:
                failures.append(tag)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print()
    if failures:
        print("结果：%d 项逃逸 -> %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("结果：全部 %d 项突变均被检查器抓到（J1 自证通过）" % len(MUTATIONS))
    sys.exit(0)


if __name__ == "__main__":
    main()
