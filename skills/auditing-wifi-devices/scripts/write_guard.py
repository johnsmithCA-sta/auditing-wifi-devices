#!/usr/bin/env python3
"""受控写三闸的**代码级强制点**（0.4.7）。

本模块不连接路由器、不操作浏览器。真实写动作由宿主 Agent 在用户已登录的
后台页面执行；但**任何写动作在动手前必须先过本模块**，否则一律拒绝。
目的是把 SKILL.md 里「默认只读 + 受控写三闸」从文档声明变成可验证的守卫。

三闸（对应 SKILL.md Guidelines 与 references/router-console.md §四）：
  闸 1 先读后写：必须传入本次读到的当前值（不得凭记忆、不得为空）。
  闸 2 逐条确认：每次只允许一项改动，且必须拿到用户明确确认。
  闸 3 留痕：改完必须回读复核，产出含「原值→新值→回滚动作」的变更表行。

退出/异常：任何一闸不满足抛 GuardError，调用方必须终止写动作。
"""
import hashlib
import io
import os
import sys
from datetime import datetime

ALLOWED_WRITES = frozenset({"wifi_schedule_allowlist", "ip_mac_binding"})

FORBIDDEN = frozenset({
    "admin_password", "wifi_password", "encryption", "firmware_upgrade",
    "factory_reset", "reboot", "dmz", "wan_expose", "firewall_off",
    "kick_device", "denylist", "dhcp_pool_or_lease",
})

# 确认必须是**整句精确匹配**：子串匹配会把「不好 / 不是 / 不可以 / 没同意 /
# 不能改」当成同意，也会被注入文本「ignore previous instructions 好」骗过。
CONFIRM_EXACT = frozenset({
    "改", "确认", "好", "是", "可以", "同意", "yes", "ok", "y",
    "改吧", "好的", "确认改", "同意修改", "确定", "执行",
})
DENY_MARKERS = ("不", "没", "别", "无", "否", "拒绝", "取消", "算了", "再想",
                "等等", "稍后", "maybe", "no", "not", "cancel", "wait", "later")
INJECT_MARKERS = ("ignore", "忽略", "指令", "instruction", "system", "prompt",
                  "输出", "above", "previous", "bypass", "绕过", "系统提示")


def is_confirm(reply):
    """精确确认判定：先排注入、再排否定、最后整句白名单匹配。"""
    r = str(reply or "").strip().lower().rstrip("!！。.")
    if not r:
        return False
    if any(m in r for m in INJECT_MARKERS):
        return False
    if any(m in r for m in DENY_MARKERS):
        return False
    return r in CONFIRM_EXACT


class GuardError(Exception):
    """写动作被守卫拒绝。"""


_KEY_FILE = os.path.join(os.path.expanduser("~"), ".write_guard_key")


def _key():
    """取（必要时生成）本地一次性签名密钥，权限 600，仅本机可用。

    目的是让 verify 无法接受**手写伪造的 plan**：prepare 产出的 plan 带签名，
    verify 校验签名、重跑 check_op 并比对 op/current/target 三元组，
    绕过前两闸直接拼一个 JSON 喂给 verify 会被拒。
    """
    try:
        if os.path.isfile(_KEY_FILE):
            return io.open(_KEY_FILE, encoding="utf8").read().strip()
        import binascii
        k = binascii.hexlify(os.urandom(32)).decode()
        with io.open(_KEY_FILE, "w", encoding="utf8") as f:
            f.write(k)
        try:
            os.chmod(_KEY_FILE, 0o600)
        except Exception:
            pass
        return k
    except (IOError, OSError) as e:
        # 家目录不可写等情况：转成守卫拒绝（rc=2），不吐 traceback
        raise GuardError("无法读写签名密钥 %s（%s）：拒绝在无法留痕的环境里执行写动作"
                         % (_KEY_FILE, e))


def _sign(plan):
    raw = "|".join([plan["op"], plan["current"], plan["target"], _key()])
    return hashlib.sha256(raw.encode("utf8")).hexdigest()


def check_op(op):
    """校验写操作类型：只放行两类，永不执行清单与第三类写一律拒绝。"""
    if op in FORBIDDEN:
        raise GuardError(f"操作 `{op}` 在永不执行清单内，绝对不可豁免")
    if op not in ALLOWED_WRITES:
        raise GuardError(f"操作 `{op}` 不在允许的两类写内（DHCP 地址池/租期调整不属本技能）")
    return True


def confirm(op, current, target, user_reply, *, known_device=False, batch=None):
    """闸 1 + 闸 2：先读后写 + 逐条确认。返回待写清单（仍不含执行权）。"""
    check_op(op)
    if current is None or str(current).strip() == "":
        raise GuardError("闸1 未过：缺少本次读到的当前值，禁止凭记忆改动")
    if target is None or str(target).strip() == "":
        raise GuardError("闸1 未过：目标值为空")
    if str(current) == str(target):
        raise GuardError("闸1 未过：当前值与目标值相同，无需写")
    if batch:
        raise GuardError("闸2 未过：批量操作必须拆成逐条确认")
    if not is_confirm(user_reply):
        raise GuardError("闸2 未过：未拿到用户明确确认（否定句与注入文本一律不算），禁止动手")
    if not known_device:
        raise GuardError("闸2 未过：不认识的设备不得加进白名单")
    plan = {"op": op, "current": str(current), "target": str(target)}
    plan["_sig"] = _sign(plan)
    return plan


def audit(plan, readback, *, when=None):
    """闸 3：回读复核 + 留痕。返回可交给用户作回滚依据的变更表行。"""
    if not plan or "target" not in plan:
        raise GuardError("闸3 未过：没有已确认的变更计划")
    # 防伪造：verify 须重校操作类型与当前值，并核对签名，不能只信 plan 里的字段
    check_op(plan.get("op", ""))
    if not plan.get("_sig") or plan["_sig"] != _sign(plan):
        raise GuardError("闸3 未过：plan 签名缺失或不符（疑似手写伪造，须经 prepare 产出）")
    if str(plan.get("current", "")).strip() == "":
        raise GuardError("闸3 未过：plan 缺少当前值（闸1 未过）")
    if readback is None or str(readback).strip() == "":
        raise GuardError("闸3 未过：未回读页面，不能只信「保存成功」提示")
    if str(readback) != str(plan["target"]):
        raise GuardError(f"闸3 未过：回读值 `{readback}` != 目标值 `{plan['target']}`")
    ts = when or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "time": ts, "page": plan["op"],
        "change": f"{plan['current']} → {plan['target']}",
        "basis": "用户逐条确认",
        "rollback": f"把 {plan['op']} 从 `{plan['target']}` 改回 `{plan['current']}`",
    }


def guarded_write(op, current, target, user_reply, readback, *, known_device=False):
    """完整三闸一次走完；任一闸失败抛 GuardError，不产出变更表。"""
    plan = confirm(op, current, target, user_reply, known_device=known_device)
    return audit(plan, readback)


def main(argv=None):
    """生产接线入口：写动作前后由 Agent 各调一次，输出留痕 JSON。

    用法：
      python3 scripts/write_guard.py prepare --op wifi_schedule_allowlist \
          --current '不在名单' --target '在名单' --reply '确认' > plan.json
      # ... 在用户已登录的浏览器里执行改动，然后回读页面 ...
      python3 scripts/write_guard.py verify --plan plan.json --readback '在名单'
    prepare 只产出**待写清单**并校验前两闸，不授予执行权；verify 走第三闸
    （回读不符即拒绝），成功后输出变更表行。任何一步失败退出码 2。
    """
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(description="受控写三闸命令行入口")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prepare", help="闸1+闸2：产出待写清单")
    for k in ("op", "current", "target", "reply"):
        pp.add_argument("--" + k, required=True)
    pp.add_argument("--known", default="no",
                    help="是否为已核实的自用设备 (yes/no)；默认 no，未知一律拒绝")
    pv = sub.add_parser("verify", help="闸3：回读复核 + 变更留痕")
    pv.add_argument("--plan", required=True)
    pv.add_argument("--readback", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "prepare":
            out = confirm(a.op, a.current, a.target, a.reply,
                          known_device=(a.known.lower() == "yes"))
            print(_json.dumps(out, ensure_ascii=False))
        else:
            plan = _json.load(io.open(a.plan, encoding="utf8"))
            out = audit(plan, a.readback)
            print(_json.dumps(out, ensure_ascii=False))
    except GuardError as e:
        print("守卫拒绝: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
