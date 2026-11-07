# 参与开发

本仓库只放一个技能：`skills/auditing-wifi-devices/`。改动脚本或行为规则后按下述顺序自检。

## 回归入口

```bash
python3 skills/auditing-wifi-devices/evals/run_all.py       # 退出码 0 = 全部通过
```

`run_all.py` 覆盖：报告结论与下一步手段、幽灵条目与 RST 判活、三闸守卫的正反例、两步校验 CLI、外部字符串的转义边界，以及触发词面的「新增召回 / 新增误伤」两个数。只跑 `smoke_test.py` 不够。

## 检查器自证

```bash
python3 skills/auditing-wifi-devices/evals/mutation_check.py
```

把关键实现逐项改坏（17 项），两个检查器必须报 FAIL。**报 PASS 的检查器，先证明它有本事报 FAIL**——否则「全部通过」不构成证据。任一项「逃逸」都说明检查器失去鉴别力，先修检查器再谈改动。

## 提交前

- `version`（SKILL.md）与 `scripts/lan_scan.py`、`evals/run_all.py`、`scripts/write_guard.py` 里的版本标注保持一致
- `references/Changelog.md` 增一条「用户能感知到的变化」，版本号与 tag 一致
- 提交与 tag 用 SSH 签名；tag 形如 `v0.4.5`
