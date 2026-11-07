# evals —— 可执行回归用例

改动本技能后先跑这一条：

```bash
python3 evals/run_all.py      # 退出码 0 = 全部通过
```

只跑 `smoke_test.py` 不够：`run_all.py` 另含三闸守卫、报告结论与下一步手段、幽灵条目与 RST 判活断言，以及触发词面的「新增召回／新增误伤」两个数。

`mutation_check.py` 是检查器的自证：把关键实现逐项改坏，两个检查器必须报 FAIL。**报 PASS 的检查器，先证明它有本事报 FAIL**，否则「全部通过」不构成证据。

`trigger_eval.json` 是用例数据。本文件（README）不随 SkillHub 包发布，用例脚本随包提供，供使用者自行复核。
