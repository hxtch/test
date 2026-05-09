# 最终中文漏洞报告模板

主 agent 只能基于子 agent 中间结果做最终复核和汇总，不能自己补做源码分析。

最终 `final-review-report.md` 必须是中文漏洞报告，不是全量审计台账。除代码、路径、类名、方法名、action、sink、命令外，所有自然语言内容都必须使用中文。

## 复核顺序

1. 结构校验
2. 证据充分性校验
3. remediation 状态核对
4. 仅汇总最终确认漏洞

## 强制打回条件

- `confirmed_sensitive` 缺 `matched_branch_evidence`
- `confirmed_sensitive` 缺 `dataflow_trace_summary`
- `confirmed_sensitive` 缺 `visited_methods`
- `confirmed_sensitive` 缺 `visited_sinks`
- `confirmed_sensitive` 缺 `poc_command`
- `confirmed_sensitive` 缺 `vulnerability_analysis`
- `confirmed_sensitive` 缺 `attack_path`
- `confirmed_sensitive` 缺 `root_cause`
- `confirmed_sensitive` 缺 `impact`
- `confirmed_sensitive` 缺 `fix_recommendation`
- `confirmed_sensitive` 缺 `vuln_code_blocks`
- `confirmed_sensitive` 缺 `vuln_code_paths`
- `confirmed_sensitive` 的漏洞描述、攻击路径、漏洞成因、影响、修复建议不是中文
- `input_action_list=[]` 且缺 `traced_action_list`

## 最终报告结构

最终 Markdown 只允许使用下面结构：

- `# 动态广播漏洞报告`
- `## 概览`
- `## 漏洞 1：...`
- `## 漏洞 2：...`
- `## 覆盖率统计`

正文只渲染 `final_subagent_verdict = confirmed_sensitive` 的 finding。

以下结果不得出现在最终 Markdown 正文中，只能保留在 `reviewed-findings.json` 或 `coverage-summary.json`：

- `needs_more_evidence`
- `system-only-after-trace`
- `no_sensitive_behavior_found`
- `incomplete_subagent_analysis`
- 主 agent 修正为非漏洞的 finding

每条漏洞固定包含：

- 基本信息
- `### 漏洞描述`
- `### 攻击路径`
- `### 漏洞成因`
- `### 影响`
- `### Guard / 校验情况`
- `### 漏洞代码与证据`
- `### PoC`
- `### 复现前提`
- `### 预期效果`
- `### 修复建议`

漏洞报告禁止退化为“代码片段列表”。每条漏洞必须说明风险等级、外部可触发入口、数据流如何到达 sink、缺少什么 guard、可造成什么影响，以及如何修复。
