---
name: android-dynamic-broadcast-llm-review-orchestrator
description: 直接接入动态广播扫描器，生成并读取 dangerous_dynamic_broadcasts.jsonl，按应用边界定位逆向源码，补 action 追溯并只对自定义 action 分支深挖 onReceive。
---

# Android Dynamic Broadcast LLM Review Orchestrator

这个 skill 用来消费动态广播扫描器输出的危险广播列表，并把：

- APK / JAR / 目录扫描前置输入生成
- `action_list` 为空时的源码追溯
- 扫描器输出的自定义 action 分支深挖
- `onReceive` 自定义分支敏感行为分析
- 子 agent 中间结果落盘
- 主 agent 最终复核汇总

做成固定编排流程。

## 什么时候用

当用户要做下面这些事时，使用这个 skill：

- 基于 `dangerous_dynamic_broadcasts.jsonl` 深挖真实风险
- 用户给 APK / JAR / APK 目录，需要先生成 `dangerous_dynamic_broadcasts.jsonl`
- 让多个子 agent 并行分析动态广播 finding
- `action_list` 为空时追溯 `IntentFilter` 真实 action
- 只分析自定义 action 对应的 `onReceive` 分支
- 对 `normal` 权限保护的动态广播继续分析敏感操作
- 输出中间结果和最终审计报告

## 扫描前置步骤

如果用户给的是 APK、JAR、ZIP 或目录，而不是已经生成好的 `dangerous_dynamic_broadcasts.jsonl`，必须先直接运行内置扫描器生成输入文件。扫描器是本 skill 的前置工具，不需要额外入口。

扫描命令固定为：

```bash
java -jar vendor/framework-broadcast-scanner/framework-broadcast-scanner-all.jar \
  --input-path <apk-or-jar-or-dir> \
  --input-type auto \
  --protected-broadcasts references/protected-broadcasts.txt \
  --permissions references/permissions.txt \
  --android-platforms <android-platforms-or-android.jar> \
  --out-dir <scan-out-dir> \
  --scan-all-receivers
```

扫描阶段固定规则：

- `references/protected-broadcasts.txt` 是唯一保护广播基线，格式必须是一行一个 action。
- 只使用 `references/protected-broadcasts.txt`，不生成、不使用其他格式的保护广播基线。
- 不转换、不改写扫描结果。
- `dangerous_dynamic_broadcasts.jsonl` 直接作为深挖阶段的 `--findings` 输入。
- 扫描结果为空时停止，不逆向、不深挖。
- 扫描结果非空时，才进入源码准备和 LLM 深挖。

源码准备规则：

- 如果用户已经提供 `--reverse-root` 或逆向源码目录，直接使用该目录。
- 如果用户只提供 APK 且扫描结果非空，使用 `vendor/jadx/dist/bin/jadx` 逆向到样本工作目录，再把该目录作为 `--reverse-root`。
- 如果用户提供 JAR 但没有源码目录，只能完成扫描；深挖阶段必须把源码上下文不足记录为 `needs_more_evidence`，不能假装完成源码分析。

## 深挖输入

固定输入：

- `--findings <dangerous_dynamic_broadcasts.jsonl>`
- `--reverse-root <逆向源码根目录>`
- `--system-broadcast-file <references/protected-broadcasts.txt>`
- `--out-dir <输出目录>`

可选输入：

- `--trace-max-hops <N>`，默认 `3`
- `--onreceive-max-hops <N>`，默认 `3`
- `--max-remediation-rounds <N>`，默认 `1`
- `--max-total-attempts-per-finding <N>`，默认 `2`

默认主输入文件是 `dangerous_dynamic_broadcasts.jsonl`。

`action_list` 语义固定为：

- `action_list = []`：扫描阶段没有恢复出 action，必须由子 agent 在源码内补 action。
- `action_list = ["..."]`：扫描器已经输出的 action 候选，子 agent 直接按模板深挖对应分支，不允许主 agent 重新分类。
- 不允许 `unknown_action`；历史脏数据进入 batch 前必须清洗为空列表。

## 绝对边界

- 不要直接在整个 `reverse-root` 下 grep `declaring_class`。
- 必须先建立 `app-index.json`，再把每条 finding 绑定到唯一 `app_root`。
- `candidate_source_roots` 绝不能直接填成用户提供的 `reverse-root`。
- `candidate_source_roots` 只能填写 `app_root` 下实际存在、且确实承载源码的具体子目录；例如 `src/`、`sources/`、`smali*/`、`java/`、`kotlin/`、`jadx-sources/`。
- 如果只能确定 `app_root`，但无法收敛到具体源码子目录，则 `candidate_source_roots` 必须留空，并把该 finding 标成 `needs_more_evidence` 或 `app_index_mode = unresolved`。
- `AndroidManifest.xml` 是优先线索，不是必需前提；没有 manifest 不能跳过审计。
- 没有 manifest 时，必须走 `source_only` 索引；不能升级成全局 grep。
- 不要整文件读取 `system-broadcast-file`；只有从源码补出新 action 时，才允许对当前 action 用 `rg`/`grep` 查询。
- 非空 `action_list` 来自扫描器输出，主 agent 和子 agent 都不能把它当成未分类原始 action 列表重新筛选。
- 每个子 agent 最多处理 10 条 finding。
- 任一时刻最多并发 5 个子 agent，必须采用 wave-based execution。
- 子 agent 必须先写中间结果文件，再由主 agent 复核。
- `normal` 权限、未定义权限、无权限都不能直接关闭；必须继续分析敏感行为。
- `onReceive` 分析时只看自定义 action 分支，不分析纯系统广播分支。
- `onReceive` 分析不能停留在“读一下方法体”；必须对命中的自定义 action 分支继续做数据流追踪，直到收敛到 sink、guard、无后续相关流或明确缺失上下文。

## 输出目录

输出目录固定采用：

- `broadcast-review-records-YYYY-MM-DD/`

至少生成：

- `input-summary.json`
- `app-index.json`
- `partition-plan.json`
- `intermediate/batch-*-input.json`
- `intermediate/batch-*-prompt.md`
- `intermediate/batch-*.json`
- `intermediate/batch-*.md`
- `reviewed-findings.json`
- `final-review-report.md`
- `coverage-summary.json`

## 固定资产

主 agent 不再自由组织子 agent 提示词，必须优先复用这些固定资产：

- `templates/subagent-batch-template.md`
- `templates/remediation-template.md`
- `templates/final-review-template.md`
- `scripts/build_review_batches.py`
- `scripts/validate_review_batch.py`
- `scripts/finalize_review_report.py`
- `vendor/framework-broadcast-scanner/framework-broadcast-scanner-all.jar`
- `vendor/jadx/dist/bin/jadx`
- `references/permissions.txt`
- `references/protected-broadcasts.txt`

推荐顺序固定为：

1. 运行 `build_review_batches.py` 生成 `app-index.json`、`partition-plan.json`、`batch-*-input.json` 和 `batch-*-prompt.md`
2. 主 agent 只替换模板占位符并派发子 agent
3. 每个子 agent 写 `batch-*.json` 和 `batch-*.md`
4. 主 agent 运行 `validate_review_batch.py` 做结构与证据校验
5. 需要时套用 `templates/remediation-template.md` 做补分析
6. 最后运行 `finalize_review_report.py` 汇总最终报告

## 固定流程

顺序固定，不能跳步：

1. 读取输入并校验 finding 结构
2. 建立应用索引
3. 切分 finding 批次
4. 分波次派子 agent 执行
5. 主 agent 读取全部中间结果并复核
6. 输出最终 JSON 和 Markdown 报告

任一阶段缺少必需产物，流程必须停止并说明阻塞点。

## 主 agent 与子 agent 分工

### 主 agent 只负责这些事

主 agent 的职责固定为：

1. 读取和校验输入
2. 构建 `app-index.json`
3. 按批次切分 finding
4. 分波次派发子 agent
5. 校验子 agent 中间结果是否完整
6. 复核子 agent 结论
7. 汇总最终 JSON 和 Markdown 报告

主 agent 明确**不负责**：

- 不负责直接下钻单条 finding 的源码逻辑
- 不负责直接分析 `onReceive` 分支
- 不负责直接判断单条 finding 是否有敏感 sink
- 不负责直接判断 `action_list` 中哪些是系统 action、哪些是自定义 action
- 不负责把非空 `action_list` 重新分类或改写
- 不负责直接执行 `system-broadcast-file` 查询来替子 agent 完成空 action 补全后的基线过滤
- 不负责在没有子 agent 中间结果时自行给最终结论

除非是做结构校验或复核，主 agent 不能提前对单条 finding 做实质性源码分析。
主 agent 传给子 agent 的输入只能包含：

- 原始 finding 记录
- `resolved_app_root`
- `candidate_source_roots`
- `app_index_mode`
- 批次元数据

主 agent 禁止把自己提前分析出来的：

- “这个 action 是自定义的”
- “这个 action 是系统的”
- “这个分支就是要分析的分支”
- “这个 finding 已经很危险/不危险”

这类判断预先塞给子 agent。

主 agent 还必须负责：

- 识别 `incomplete_subagent_analysis`
- 强制生成补分析任务
- 在允许重试时重新派发补分析子 agent
- 只有在达到停止条件后，才允许把结果降级成 `needs_more_evidence`

### 子 agent 只负责这些事

每个子 agent 只负责自己 batch 内的 finding，职责固定为：

1. 使用主 agent 提供的 `resolved_app_root`
2. 在限定目录内定位类、注册点和 `onReceive`
3. 仅在 `action_list` 为空且从源码补出 action 后，执行 `system-broadcast-file` 查询
4. 对非空 `action_list` 原样作为扫描器输出的 action 候选处理，不重新分类、不改写
5. 只对自定义 action 分支做追踪
6. 继续追踪分支内的数据流、调用链、sink、guard
7. 生成 `intermediate/batch-*.json` 和 `intermediate/batch-*.md`

子 agent 明确**不负责**：

- 不负责重新切批
- 不负责重新构建全局 app 索引
- 不负责合并其他 batch 结果
- 不负责直接输出最终总报告
- 不负责越过 `resolved_app_root` 做全局 grep

## Phase 1：读取输入

优先读取：

1. 用户显式提供的 `--findings`
2. 当前工作目录下的 `dangerous_dynamic_broadcasts.jsonl`

如果输入不存在：

- 直接停止
- 明确告诉用户缺少 finding 文件
- 不要猜路径

读取 finding 后，主 agent 必须先校验每条记录至少包含：

- `jar_path`
- `declaring_class`
- `declaring_method`
- `action_list`
- `broadcast_permission`
- `permission_protection_level`
- `evidence`

同时生成 `input-summary.json`，至少记录：

- `finding_count`
- `empty_action_list_count`
- `non_empty_action_list_count`
- `normal_permission_count`
- `unknown_permission_count`

## Phase 2：应用索引

主 agent 必须先建立 `app-index.json`，再允许任何源码回查。

### A. Manifest 优先路径

如果某个样本目录下存在 `AndroidManifest.xml`，建立：

- `app_id`
- `app_root`
- `manifest_path`
- `package_name`
- `candidate_source_roots`
- `index_mode = manifest_backed`

这里的 `candidate_source_roots` 必须满足：

- 只能是 `app_root` 下的具体子目录
- 该目录内必须真实存在 Java / Kotlin / smali / Jadx 源码文件
- 不能直接写 `app_root`
- 更不能写用户传入的总 `reverse-root`

### B. 无 Manifest 回退路径

如果某个样本目录没有 `AndroidManifest.xml`，仍必须纳入索引，建立：

- `app_id`
- `app_root`
- `manifest_path = null`
- `package_name = null`
- `candidate_source_roots`
- `top_level_package_prefixes`
- `index_mode = source_only`

回退索引规则固定：

- 只允许以 `reverse-root` 下一层样本目录或用户给定样本目录作为 `app_root`
- `app_root` 只表示样本边界，不表示源码目录
- 在每个 `app_root` 内统计：
  - Java / Kotlin / smali / Jadx 目录
  - 高频包名前缀
  - 类名分布
- 只能把这些真实源码子目录写入 `candidate_source_roots`
- 用 `declaring_class` 的包名前缀先做精确匹配
- 只在候选 `app_root` 内做受限 grep

`candidate_source_roots` 的生成规则必须固定为：

1. 先枚举 `app_root` 下常见源码目录名：
   - `src`
   - `sources`
   - `java`
   - `kotlin`
   - `smali`
   - `smali_classes*`
   - `jadx-sources`
   - `decompiled`
2. 只保留实际存在且包含源码文件的目录
3. 如果 `decompiled/` 这类目录下还有更具体的源码目录，优先写更具体的子目录，而不是写大根目录
4. 如果没有任何具体源码目录可确认：
   - `candidate_source_roots = []`
   - 不允许退化成 `[reverse-root]`

如果多个 `app_root` 同时命中且无法唯一收敛：

- 该 finding 标记为 `needs_more_evidence`
- `app_index_mode = unresolved`
- 不能升级成全局 grep

## Phase 3：切分任务

主 agent 负责切批，不允许子 agent 自己抢任务。

切批规则固定：

- 每批最多 10 条 finding
- 每个子 agent 只负责 1 个 batch
- 总并发最多 5 个子 agent
- 批次数超过 5 时，必须 wave-based execution

波次顺序固定：

1. wave 1 最多 5 个 batch
2. wave 1 全部完成后，才允许启动 wave 2
3. 依次类推

主 agent 必须输出 `partition-plan.json`，至少记录：

- `total_findings`
- `batch_count`
- `wave_count`
- 每个 `batch_id` 的 finding 列表
- 每个 `batch_id` 对应的 `resolved_app_root`
- 每个 `batch_id` 对应的 `candidate_source_roots`

主 agent 在这一步仍然不能自己进入单条 finding 的源码分析，只能准备任务输入。
主 agent 在这一步也不能自己做这些事：

- 不能先判定 `action_list` 是否包含自定义 action
- 不能先判定某个 action 属于系统广播
- 不能先替子 agent 选出要分析的 action 分支

这些都必须留给对应 batch 的子 agent，并写入中间结果。

默认固定切批策略允许直接按 4/4/4 切 3 个 batch；如果样本后续变多，仍沿用“单 batch 单模板”的约束，不允许主 agent 临时改写子 agent 协议。

## Phase 4：子 agent 分析协议

每个子 agent 必须严格按 `resolved_app_root` 限制搜索边界。

如果主 agent 传给子 agent 的 `candidate_source_roots` 为空：

- 子 agent 不能擅自升级成全局 grep
- 必须把该 finding 收敛为 `needs_more_evidence`，并写清楚缺少哪一层源码目录定位证据

如果主 agent 没有给出明确的 `resolved_app_root`：

- 子 agent 不能自己回到 `reverse-root` 做全局搜索
- 必须把该 finding 收敛为 `needs_more_evidence`

## 子 agent 正式状态机

子 agent 单条 finding 只允许先落到以下状态之一：

- `confirmed_sensitive`
- `no_sensitive_behavior_found`
- `system-only-after-trace`
- `needs_more_evidence`
- `incomplete_subagent_analysis`

其中 `incomplete_subagent_analysis` 的含义固定为：

- 子 agent 已经开始分析
- 但没有交出最小证据集
- 或虽然给了结论，但结论无法由现有证据支撑

### 路线 A：`action_list` 非空

这类 finding 来自扫描器已经过滤后的自定义 action 列表，不再补 action，直接进入 `onReceive` 深挖。子 agent 不能把 `action_list` 当成未分类原始 action 列表，也不能因为重复分类而跳过分析。

1. 将 `action_list` 作为已过滤后的自定义 action 候选
2. 只分析这些自定义 action 对应的 `onReceive` 分支
3. `action_classification_evidence` 记录为 `scanner_filtered_custom_action`
4. 忽略其他兄弟分支和系统广播分支

这里的硬约束是：

- `action_list` 不允许出现 `unknown_action` 或其他占位值
- 输入构建阶段如遇占位 action，必须在 batch 构建前清洗为空列表
- 主 agent 不能改写扫描器已经输出的真实自定义 action
- 子 agent 不得对非空 `action_list` 重新做系统/自定义分类
- 子 agent 不得重新扩大分析范围到系统广播分支

### 路线 C：`kind = static_receiver`

如果 finding 被标成 `static_receiver`：

1. 不再强制套用 `registerReceiver` 的 action 补全流程
2. 直接围绕 receiver 入口逻辑、命中 action 分支和后续数据流做分析
3. 若确认高风险，仍必须补 PoC

这里的硬约束是：

- static finding 可以进入同一轮审计
- 但最终报告必须单列
- 不能把 static finding 写成“动态广播漏洞”结论

### 路线 B：`action_list` 为空

这类 finding 先追溯源码补 action，再决定是否继续深挖：

1. 在 `resolved_app_root` 内定位注册点和相关类
2. 只做有限跳数追溯：
   - 当前方法内局部变量回溯
   - 零参数 helper 方法
   - 简单常量字段
   - 简单包装 API
3. 超过 `--trace-max-hops` 仍未恢复 action：
   - 标记 `needs_more_evidence`
4. 如果恢复出 action：
   - 逐条用 `system-broadcast-file` 查询
   - 只有 `custom_or_not_found` 才进入 `onReceive` 分支分析
5. 如果全部命中系统广播：
   - 标记 `system-only-after-trace`

### `onReceive` 分析要求

子 agent 必须只分析自定义 action 分支，而且分析顺序固定为：

1. 先确认当前自定义 action 命中了 `onReceive` 的哪条分支
2. 再对该分支继续做数据流追踪
3. 最后把该分支收敛到明确结论

#### A. 分支定位

必须先确认自定义 action 在 `onReceive` 里对应的具体分支。允许的典型形态包括：

- `if ("ACTION".equals(intent.getAction()))`
- `switch(action)`
- `when(action)`
- `if/else if` 链
- helper 方法包装后的 action 比较

如果 `onReceive` 同时处理系统广播和自定义广播：

- 只能对自定义广播命中的分支继续追踪
- 不能把整个 `onReceive` 粗看后直接结束

如果多个自定义 action 共用同一段逻辑：

- 允许合并分析共享分支
- 但必须在结果中写清楚哪些自定义 action 命中了同一段逻辑

#### B. 分支内数据流追踪

对命中的自定义 action 分支，必须继续追踪这些数据流：

- `intent.getAction()`
- `intent.getStringExtra`
- `intent.getParcelableExtra`
- `intent.getExtras`
- 从 extras 派生出来的局部变量
- 分支内向下调用的方法参数
- 简单对象字段读取
- 本类 helper 方法调用前后的实参/返回值关系

追踪边界固定如下：

- 方法内必须追：
  - 局部变量赋值
  - 条件分支
  - 参数透传
  - `intent` 相关取值
- 有限跨方法必须追：
  - 从当前自定义 action 分支直接调用出去的方法
  - 只允许继续追 `--onreceive-max-hops`
  - 默认 `3`
- 不要求全程序追：
  - 不要求全程序污点分析
  - 不要求跨线程、跨进程、跨组件全局闭环
  - 不要求扩散到与当前自定义 action 分支无关的兄弟逻辑

如果分支里直接触发了以下敏感点，必须继续追到该敏感点或明确边界：

- `startActivity`
- `startService`
- `bindService`
- `sendBroadcast`
- 敏感 Manager / Provider / 文件 / 网络 / Shell / 设置操作

不能只记录“调用了某个方法”，必须继续判断这个调用最终做了什么。

#### C. 收敛到结论

每条自定义 action 分支必须收敛到以下之一：

- `confirmed_sensitive`
- `no_sensitive_behavior_found`
- `needs_more_evidence`

只有在以下情况才允许停止：

- 到达敏感 sink
- 到达有效 guard
- 没有更多与当前自定义 action 分支相关的数据流
- 达到 hop 上限
- 缺少关键上下文

子 agent 至少要回答：

- 是否存在界面启动、界面跳转、弹窗、前台拉起
- 是否存在 Service 启动、bind、Job / Alarm / 任务调度
- 是否存在敏感设置、账号、设备、网络、文件、组件控制等操作
- 是否存在额外权限校验、caller 校验、参数校验、来源校验

`permission_protection_level = normal` 时：

- 不能关闭
- 必须继续分析是否存在敏感行为

#### D. 敏感行为与 guard 双记录

对子定义 action 分支，必须至少记录两组事实：

1. 命中的敏感操作：
   - 界面拉起、Activity 跳转、Dialog/Window/UI 唤起
   - Service 启动、bind、前台服务
   - 广播转发、PendingIntent、组件调度
   - 账号、设置、设备标识、系统状态修改
   - 文件读写、Provider 访问、URI 处理
   - 网络请求、下载、上传、远程配置
   - Shell / Runtime / 反射 / 动态加载
   - 权限授予、组件开关、包管理操作
2. 已见保护/校验：
   - 权限检查
   - caller / uid / pid 校验
   - action 白名单
   - extra 参数校验
   - 用户态 / 前台态 / 登录态校验
   - 特定系统属性或签名校验

如果命中了敏感 sink 但没有看到可靠 guard：

- 不能只写“疑似风险”
- 必须进入 `confirmed_sensitive` 或 `needs_more_evidence`

#### E. 什么时候必须标记为 `incomplete_subagent_analysis`

子 agent 或主 agent 复核时，只要遇到以下任一情况，必须标记为 `incomplete_subagent_analysis`：

1. `onReceive` 分析证据不足：
   - `onreceive_analysis_status = completed`，但没有 `visited_methods`
   - 没有 `matched_branch_evidence`
   - 没有 `dataflow_trace_summary`
   - 没有 `trace_stop_reason`
   - 只写了“读了 onReceive / 未见明显风险”之类主观结论
2. `confirmed_sensitive` 证据不足：
   - 没有 `visited_sinks`
   - 没有 `guard_summary`
   - 没有完整数据流摘要
   - 没有 PoC
   - PoC 与 action / extras / sink 不一致
3. `no_sensitive_behavior_found` 证据不足：
   - 没有说明为何停止
   - 没有说明是命中 guard 还是没有继续相关数据流
   - 没有记录至少一条被追踪过的方法链
4. action 补全证据不足：
   - `action_list` 为空，子 agent 声称已恢复 action，但没有 `traced_action_list`
   - 没有说明 action 是怎么恢复出来的
   - 没有给出系统/自定义 action 判定证据

## 系统广播判定协议

只能对**当前 action**做查询，不能 preload 整个文件。

判定三态固定为：

- `system_exact`
- `system_prefix`
- `custom_or_not_found`

查询规则固定：

- 精确 action：查是否存在完全相等的行
- 前缀通配：只 grep 可能命中的 `xxx.*` 行

## 子 agent 输出约定

每个子 agent 必须同时输出：

- `intermediate/batch-0001.json`
- `intermediate/batch-0001.md`

JSON 每条至少包含：

- `finding_id`
- `kind`
- `jar_path`
- `declaring_class`
- `declaring_method`
- `resolved_app_root`
- `app_index_mode`
- `input_action_list`
- `traced_action_list`
- `custom_action_list`
- `trace_status`
- `trace_hops_used`
- `matched_custom_actions`
- `onreceive_entry_method`
- `matched_branch_evidence`
- `dataflow_trace_summary`
- `visited_methods`
- `visited_sinks`
- `guard_summary`
- `trace_stop_reason`
- `onreceive_hops_used`
- `onreceive_analysis_status`
- `custom_branches_analyzed`
- `ui_operations`
- `sensitive_operations`
- `guards_found`
- `final_subagent_verdict`
- `evidence`
- `needs_main_agent_attention`
- `analysis_attempt`
- `remediation_required`
- `remediation_reason`
- `previous_attempt_id`
- `attempt_status`
- `poc_command`
- `poc_preconditions`
- `poc_expected_effect`
- `poc_minimal_extras`

推荐 `final_subagent_verdict` 只使用：

- `confirmed_sensitive`
- `system-only-after-trace`
- `needs_more_evidence`
- `no_sensitive_behavior_found`

`trace_stop_reason` 只能取：

- `reached_sensitive_sink`
- `reached_effective_guard`
- `no_more_relevant_flow`
- `hop_limit_reached`
- `missing_context`

`attempt_status` 只能取：

- `initial`
- `remediation`
- `finalized`

PoC 约束固定为：

- `poc_command` 必须优先采用 `adb shell am broadcast -a "ACTION"` 形式
- 如果需要 extras，必须补最小可复现 extras
- 如果 action、extras 或命中分支仍无法收敛，不能伪造 PoC，必须落为 `needs_more_evidence`

## Phase 5：主 agent 复核

主 agent 必须读取所有中间结果，然后做两步：

1. 结构校验
2. 内容复核

主 agent 必须额外复核：

- 所有 `app_index_mode = source_only` 且结论为高风险的 finding
- 所有 `app_index_mode = unresolved`
- 所有 `needs_more_evidence`
- 所有 `custom_action_list` 为空但 `trace_status = resolved`
- 所有 `permission_protection_level = normal` 且存在敏感操作的 finding
- 所有 `onreceive_analysis_status = completed` 但 `visited_methods` 为空的 finding
- 所有 `confirmed_sensitive` 但缺少 `matched_branch_evidence` 的 finding
- 所有 `confirmed_sensitive` 但缺少 `visited_sinks` 的 finding
- 所有 `no_sensitive_behavior_found` 但缺少 `trace_stop_reason` 的 finding
- 所有 `needs_more_evidence` 但没有写清 `missing_context` 的 finding
- 所有只记录了 “onReceive exists” 但没有 `dataflow_trace_summary` 的 finding

如果主 agent 覆写了结论，必须在最终结果里附带：

- `main_agent_correction`
- `review_agent`
- `batch_id`

如果主 agent 发现子 agent 只是“读了 `onReceive` 方法”但没有真正追踪分支内数据流：

- 必须覆写为 `needs_more_evidence` 或要求补分析
- 不能直接通过

## 强制补分析闭环

主 agent 对每个 batch 的处理中，顺序固定为：

1. 读取子 agent 中间结果
2. 做结构校验
3. 做证据充分性校验
4. 若命中 `incomplete_subagent_analysis`：
   - 不允许直接汇入最终结果
   - 必须生成补分析任务
   - 重新派给新的子 agent
5. 补分析子 agent 只处理这些不完整 finding
6. 主 agent 再次读取补分析结果并复核
7. 直到：
   - 转为有效结论
   - 或达到强制停止条件

补分析的强制规则固定为：

- 只要还有剩余重试次数，必须重派
- 不能由主 agent 自己补做源码分析来代替子 agent
- 不能因为“看起来大概没问题”就放过
- 不能因为“模型已经读过一次了”就不重派

默认行为固定为：

- 首轮不足 -> 至少强制补跑 1 轮
- 补跑后仍不足 -> 才允许进入降级判断

只有以下情况才允许从 `incomplete_subagent_analysis` 降级为 `needs_more_evidence`：

1. 已达到 `--max-total-attempts-per-finding`
2. 客观上下文缺失：
   - 类找不到
   - `resolved_app_root` 无法定位
   - `candidate_source_roots` 为空
   - 关键 helper / sink / receiver 实现缺失
   - 必需 extras / branch 逻辑无法恢复
3. 已明确写出阻塞原因

如果只是“子 agent 没追够”，不能直接降级，必须先补分析。

## 最终报告

主 agent 汇总后必须输出：

- `reviewed-findings.json`
- `final-review-report.md`
- `coverage-summary.json`

最终 `final-review-report.md` 是**漏洞报告**，不是全量审计台账。

最终 `final-review-report.md` 必须使用中文编写。漏洞描述、攻击路径、漏洞成因、影响、Guard / 校验情况、复现前提、预期效果和修复建议都必须是中文；代码标识、类名、方法名、action、命令和路径可以保持原文。

最终 Markdown 报告固定结构：

- `# 动态广播漏洞报告`
- `## 概览`
- `## 漏洞 1：...`
- `## 漏洞 2：...`
- `## 覆盖率统计`

硬约束固定为：

- 正文只允许出现 `final_subagent_verdict = confirmed_sensitive` 的 finding
- `needs_more_evidence`
- `system-only-after-trace`
- `no_sensitive_behavior_found`
- 主 agent 修正为非漏洞的项

以上内容都**不得进入最终 md 正文**，只允许保留在：

- `reviewed-findings.json`
- `coverage-summary.json`

每条最终确认漏洞必须包含：

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

只有当子 agent 为该 finding 提供了：

- `vulnerability_analysis`
- `attack_path`
- `root_cause`
- `impact`
- `fix_recommendation`
- `vuln_code_blocks`
- `vuln_code_paths`

才允许进入最终 md；否则必须视为 `incomplete_subagent_analysis` 并补分析。

最终报告禁止退化为“代码片段列表”。代码证据必须服务于漏洞分析链路：入口、分支、数据流、sink、guard 缺失、影响和修复建议都必须在正文中说清楚。

`覆盖率统计` 至少包含：

- finding 总数
- 实际审计完成数
- `manifest_backed_app_count`
- `source_only_app_count`
- `unresolved_finding_count`
- 总批次数
- 总波次数
- 主 agent 修正数
- `remediation_round_count`
- `incomplete_subagent_analysis_count`
- `forced_remediation_count`
- `downgraded_to_needs_more_evidence_count`

强制补分析、主 agent 修正、证据不足和系统广播项只允许在 JSON / 覆盖率统计中体现，不允许作为条目正文写入最终 Markdown 漏洞报告。

## 禁止事项

- 禁止在整个 `reverse-root` 直接 grep `declaring_class`
- 禁止整文件读取 `system-broadcast-file`
- 禁止因为没有 `AndroidManifest.xml` 就跳过
- 禁止因为权限是 `normal` 就关闭
- 禁止分析纯系统广播分支
- 禁止子 agent 不落中间文件就直接给主 agent 结论
