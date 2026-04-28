# Framework Broadcast Scanner 使用说明

## 1. 工具简介

这个工具用于扫描 Android 动态广播注册点，默认输出**危险动态广播列表**。

当前支持输入：

- 普通 `class jar`
- 含 `classes.dex` 的 `jar/zip`
- `apk`

当前危险判定规则：

- 命中 `RECEIVER_NOT_EXPORTED` 直接跳过
- `action_list` 全部是保护广播时跳过
- 只要混入一个自定义 action，就继续检查权限
- `signature` / `system` / `signatureOrSystem` 高保护权限跳过
- `normal`、未传 permission、权限表中查不到定义时保留为危险结果

如果开启 `--scan-all-receivers`，会在危险结果之外额外输出**全量动态广播注册点**，方便确认“到底有没有扫到”。

## 2. 运行前准备

目标机器只需要 Java 运行环境，不需要安装 Kotlin。

建议：

- 运行环境：`JDK 11`
- 编译环境：`JDK 11`

需要准备 3 类输入：

1. 扫描目标
- 可以是目录、单个 `jar`、单个 `apk`

2. `proaction.xml`
- 只需要包含多行 `<protected-broadcast ... />`
- 不要求 `<root>`

示例：

```xml
<protected-broadcast android:name="android.intent.action.ACTION_SET_GLOBAL_AUTO_PARAM_DONE" />
<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />
```

3. `permission.txt`
- 兼容你给的这种格式
- 解析器只关心 `permission:` 和 `protectionLevel:`
- `package:`、`label:`、`description:` 这些行可以保留，会自动忽略

示例：

```text
All Permissions:

+ permission:android.permission.NFC_PREFERRED_PAYMENT_INFO
  package:android
  label:首选 NFC 付款服务信息
  description:允许应用获取首选 NFC 付款服务信息，例如注册的应用标识符和路线目的地。
  protectionLevel:normal
+ permission:android.permission.WIFI_ACCESS_COEX_UNSAFE_CHANNELS
  package:android
  label:null
  description:null
  protectionLevel:signature|role
```

如果输入里包含 `dex-jar` 或 `apk`，还需要提供 Android 平台目录或 `android.jar`：

- `--android-platforms /path/to/platforms`
- 或 `--android-platforms /path/to/android.jar`

## 3. 命令行用法

标准命令：

```bash
java -jar framework-broadcast-scanner-all.jar \
  --input-path /path/to/targets \
  --input-type auto \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --android-platforms /path/to/platforms \
  --out-dir /path/to/out \
  --scan-all-receivers \
  -j 2
```

### 3.1 参数说明

- `--input-path`
  - 必填
  - 可以是目录、单个 `jar`、单个 `zip`、单个 `apk`

- `--input-type`
  - 选填，默认 `auto`
  - 可选值：
    - `auto`
    - `class-jar`
    - `dex-jar`
    - `apk`

- `--jar-dir`
  - 老参数兼容别名，等价于 `--input-path`

- `--protected-broadcasts`
  - 必填
  - 指向 `proaction.xml`

- `--permissions`
  - 必填
  - 指向 `permission.txt`

- `--android-platforms`
  - 扫描 `dex-jar` / `apk` 时必填
  - 可传 Android SDK `platforms` 目录，或单个 `android.jar`

- `--out-dir`
  - 选填
  - 默认 `out`

- `--package-prefix`
  - 选填
  - 只扫描指定类名前缀
  - 例如：`--package-prefix com.huawei`

- `--scan-all-receivers`
  - 选填
  - 默认只输出危险广播
  - 加上后会额外输出全量动态广播文件

- `-j`
  - 选填
  - 默认 `1`
  - 按输入文件级并发扫描
  - 当前通过“父进程调度 + 子进程扫描单文件”实现，避免 Soot 全局状态互相干扰

### 3.2 自动判型规则

`--input-type auto` 下的行为：

- 目录：递归扫描 `.jar`、`.zip`、`.apk`
- `.apk`：按 APK 处理
- `.jar` / `.zip`：
  - 内部含 `.dex` 时按 `dex-jar`
  - 否则按 `class-jar`

## 4. 输出文件说明

### 4.1 主结果

- `dangerous_dynamic_broadcasts.jsonl`
- `dangerous_dynamic_broadcasts.md`

这两份文件只表示**危险动态广播列表**。

### 4.2 全量结果

只有开启 `--scan-all-receivers` 才会生成：

- `all_dynamic_broadcasts.jsonl`
- `all_dynamic_broadcasts.md`

这两份文件表示**所有扫描到的动态广播注册点**。

### 4.3 统计与错误

- `scan_summary.json`
- `partial_jars.jsonl`
- `failed_jars.jsonl`
- `scan_errors.log`

注意：

- 字段名仍然沿用 `jar_path`
- 现在它实际表示“扫描输入文件路径”，可能是 `jar`、`zip` 或 `apk`

## 5. 危险广播字段说明

主结果中的每条记录只保留这 8 个字段：

- `jar_path`
  - 命中的输入文件路径

- `declaring_class`
  - 注册调用所在类

- `declaring_method`
  - 注册调用所在方法签名

- `source_line`
  - 行号
  - `dex-jar` / `apk` 中如果恢复不到，会是 `null`

- `action_list`
  - 当前注册点恢复出的 action 数组
  - 恢复失败时为空数组

- `broadcast_permission`
  - 传给 `registerReceiver(...)` 的 permission
  - 无值时为 `null`

- `permission_protection_level`
  - 从 `permission.txt` 查到的保护级别原文
  - 查不到或无 permission 时为 `null`

- `evidence`
  - 注册语句摘要

## 6. 统计口径

`scan_summary.json` 中：

- `total_jars`
  - 实际表示总扫描文件数，包含 `jar` / `zip` / `apk`

- `success_jars`
  - 完整扫描成功的文件数

- `partial_jars`
  - 中途报错，但报错前已经产出结果的文件数

- `failed_jars`
  - 完全失败、没有产出结果的文件数

- `dangerous_broadcasts`
  - 最终危险广播总数

- `all_dynamic_broadcasts`
  - 全量动态广播总数
  - 只有开启 `--scan-all-receivers` 时才有实际意义

- `full_success_rate`
  - `success_jars / total_jars`

- `processed_rate`
  - `(success_jars + partial_jars) / total_jars`

## 7. 终端进度

非交互终端下会输出逐文件进度，例如：

```text
scan started: total_jars=2
progress: 1/2 success=1 partial=0 failed=0 dangerous=1 status=success current=sample.apk
progress: 2/2 success=2 partial=0 failed=0 dangerous=2 status=success current=sample-dex.jar
scan completed: total_jars=2, success_jars=2, partial_jars=0, failed_jars=0, dangerous_broadcasts=2, all_dynamic_broadcasts=4
```

交互终端下会显示单行刷新进度条。

## 8. 已验证真实样例

本地已经用下面这组真实样例验证通过：

- Android 平台目录
  - `/Users/pa1m/workspace/appshark/config/tools/platforms`

- 含 dex 的 jar
  - `/tmp/fbscan-real-v2/dual-inputs/sample-dex.jar`

- APK
  - `/tmp/fbscan-real-v2/dual-inputs/sample.apk`

对应输出摘要：

```json
{"total_jars":2,"success_jars":2,"partial_jars":0,"failed_jars":0,"dangerous_broadcasts":2,"all_dynamic_broadcasts":4,"full_success_rate":1.0000,"processed_rate":1.0000}
```

仓库里还附带了一份验证输出示例：

- `examples/validated-output/dangerous_dynamic_broadcasts.jsonl`
- `examples/validated-output/all_dynamic_broadcasts.jsonl`
- `examples/validated-output/scan_summary.json`

## 9. 常见问题

### 9.1 `Unsupported class file major version 65`

说明你喂进来的 class 是更高版本字节码，当前运行时或 Soot 不兼容。  
优先建议：

- 用 `JDK 11` 运行扫描器
- 确认输入不是 JDK 21 编译出的 class

### 9.2 扫描 `dex-jar` / `apk` 时提示缺少 Android 平台

补上：

```bash
--android-platforms /path/to/platforms
```

或者：

```bash
--android-platforms /path/to/android.jar
```

### 9.3 `jar` / `zip` 扫不到

先确认它到底是哪种：

- 普通 class jar
- 里面封了 `classes.dex` 的 dex-jar

如果不确定，直接用：

```bash
--input-type auto
```

### 9.4 为什么 `jar_path` 字段里会出现 APK 路径

这是兼容历史字段名的设计。  
字段名暂时不改，但值可能对应：

- `.jar`
- `.zip`
- `.apk`
