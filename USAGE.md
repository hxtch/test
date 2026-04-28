# Framework Jar 动态广播扫描器使用文档

## 1. 工具简介

这个工具用于扫描 `framework jar` 目录中的动态广播注册点，最终输出**危险广播列表**。

当前版本默认会扫描所有类中的动态广播注册点。

如果你只想筛选某个包前缀，比如只看 `com.huawei.*`，可以加 `--package-prefix com.huawei`。

工具内部会按以下规则过滤：

- 命中 `RECEIVER_NOT_EXPORTED` 的动态广播直接跳过
- `action_list` 中全部 action 都属于保护广播时直接跳过
- 动态广播权限属于高保护权限时直接跳过
  - 包括：`signature`
  - 包括：`system`
  - 包括：`signatureOrSystem`
- 只要混入一个自定义 action，就不会因为系统 action 而跳过，仍然继续检查权限

最终主结果文件只保留危险广播，不混入中间状态字段。

## 2. 运行前准备

目标机器需要：

- 安装 Java 运行环境
- 不需要安装 Kotlin

需要准备 3 类输入：

### 2.1 jar-dir

待扫描的 jar 目录。

例如：

```text
/path/to/framework-jars
```

目录下应包含一个或多个 `.jar` 文件。

说明：

- 当前版本会递归搜索子目录中的 `.jar`
- 默认会扫描 jar 中的所有类
- 如果传 `--package-prefix`，则只扫描匹配该前缀的类

### 2.2 proaction.xml

保护广播定义文件。

格式示例：

```xml
<protected-broadcast android:name="android.intent.action.ACTION_SET_GLOBAL_AUTO_PARAM_DONE" />
```

### 2.3 permission.txt

权限定义文件。

格式示例：

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

说明：

- 当前解析器只依赖两类关键行：
  - `+ permission:...`
  - `protectionLevel:...`
- 像 `package:`、`label:`、`description:` 这类中间行会被忽略，但**完全允许存在**
- 所以你提供的完整 `pm permissions -f` 风格文本可以直接使用，不需要手工删字段

## 3. 命令行用法

标准命令：

```bash
java -jar framework-broadcast-scanner-all.jar \
  --jar-dir /path/to/jars \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out
```

参数说明：

- `--jar-dir`
  - 必填
  - 待扫描的 jar 目录
- `--protected-broadcasts`
  - 必填
  - 保护广播 XML 文件路径
- `--permissions`
  - 必填
  - 权限定义文件路径
- `--out-dir`
  - 可选
  - 输出目录
  - 不传时默认使用当前目录下的 `out`
- `--package-prefix`
  - 可选
  - 只扫描类名以这个前缀开头的类
  - 例如：`--package-prefix com.huawei`
- `--scan-all-receivers`
  - 可选
  - 兼容旧参数
  - 当前默认已经是扫描全部 receiver，通常不需要再传

如果只想扫描 `com.huawei.*`，可这样运行：

```bash
java -jar framework-broadcast-scanner-all.jar \
  --jar-dir /path/to/jars \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out \
  --package-prefix com.huawei
```

如果只想查看帮助：

```bash
java -jar framework-broadcast-scanner-all.jar --help
```

运行过程中会显示 jar 级进度：

```text
[####--------] 37/213 success=30 partial=4 failed=3 dangerous=12 current=services.jar
```

如果输出被重定向到文件，则会改为逐 jar 的文本进度日志，避免控制台覆盖符污染日志。

## 4. 输出文件说明

运行完成后，`out-dir` 下会生成以下文件：

### 4.1 dangerous_dynamic_broadcasts.jsonl

主结果文件。

只包含**危险广播列表**。

每行一条 JSON 记录。

### 4.2 dangerous_dynamic_broadcasts.md

危险广播列表的 Markdown 版本，便于人工查看。

### 4.3 scan_summary.json

扫描统计摘要。

包含：

- 总 jar 数
- 完整成功 jar 数
- 部分失败 jar 数
- 完全失败 jar 数
- 危险广播总数
- 完整成功率
- 处理率

### 4.4 partial_jars.jsonl

部分失败 jar 列表。

这类 jar 在扫描中途失败，但失败前已经找到的危险广播仍会保留在主结果文件里。

### 4.5 failed_jars.jsonl

完全失败 jar 列表。

这类 jar 没有产出任何危险广播结果。

### 4.6 scan_errors.log

错误摘要日志。

用于查看 `partial` 和 `failed` jar 的错误信息。

## 5. 危险广播结果字段说明

`dangerous_dynamic_broadcasts.jsonl` 中每条记录只包含以下 8 个字段：

### 5.1 jar_path

命中危险广播的 jar 路径。

### 5.2 declaring_class

动态广播注册点所在类名。

### 5.3 declaring_method

动态广播注册点所在方法签名。

### 5.4 source_line

注册语句对应的源码行号。

如果无法恢复，则为 `null`。

### 5.5 action_list

恢复出的动态广播 action 列表。

如果 action 无法恢复，则输出空数组。

### 5.6 broadcast_permission

动态广播注册时传入的权限字符串。

如果没有传权限，则为 `null`。

### 5.7 permission_protection_level

从 `permission.txt` 中解析到的权限保护级别。

例如：

- `normal`
- `dangerous`
- `signature|role`

如果没有传权限，或者权限在 `permission.txt` 中查不到，则为 `null`。

### 5.8 evidence

注册语句对应的 Soot/Jimple 证据字符串。

用于人工快速复核。

## 6. 统计口径说明

`scan_summary.json` 中的字段含义如下：

### 6.1 total_jars

总共扫描的 jar 数。

### 6.2 success_jars

完整扫描成功的 jar 数。

### 6.3 partial_jars

扫描中途失败，但失败前已经产出危险广播的 jar 数。

注意：

- `partial` jar 的危险广播**会保留在主结果文件中**

### 6.4 failed_jars

完全失败、没有产出任何危险广播结果的 jar 数。

注意：

- `failed` jar **不会贡献危险记录**

### 6.5 dangerous_broadcasts

最终输出的危险广播总数。

也就是 `dangerous_dynamic_broadcasts.jsonl` 中的记录条数。

### 6.6 full_success_rate

完整成功率：

```text
success_jars / total_jars
```

### 6.7 processed_rate

处理率：

```text
(success_jars + partial_jars) / total_jars
```

## 7. 终端摘要

扫描结束后，终端会输出一行最终摘要：

```text
scan completed: total_jars=213, success_jars=190, partial_jars=15, failed_jars=8, dangerous_broadcasts=41
```

其中：

- `dangerous_broadcasts` 就是最终危险广播列表总条数
- `partial` jar 已发现的危险广播会保留在主结果文件里

## 7. 已验证真实样例

当前已经验证过一组真实样例，路径如下：

- `proaction.xml`
  - `/tmp/fbscan-real/proaction.xml`
- `permission.txt`
  - `/tmp/fbscan-real/permission.txt`
- `sample.jar`
  - `/tmp/fbscan-real/jars/sample.jar`

对应输出目录：

- `/tmp/fbscan-real/out`

示例运行命令：

```bash
java -jar /tmp/framework-broadcast-scanner/build/libs/framework-broadcast-scanner-all.jar \
  --jar-dir /tmp/fbscan-real/jars \
  --protected-broadcasts /tmp/fbscan-real/proaction.xml \
  --permissions /tmp/fbscan-real/permission.txt \
  --out-dir /tmp/fbscan-real/out
```

示例终端输出摘要：

```text
scan completed: total_jars=1, success_jars=1, partial_jars=0, failed_jars=0, dangerous_broadcasts=2
```

示例 `scan_summary.json`：

```json
{"total_jars":1,"success_jars":1,"partial_jars":0,"failed_jars":0,"dangerous_broadcasts":2,"full_success_rate":1.0000,"processed_rate":1.0000}
```

## 8. 迁移到其他机器使用

如果要迁移到其他机器，至少拷贝：

- `framework-broadcast-scanner-all.jar`

目标机器只要具备 Java 运行环境，就可以直接执行：

```bash
java -jar framework-broadcast-scanner-all.jar \
  --jar-dir /path/to/jars \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out
```

不需要安装 Kotlin，也不需要依赖 `appshark` 工程源码。
