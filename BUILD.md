# Framework Broadcast Scanner 编译文档

## 1. 代码逻辑是否已经上传

已经上传。

当前仓库里不仅有可直接运行的成品包：

- `framework-broadcast-scanner-all.jar`

还包含完整的源码工程：

- `framework-broadcast-scanner/`

核心代码位置：

- `framework-broadcast-scanner/src/main/kotlin/com/pa1m/frameworkbroadcast/`

其中主要文件包括：

- `Main.kt`
  - 命令行参数解析和程序入口
- `FrameworkJarBroadcastScanner.kt`
  - jar 遍历、Soot 初始化、动态广播扫描主逻辑
- `MethodLocalResolver.kt`
  - 方法内局部回溯，恢复 `IntentFilter` / permission / flags
- `ReportWriter.kt`
  - 危险广播结果和统计文件输出
- `ScanProgressReporter.kt`
  - 扫描进度条输出

## 2. 目标机器需要什么环境

目标机器需要：

- Git
- Java 11

不需要单独安装 Kotlin。

原因：

- 这个工程自带 `Gradle Wrapper`
- Kotlin 编译器会由 Gradle 自动拉取

建议优先使用 Java 11。

## 3. 拉代码

在其他电脑上可以直接 clone 这个仓库：

```bash
git clone https://github.com/hxtch/test.git
cd test/framework-broadcast-scanner
```

如果你要拿我当前这条分支上的最新扫描器代码，可以切到：

```bash
git checkout codex/scan-all-receivers
```

## 4. 修改代码

源码目录：

```text
framework-broadcast-scanner/src/main/kotlin/com/pa1m/frameworkbroadcast/
```

测试代码目录：

```text
framework-broadcast-scanner/src/test/kotlin/com/pa1m/frameworkbroadcast/
```

常见修改点：

- 想改命令行参数：看 `Main.kt`
- 想改扫描范围过滤：看 `FrameworkJarBroadcastScanner.kt`
- 想改 action / permission / flags 恢复：看 `MethodLocalResolver.kt`
- 想改输出字段：看 `ReportWriter.kt`

## 5. 编译前建议

先确认 Java 版本：

```bash
java -version
javac -version
```

如果机器上有多个 JDK，建议显式指定 `JAVA_HOME` 为 JDK 11。

macOS 示例：

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 11)
export PATH="$JAVA_HOME/bin:$PATH"
```

Linux 示例：

```bash
export JAVA_HOME=/path/to/jdk-11
export PATH="$JAVA_HOME/bin:$PATH"
```

## 6. 跑测试

进入源码工程目录：

```bash
cd framework-broadcast-scanner
```

运行测试：

```bash
./gradlew test
```

测试通过后再打包。

## 7. 打包 fat jar

执行：

```bash
./gradlew fatJar
```

打包完成后，产物在：

```text
framework-broadcast-scanner/build/libs/framework-broadcast-scanner-all.jar
```

这个 jar 是 fat jar，目标机器只需要 Java 就能直接运行。

## 8. 运行方式

默认扫描全部类中的动态广播：

```bash
java -jar build/libs/framework-broadcast-scanner-all.jar \
  --jar-dir /path/to/jars \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out
```

如果你只想筛选某个包前缀，比如 `com.huawei`：

```bash
java -jar build/libs/framework-broadcast-scanner-all.jar \
  --jar-dir /path/to/jars \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out \
  --package-prefix com.huawei
```

## 9. 常用命令汇总

查看帮助：

```bash
./gradlew --version
java -jar build/libs/framework-broadcast-scanner-all.jar --help
```

运行测试：

```bash
./gradlew test
```

重新打包：

```bash
./gradlew fatJar
```

## 10. 结果说明

主结果文件：

- `dangerous_dynamic_broadcasts.jsonl`
- `dangerous_dynamic_broadcasts.md`

统计和错误文件：

- `scan_summary.json`
- `partial_jars.jsonl`
- `failed_jars.jsonl`
- `scan_errors.log`

## 11. 备注

如果你改完代码后只想把新 jar 拷出来，可以直接拿：

```text
framework-broadcast-scanner/build/libs/framework-broadcast-scanner-all.jar
```

如果后续你希望我再补一份：

- Windows 编译说明
- JDK 安装说明
- GitHub Actions 自动构建脚本

我可以继续补上。
