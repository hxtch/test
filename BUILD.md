# Framework Broadcast Scanner 编译说明

## 1. 环境要求

- 推荐 `JDK 11`
- 需要能运行 Gradle Wrapper
- 不需要单独安装 Kotlin

如果你要扫描 `dex-jar` 或 `apk`，运行时还需要 Android 平台目录或 `android.jar`：

- 例如 Android SDK 的 `platforms` 目录

## 2. 编译步骤

在工程根目录执行：

```bash
export JAVA_HOME=/path/to/jdk11
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew test fatJar
```

说明：

- `test`
  - 先跑单元测试
- `fatJar`
  - 生成可直接迁移运行的 fat jar

## 3. 产物位置

fat jar 固定在：

```text
build/libs/framework-broadcast-scanner-all.jar
```

迁移到其他机器后，只要那台机器有 Java 运行环境，就可以直接运行：

```bash
java -jar framework-broadcast-scanner-all.jar --help
```

## 4. 常用命令

### 4.1 只扫普通 class jar

```bash
java -jar build/libs/framework-broadcast-scanner-all.jar \
  --input-path /path/to/jars \
  --input-type class-jar \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --out-dir /path/to/out
```

### 4.2 扫 dex-jar / APK

```bash
java -jar build/libs/framework-broadcast-scanner-all.jar \
  --input-path /path/to/targets \
  --input-type auto \
  --protected-broadcasts /path/to/proaction.xml \
  --permissions /path/to/permission.txt \
  --android-platforms /path/to/platforms \
  --out-dir /path/to/out \
  --scan-all-receivers \
  -j 2
```

## 5. 当前实现说明

- `--input-path`
  - 支持目录、单个 jar、单个 zip、单个 apk

- `--input-type`
  - 支持 `auto` / `class-jar` / `dex-jar` / `apk`

- `-j`
  - 按输入文件级并发
  - 当前用“父进程调度 + 子进程单文件扫描”实现，避免 Soot 全局状态冲突

- `--scan-all-receivers`
  - 在危险结果之外额外生成全量动态广播结果

## 6. 本地验证

当前版本已完成：

- `./gradlew test`
- `./gradlew fatJar`
- 真实 `sample-dex.jar` 验证
- 真实 `sample.apk` 验证
- `-j 2` 并发验证

真实验证使用的平台目录：

```text
/Users/pa1m/workspace/appshark/config/tools/platforms
```

## 7. 常见问题

### 7.1 `Unsupported class file major version 65`

优先确认：

- 是否使用了 `JDK 11`
- 输入 class 是否由过高版本 JDK 编译

### 7.2 `--android-platforms` 该传什么

两种都可以：

- Android SDK `platforms` 目录
- 单个 `android.jar`

### 7.3 为什么打包后不需要安装 Kotlin

因为 `fatJar` 已经把运行时依赖一起打进产物里了，目标机器只需要 Java。
