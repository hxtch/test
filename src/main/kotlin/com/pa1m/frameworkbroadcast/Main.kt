package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val config = parseArgs(args)
    if (config.workerArtifact != null) {
        runWorkerMode(config)
        return
    }

    val scanResult = if (config.jobs > 1) {
        ParallelScanCoordinator.scan(config)
    } else {
        val protectedBroadcasts = ProtectedBroadcastParser.parse(Path.of(config.protectedBroadcasts))
        val permissions = PermissionDefinitionsParser.parse(Path.of(config.permissions))
        val scanner = FrameworkJarBroadcastScanner(
            scanAllReceivers = config.scanAllReceivers,
            packagePrefix = config.packagePrefix,
        )
        scanner.scan(
            inputPath = Path.of(config.inputPath),
            inputType = config.inputType,
            protectedBroadcasts = protectedBroadcasts,
            permissions = permissions,
            androidPlatforms = config.androidPlatforms?.let(Path::of),
        )
    }

    ReportWriter.write(Path.of(config.outDir), scanResult, writeAllRecords = config.scanAllReceivers)
    println(buildSummaryLine(scanResult, config.scanAllReceivers))
}

internal fun parseArgs(args: Array<String>): ScanCliConfig {
    if (args.isEmpty() || "--help" in args || "-h" in args) {
        printUsage()
        kotlin.system.exitProcess(0)
    }
    val map = mutableMapOf<String, String>()
    val flags = mutableSetOf<String>()
    var index = 0
    while (index < args.size) {
        val key = args[index]
        require(key.startsWith("--") || key == "-j") { "非法参数: $key" }
        if (key == "--scan-all-receivers") {
            val next = args.getOrNull(index + 1)
            if (next == null || next.startsWith("-")) {
                flags += key
                index += 1
            } else {
                map[key] = next
                index += 2
            }
            continue
        }
        require(index + 1 < args.size) { "参数缺少值: $key" }
        map[key] = args[index + 1]
        index += 2
    }

    val inputPath = map["--input-path"] ?: map["--jar-dir"] ?: map["--worker-artifact"] ?: error("缺少参数: --input-path")
    val config = ScanCliConfig(
        inputPath = inputPath,
        inputType = InputTypeMode.fromCli(map["--input-type"] ?: "auto"),
        protectedBroadcasts = map["--protected-broadcasts"] ?: error("缺少参数: --protected-broadcasts"),
        permissions = map["--permissions"] ?: error("缺少参数: --permissions"),
        outDir = map["--out-dir"] ?: "out",
        scanAllReceivers = parseBooleanOption(
            rawValue = map["--scan-all-receivers"],
            optionName = "--scan-all-receivers",
            presentWithoutValue = flags.contains("--scan-all-receivers"),
            defaultValue = false,
        ),
        packagePrefix = map["--package-prefix"]?.takeIf { it.isNotBlank() },
        androidPlatforms = map["--android-platforms"]?.takeIf { it.isNotBlank() },
        jobs = map["-j"]?.toIntOrNull()?.also { require(it > 0) { "-j 必须大于 0" } } ?: 1,
        workerArtifact = map["--worker-artifact"],
        workerArtifactType = map["--worker-artifact-type"]?.let(ArtifactType::fromCli),
        workerResultFile = map["--worker-result-file"],
    )

    require(Files.exists(Path.of(config.inputPath))) { "输入路径不存在: ${config.inputPath}" }
    require(Files.isRegularFile(Path.of(config.protectedBroadcasts))) { "保护广播文件不存在: ${config.protectedBroadcasts}" }
    require(Files.isRegularFile(Path.of(config.permissions))) { "权限定义文件不存在: ${config.permissions}" }
    config.androidPlatforms?.let {
        require(Files.exists(Path.of(it))) { "Android 平台路径不存在: $it" }
    }
    if (config.workerArtifact != null) {
        require(config.workerArtifactType != null) { "worker 模式缺少 --worker-artifact-type" }
        require(!config.workerResultFile.isNullOrBlank()) { "worker 模式缺少 --worker-result-file" }
    }
    return config
}

private fun runWorkerMode(config: ScanCliConfig) {
    val protectedBroadcasts = ProtectedBroadcastParser.parse(Path.of(config.protectedBroadcasts))
    val permissions = PermissionDefinitionsParser.parse(Path.of(config.permissions))
    val scanner = FrameworkJarBroadcastScanner(
        progressReporter = object : ScanProgressReporter() {
            override fun onScanStarted(totalJars: Int) = Unit
            override fun onJarFinished(currentIndex: Int, totalJars: Int, jarResult: JarScanResult, dangerousTotal: Int) = Unit
            override fun onScanCompleted() = Unit
        },
        scanAllReceivers = config.scanAllReceivers,
        packagePrefix = config.packagePrefix,
    )
    val result = scanner.scanSingleArtifact(
        artifact = ScanArtifact(config.workerArtifact!!, config.workerArtifactType!!),
        protectedBroadcasts = protectedBroadcasts,
        permissions = permissions,
        androidPlatforms = config.androidPlatforms?.let(Path::of),
    )
    WorkerProtocol.writeResult(Path.of(config.workerResultFile!!), result)
}

private fun buildSummaryLine(scanResult: ScanResult, writeAllRecords: Boolean): String {
    val totalJars = scanResult.jarResults.size
    val successJars = scanResult.jarResults.count { it.status == JarScanStatus.SUCCESS }
    val partialJars = scanResult.jarResults.count { it.status == JarScanStatus.PARTIAL }
    val failedJars = scanResult.jarResults.count { it.status == JarScanStatus.FAILED }
    return buildString {
        append("scan completed: total_jars=$totalJars, success_jars=$successJars, partial_jars=$partialJars, failed_jars=$failedJars, dangerous_broadcasts=${scanResult.dangerousRecords.size}")
        if (writeAllRecords) {
            append(", all_dynamic_broadcasts=${scanResult.allRecords.size}")
        }
    }
}

private fun parseBooleanOption(rawValue: String?, optionName: String, presentWithoutValue: Boolean, defaultValue: Boolean): Boolean {
    if (presentWithoutValue) {
        return true
    }
    if (rawValue == null) {
        return defaultValue
    }
    return when (rawValue.lowercase()) {
        "true", "1", "yes", "y", "on" -> true
        "false", "0", "no", "n", "off" -> false
        else -> error("布尔参数取值非法: $optionName=$rawValue")
    }
}

private fun printUsage() {
    println(
        """
        Usage:
          java -jar framework-broadcast-scanner-all.jar --input-path <path> [--input-type <auto|class-jar|dex-jar|apk>] --protected-broadcasts <file> --permissions <file> [--android-platforms <path>] [--out-dir <dir>] [--package-prefix <prefix>] [--scan-all-receivers] [-j <n>]
        """.trimIndent()
    )
}
