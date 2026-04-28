package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val config = parseArgs(args)
    val protectedBroadcasts = ProtectedBroadcastParser.parse(Path.of(config.protectedBroadcasts))
    val permissions = PermissionDefinitionsParser.parse(Path.of(config.permissions))
    val scanner = FrameworkJarBroadcastScanner(
        scanAllReceivers = config.scanAllReceivers,
        packagePrefix = config.packagePrefix,
    )
    val scanResult = scanner.scan(Path.of(config.jarDir), protectedBroadcasts, permissions)
    ReportWriter.write(Path.of(config.outDir), scanResult)
    val totalJars = scanResult.jarResults.size
    val successJars = scanResult.jarResults.count { it.status == JarScanStatus.SUCCESS }
    val partialJars = scanResult.jarResults.count { it.status == JarScanStatus.PARTIAL }
    val failedJars = scanResult.jarResults.count { it.status == JarScanStatus.FAILED }
    println(
        "scan completed: total_jars=$totalJars, success_jars=$successJars, partial_jars=$partialJars, failed_jars=$failedJars, dangerous_broadcasts=${scanResult.dangerousRecords.size}"
    )
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
        require(key.startsWith("--")) { "非法参数: $key" }
        if (key == "--scan-all-receivers") {
            val next = args.getOrNull(index + 1)
            if (next == null || next.startsWith("--")) {
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
    val config = ScanCliConfig(
        jarDir = map["--jar-dir"] ?: error("缺少参数: --jar-dir"),
        protectedBroadcasts = map["--protected-broadcasts"] ?: error("缺少参数: --protected-broadcasts"),
        permissions = map["--permissions"] ?: error("缺少参数: --permissions"),
        outDir = map["--out-dir"] ?: "out",
        scanAllReceivers = parseBooleanOption(
            rawValue = map["--scan-all-receivers"],
            optionName = "--scan-all-receivers",
            presentWithoutValue = flags.contains("--scan-all-receivers"),
            defaultValue = true,
        ),
        packagePrefix = map["--package-prefix"]?.takeIf { it.isNotBlank() },
    )
    require(Files.isDirectory(Path.of(config.jarDir))) { "jar 目录不存在: ${config.jarDir}" }
    require(Files.isRegularFile(Path.of(config.protectedBroadcasts))) { "保护广播文件不存在: ${config.protectedBroadcasts}" }
    require(Files.isRegularFile(Path.of(config.permissions))) { "权限定义文件不存在: ${config.permissions}" }
    return config
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
          java -jar framework-broadcast-scanner-all.jar --jar-dir <dir> --protected-broadcasts <file> --permissions <file> [--out-dir <dir>] [--package-prefix <prefix>] [--scan-all-receivers]
        """.trimIndent()
    )
}
