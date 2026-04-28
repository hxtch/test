package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    val config = parseArgs(args)
    val protectedBroadcasts = ProtectedBroadcastParser.parse(Path.of(config.protectedBroadcasts))
    val permissions = PermissionDefinitionsParser.parse(Path.of(config.permissions))
    val scanner = FrameworkJarBroadcastScanner()
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

private fun parseArgs(args: Array<String>): ScanCliConfig {
    if (args.isEmpty() || "--help" in args || "-h" in args) {
        printUsage()
        kotlin.system.exitProcess(0)
    }
    val map = mutableMapOf<String, String>()
    var index = 0
    while (index < args.size) {
        val key = args[index]
        require(key.startsWith("--")) { "非法参数: $key" }
        require(index + 1 < args.size) { "参数缺少值: $key" }
        map[key] = args[index + 1]
        index += 2
    }
    val config = ScanCliConfig(
        jarDir = map["--jar-dir"] ?: error("缺少参数: --jar-dir"),
        protectedBroadcasts = map["--protected-broadcasts"] ?: error("缺少参数: --protected-broadcasts"),
        permissions = map["--permissions"] ?: error("缺少参数: --permissions"),
        outDir = map["--out-dir"] ?: "out",
    )
    require(Files.isDirectory(Path.of(config.jarDir))) { "jar 目录不存在: ${config.jarDir}" }
    require(Files.isRegularFile(Path.of(config.protectedBroadcasts))) { "保护广播文件不存在: ${config.protectedBroadcasts}" }
    require(Files.isRegularFile(Path.of(config.permissions))) { "权限定义文件不存在: ${config.permissions}" }
    return config
}

private fun printUsage() {
    println(
        """
        Usage:
          java -jar framework-broadcast-scanner-all.jar --jar-dir <dir> --protected-broadcasts <file> --permissions <file> [--out-dir <dir>]
        """.trimIndent()
    )
}
