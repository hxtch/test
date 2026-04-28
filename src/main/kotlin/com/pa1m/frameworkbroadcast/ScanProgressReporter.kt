package com.pa1m.frameworkbroadcast

import java.io.PrintStream
import java.nio.file.Path

open class ScanProgressReporter(
    private val out: PrintStream = System.out,
    private val interactive: Boolean = System.console() != null,
) {
    private var successCount = 0
    private var partialCount = 0
    private var failedCount = 0
    private var lastRenderedLength = 0

    open fun onScanStarted(totalJars: Int) {
        if (!interactive) {
            out.println("scan started: total_jars=$totalJars")
        }
    }

    open fun onJarFinished(
        currentIndex: Int,
        totalJars: Int,
        jarResult: JarScanResult,
        dangerousTotal: Int,
    ) {
        when (jarResult.status) {
            JarScanStatus.SUCCESS -> successCount += 1
            JarScanStatus.PARTIAL -> partialCount += 1
            JarScanStatus.FAILED -> failedCount += 1
        }

        val currentJarName = runCatching { Path.of(jarResult.jarPath).fileName?.toString() ?: jarResult.jarPath }
            .getOrDefault(jarResult.jarPath)
        val status = jarResult.status.name.lowercase()

        if (interactive) {
            val line = buildInteractiveLine(
                currentIndex = currentIndex,
                totalJars = totalJars,
                currentJarName = currentJarName,
                dangerousTotal = dangerousTotal,
            )
            val padding = " ".repeat((lastRenderedLength - line.length).coerceAtLeast(0))
            out.print("\r$line$padding")
            out.flush()
            lastRenderedLength = line.length
        } else {
            out.println(
                "progress: $currentIndex/$totalJars success=$successCount partial=$partialCount failed=$failedCount dangerous=$dangerousTotal status=$status current=$currentJarName"
            )
        }
    }

    open fun onScanCompleted() {
        if (interactive && lastRenderedLength > 0) {
            out.println()
            out.flush()
        }
    }

    private fun buildInteractiveLine(
        currentIndex: Int,
        totalJars: Int,
        currentJarName: String,
        dangerousTotal: Int,
    ): String {
        val width = 20
        val filled = if (totalJars <= 0) 0 else (currentIndex * width) / totalJars
        val bar = buildString {
            append("[")
            append("#".repeat(filled.coerceIn(0, width)))
            append("-".repeat((width - filled).coerceAtLeast(0)))
            append("]")
        }
        return "$bar $currentIndex/$totalJars success=$successCount partial=$partialCount failed=$failedCount dangerous=$dangerousTotal current=$currentJarName"
    }
}
