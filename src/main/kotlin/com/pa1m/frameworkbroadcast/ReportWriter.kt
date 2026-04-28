package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

object ReportWriter {
    fun write(outDir: Path, scanResult: ScanResult, writeAllRecords: Boolean = false) {
        Files.createDirectories(outDir)
        val dangerousJsonlPath = outDir.resolve("dangerous_dynamic_broadcasts.jsonl")
        val dangerousMarkdownPath = outDir.resolve("dangerous_dynamic_broadcasts.md")
        val allJsonlPath = outDir.resolve("all_dynamic_broadcasts.jsonl")
        val allMarkdownPath = outDir.resolve("all_dynamic_broadcasts.md")
        val summaryPath = outDir.resolve("scan_summary.json")
        val partialPath = outDir.resolve("partial_jars.jsonl")
        val failedPath = outDir.resolve("failed_jars.jsonl")
        val errorLogPath = outDir.resolve("scan_errors.log")

        Files.writeString(
            dangerousJsonlPath,
            scanResult.dangerousRecords.joinToString("\n") { it.toJsonLine() }.let { if (it.isEmpty()) "" else "$it\n" }
        )
        Files.writeString(
            dangerousMarkdownPath,
            buildMarkdown(
                title = "Dangerous Dynamic Broadcasts",
                countLabel = "Total dangerous broadcasts",
                records = scanResult.dangerousRecords.map { it.toAllRecord() },
            )
        )

        if (writeAllRecords) {
            Files.writeString(
                allJsonlPath,
                scanResult.allRecords.joinToString("\n") { it.toJsonLine() }.let { if (it.isEmpty()) "" else "$it\n" }
            )
            Files.writeString(
                allMarkdownPath,
                buildMarkdown(
                    title = "All Dynamic Broadcasts",
                    countLabel = "Total dynamic broadcasts",
                    records = scanResult.allRecords,
                )
            )
        } else {
            Files.deleteIfExists(allJsonlPath)
            Files.deleteIfExists(allMarkdownPath)
        }

        Files.writeString(summaryPath, buildSummary(scanResult).toJson())
        Files.writeString(
            partialPath,
            scanResult.jarResults
                .filter { it.status == JarScanStatus.PARTIAL }
                .joinToString("\n") { it.toJarStatusJsonLine() }
                .let { if (it.isEmpty()) "" else "$it\n" }
        )
        Files.writeString(
            failedPath,
            scanResult.jarResults
                .filter { it.status == JarScanStatus.FAILED }
                .joinToString("\n") { it.toJarStatusJsonLine() }
                .let { if (it.isEmpty()) "" else "$it\n" }
        )
        Files.writeString(
            errorLogPath,
            scanResult.jarResults
                .filter { it.status != JarScanStatus.SUCCESS }
                .joinToString("\n\n") { jarResult ->
                    buildString {
                        append("jar_path: ")
                        append(jarResult.jarPath)
                        append("\nstatus: ")
                        append(jarResult.status.name.lowercase())
                        append("\ndangerous_count: ")
                        append(jarResult.dangerousCount)
                        append("\nall_count: ")
                        append(jarResult.allCount)
                        append("\nerror_type: ")
                        append(jarResult.errorType ?: "<null>")
                        append("\nerror_message: ")
                        append(jarResult.errorMessage ?: "<null>")
                    }
                }
                .let { if (it.isEmpty()) "" else "$it\n" }
        )
    }

    private fun buildSummary(scanResult: ScanResult): ScanSummary {
        val jarResults = scanResult.jarResults
        val totalJars = jarResults.size
        val successJars = jarResults.count { it.status == JarScanStatus.SUCCESS }
        val partialJars = jarResults.count { it.status == JarScanStatus.PARTIAL }
        val failedJars = jarResults.count { it.status == JarScanStatus.FAILED }
        val dangerousBroadcasts = scanResult.dangerousRecords.size
        val allDynamicBroadcasts = scanResult.allRecords.size
        val fullSuccessRate = if (totalJars == 0) 0.0 else successJars.toDouble() / totalJars.toDouble()
        val processedRate = if (totalJars == 0) 0.0 else (successJars + partialJars).toDouble() / totalJars.toDouble()
        return ScanSummary(
            totalJars = totalJars,
            successJars = successJars,
            partialJars = partialJars,
            failedJars = failedJars,
            dangerousBroadcasts = dangerousBroadcasts,
            allDynamicBroadcasts = allDynamicBroadcasts,
            fullSuccessRate = fullSuccessRate,
            processedRate = processedRate,
        )
    }

    private fun buildMarkdown(
        title: String,
        countLabel: String,
        records: List<AllDynamicBroadcastRecord>,
    ): String {
        return buildString {
            appendLine("# $title")
            appendLine()
            appendLine("$countLabel: ${records.size}")
            appendLine()
            for ((index, item) in records.withIndex()) {
                appendLine("## ${index + 1}. ${item.declaringClass}")
                appendLine()
                appendLine("- jar_path: `${item.jarPath}`")
                appendLine("- declaring_method: `${item.declaringMethod}`")
                appendLine("- source_line: `${item.sourceLine ?: -1}`")
                appendLine("- action_list: `${item.actionList.joinToString(", ").ifEmpty { "<empty>" }}`")
                appendLine("- broadcast_permission: `${item.broadcastPermission ?: "<null>"}`")
                appendLine("- permission_protection_level: `${item.permissionProtectionLevel ?: "<null>"}`")
                appendLine("- evidence: `${item.evidence}`")
                appendLine()
            }
        }
    }

    private fun DangerousBroadcastRecord.toAllRecord(): AllDynamicBroadcastRecord {
        return AllDynamicBroadcastRecord(
            jarPath = jarPath,
            declaringClass = declaringClass,
            declaringMethod = declaringMethod,
            sourceLine = sourceLine,
            actionList = actionList,
            broadcastPermission = broadcastPermission,
            permissionProtectionLevel = permissionProtectionLevel,
            evidence = evidence,
        )
    }

    private fun DangerousBroadcastRecord.toJsonLine(): String = toAllRecord().toJsonLine()

    private fun AllDynamicBroadcastRecord.toJsonLine(): String {
        return buildString {
            append("{")
            appendJsonField("jar_path", jarPath)
            append(",")
            appendJsonField("declaring_class", declaringClass)
            append(",")
            appendJsonField("declaring_method", declaringMethod)
            append(",")
            append("\"source_line\":")
            append(sourceLine?.toString() ?: "null")
            append(",")
            append("\"action_list\":[")
            append(actionList.joinToString(",") { "\"${escapeJson(it)}\"" })
            append("],")
            appendJsonField("broadcast_permission", broadcastPermission)
            append(",")
            appendJsonField("permission_protection_level", permissionProtectionLevel)
            append(",")
            appendJsonField("evidence", evidence)
            append("}")
        }
    }

    private fun ScanSummary.toJson(): String {
        return buildString {
            append("{")
            append("\"total_jars\":")
            append(totalJars)
            append(",\"success_jars\":")
            append(successJars)
            append(",\"partial_jars\":")
            append(partialJars)
            append(",\"failed_jars\":")
            append(failedJars)
            append(",\"dangerous_broadcasts\":")
            append(dangerousBroadcasts)
            append(",\"all_dynamic_broadcasts\":")
            append(allDynamicBroadcasts)
            append(",\"full_success_rate\":")
            append(formatRate(fullSuccessRate))
            append(",\"processed_rate\":")
            append(formatRate(processedRate))
            append("}\n")
        }
    }

    private fun JarScanResult.toJarStatusJsonLine(): String {
        return buildString {
            append("{")
            appendJsonField("jar_path", jarPath)
            append(",")
            appendJsonField("status", status.name.lowercase())
            append(",")
            append("\"dangerous_count\":")
            append(dangerousCount)
            append(",")
            append("\"all_count\":")
            append(allCount)
            append(",")
            appendJsonField("error_type", errorType)
            append(",")
            appendJsonField("error_message", errorMessage)
            append("}")
        }
    }

    private fun StringBuilder.appendJsonField(name: String, value: String?) {
        append("\"")
        append(name)
        append("\":")
        if (value == null) {
            append("null")
        } else {
            append("\"")
            append(escapeJson(value))
            append("\"")
        }
    }

    private fun escapeJson(value: String): String {
        return buildString {
            value.forEach { ch ->
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }
    }

    private fun formatRate(value: Double): String = String.format(java.util.Locale.US, "%.4f", value)
}
