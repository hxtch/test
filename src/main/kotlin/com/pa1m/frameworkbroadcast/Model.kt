package com.pa1m.frameworkbroadcast

import java.io.Serializable

enum class ResolutionStatus {
    KNOWN,
    NULL_VALUE,
    UNKNOWN,
}

data class PermissionMeta(
    val permissionName: String,
    val protectionLevelRaw: String,
    val protectionLevelTokens: Set<String>,
    val highProtection: Boolean,
) : Serializable

data class BroadcastScanFact(
    val jarPath: String,
    val declaringClass: String,
    val declaringMethod: String,
    val intentFilterActions: Set<String>,
    val broadcastPermission: String?,
    val flagsValue: Int?,
    val isNotExported: Boolean,
    val sourceLine: Int?,
    val evidence: String,
) : Serializable

data class DangerousBroadcastRecord(
    val jarPath: String,
    val declaringClass: String,
    val declaringMethod: String,
    val sourceLine: Int?,
    val actionList: List<String>,
    val broadcastPermission: String?,
    val permissionProtectionLevel: String?,
    val evidence: String,
) : Serializable

data class AllDynamicBroadcastRecord(
    val jarPath: String,
    val declaringClass: String,
    val declaringMethod: String,
    val sourceLine: Int?,
    val actionList: List<String>,
    val broadcastPermission: String?,
    val permissionProtectionLevel: String?,
    val evidence: String,
) : Serializable

enum class JarScanStatus {
    SUCCESS,
    PARTIAL,
    FAILED,
}

enum class ArtifactType(val cliValue: String) {
    CLASS_JAR("class-jar"),
    DEX_JAR("dex-jar"),
    APK("apk");

    companion object {
        fun fromCli(value: String): ArtifactType {
            return values().firstOrNull { it.cliValue == value }
                ?: error("不支持的输入类型: $value")
        }
    }
}

enum class InputTypeMode(val cliValue: String) {
    AUTO("auto"),
    CLASS_JAR("class-jar"),
    DEX_JAR("dex-jar"),
    APK("apk");

    companion object {
        fun fromCli(value: String): InputTypeMode {
            return values().firstOrNull { it.cliValue == value }
                ?: error("不支持的输入类型: $value")
        }
    }
}

data class ScanArtifact(
    val path: String,
    val artifactType: ArtifactType,
) : Serializable

data class JarScanResult(
    val jarPath: String,
    val status: JarScanStatus,
    val dangerousRecords: List<DangerousBroadcastRecord>,
    val allRecords: List<AllDynamicBroadcastRecord> = emptyList(),
    val errorType: String? = null,
    val errorMessage: String? = null,
    val artifactType: ArtifactType = ArtifactType.CLASS_JAR,
) : Serializable {
    val dangerousCount: Int
        get() = dangerousRecords.size

    val allCount: Int
        get() = allRecords.size
}

data class ScanResult(
    val dangerousRecords: List<DangerousBroadcastRecord>,
    val allRecords: List<AllDynamicBroadcastRecord>,
    val jarResults: List<JarScanResult>,
) : Serializable

data class ScanSummary(
    val totalJars: Int,
    val successJars: Int,
    val partialJars: Int,
    val failedJars: Int,
    val dangerousBroadcasts: Int,
    val allDynamicBroadcasts: Int,
    val fullSuccessRate: Double,
    val processedRate: Double,
) : Serializable

data class ScanCliConfig(
    val inputPath: String,
    val inputType: InputTypeMode,
    val protectedBroadcasts: String,
    val permissions: String,
    val outDir: String,
    val scanAllReceivers: Boolean,
    val packagePrefix: String?,
    val androidPlatforms: String?,
    val jobs: Int,
    val workerArtifact: String? = null,
    val workerArtifactType: ArtifactType? = null,
    val workerResultFile: String? = null,
) : Serializable

data class StringResolution(
    val status: ResolutionStatus,
    val value: String?,
) : Serializable

data class IntResolution(
    val status: ResolutionStatus,
    val value: Int?,
) : Serializable

data class ActionResolution(
    val status: ResolutionStatus,
    val actions: Set<String>,
) : Serializable
