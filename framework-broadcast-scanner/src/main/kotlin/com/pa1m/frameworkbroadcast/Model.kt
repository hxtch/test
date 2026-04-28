package com.pa1m.frameworkbroadcast

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
)

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
)

data class DangerousBroadcastRecord(
    val jarPath: String,
    val declaringClass: String,
    val declaringMethod: String,
    val sourceLine: Int?,
    val actionList: List<String>,
    val broadcastPermission: String?,
    val permissionProtectionLevel: String?,
    val evidence: String,
)

enum class JarScanStatus {
    SUCCESS,
    PARTIAL,
    FAILED,
}

data class JarScanResult(
    val jarPath: String,
    val status: JarScanStatus,
    val dangerousRecords: List<DangerousBroadcastRecord>,
    val errorType: String? = null,
    val errorMessage: String? = null,
) {
    val dangerousCount: Int
        get() = dangerousRecords.size
}

data class ScanResult(
    val dangerousRecords: List<DangerousBroadcastRecord>,
    val jarResults: List<JarScanResult>,
)

data class ScanSummary(
    val totalJars: Int,
    val successJars: Int,
    val partialJars: Int,
    val failedJars: Int,
    val dangerousBroadcasts: Int,
    val fullSuccessRate: Double,
    val processedRate: Double,
)

data class ScanCliConfig(
    val jarDir: String,
    val protectedBroadcasts: String,
    val permissions: String,
    val outDir: String,
    val scanAllReceivers: Boolean,
    val packagePrefix: String?,
)

data class StringResolution(
    val status: ResolutionStatus,
    val value: String?,
)

data class IntResolution(
    val status: ResolutionStatus,
    val value: Int?,
)

data class ActionResolution(
    val status: ResolutionStatus,
    val actions: Set<String>,
)
