package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

object ProtectedBroadcastParser {
    private val actionRegex = Regex("""android:name\s*=\s*"([^"]+)"""")

    fun parse(path: Path): Set<String> {
        val content = Files.readString(path)
        return actionRegex.findAll(content)
            .map { it.groupValues[1].trim() }
            .filter { it.isNotEmpty() }
            .toSet()
    }
}

object PermissionDefinitionsParser {
    fun parse(path: Path): Map<String, PermissionMeta> {
        val lines = Files.readAllLines(path)
        val result = linkedMapOf<String, PermissionMeta>()

        var currentPermission: String? = null
        var currentProtection = ""

        fun flush() {
            val permission = currentPermission ?: return
            val normalized = currentProtection.trim()
            val tokens = normalized
                .split("|")
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
                .toSet()
            val lowered = normalized.lowercase()
            val highProtection =
                "signature" in lowered ||
                    "system" in lowered ||
                    lowered == "signatureorsystem"
            result[permission] = PermissionMeta(
                permissionName = permission,
                protectionLevelRaw = normalized,
                protectionLevelTokens = tokens,
                highProtection = highProtection,
            )
        }

        for (rawLine in lines) {
            val line = rawLine.replace('\u00A0', ' ').trim()
            when {
                line.startsWith("+ permission:") -> {
                    flush()
                    currentPermission = line.substringAfter("+ permission:").trim()
                    currentProtection = ""
                }
                line.startsWith("protectionLevel:") -> {
                    currentProtection = line.substringAfter("protectionLevel:").trim()
                }
            }
        }
        flush()
        return result
    }
}

object DangerousBroadcastFilter {
    fun filter(
        fact: BroadcastScanFact,
        protectedBroadcasts: Set<String>,
        permissions: Map<String, PermissionMeta>,
    ): DangerousBroadcastRecord? {
        if (fact.isNotExported) {
            return null
        }
        val permissionMeta = fact.broadcastPermission?.let { permissions[it] }
        val allActionsProtected = fact.intentFilterActions.isNotEmpty() &&
            fact.intentFilterActions.all { it in protectedBroadcasts }
        if (allActionsProtected) {
            return null
        }
        if (permissionMeta?.highProtection == true) {
            return null
        }
        return DangerousBroadcastRecord(
            jarPath = fact.jarPath,
            declaringClass = fact.declaringClass,
            declaringMethod = fact.declaringMethod,
            sourceLine = fact.sourceLine,
            actionList = fact.intentFilterActions.sorted(),
            broadcastPermission = fact.broadcastPermission,
            permissionProtectionLevel = permissionMeta?.protectionLevelRaw,
            evidence = fact.evidence,
        )
    }
}
