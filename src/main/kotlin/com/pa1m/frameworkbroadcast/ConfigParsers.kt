package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path

data class ProtectedBroadcastMatcher(
    val exactActions: Set<String>,
    val prefixActions: Set<String>,
) {
    fun matches(action: String): Boolean {
        if (action in exactActions) {
            return true
        }
        return prefixActions.any { action.startsWith(it) }
    }
}

object ProtectedBroadcastParser {
    private val actionRegex = Regex("""android:name\s*=\s*"([^"]+)"""")

    fun parse(path: Path): ProtectedBroadcastMatcher {
        val content = Files.readString(path)
        val xmlActions = actionRegex.findAll(content)
            .map { it.groupValues[1].trim() }
            .filter { it.isNotEmpty() }
            .toList()

        val plainTextActions = if (xmlActions.isEmpty()) {
            content.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .filterNot { it.startsWith("#") }
                .toList()
        } else {
            emptyList()
        }

        val exactActions = linkedSetOf<String>()
        val prefixActions = linkedSetOf<String>()
        (xmlActions + plainTextActions).forEach { action ->
            val normalized = action.trim()
            if (normalized.isEmpty()) {
                return@forEach
            }
            if (normalized.endsWith("*")) {
                prefixActions += normalized.removeSuffix("*").trim()
            } else {
                exactActions += normalized
            }
        }
        return ProtectedBroadcastMatcher(
            exactActions = exactActions,
            prefixActions = prefixActions,
        )
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
        protectedBroadcasts: ProtectedBroadcastMatcher,
        permissions: Map<String, PermissionMeta>,
    ): DangerousBroadcastRecord? {
        if (fact.isNotExported) {
            return null
        }
        val permissionMeta = fact.broadcastPermission?.let { permissions[it] }
        val allActionsProtected = fact.intentFilterActions.isNotEmpty() &&
            fact.intentFilterActions.all { protectedBroadcasts.matches(it) }
        if (allActionsProtected) {
            return null
        }
        val customActions = fact.intentFilterActions
            .filterNot { protectedBroadcasts.matches(it) }
            .sorted()
        if (permissionMeta?.highProtection == true) {
            return null
        }
        return DangerousBroadcastRecord(
            jarPath = fact.jarPath,
            declaringClass = fact.declaringClass,
            declaringMethod = fact.declaringMethod,
            sourceLine = fact.sourceLine,
            actionList = customActions,
            broadcastPermission = fact.broadcastPermission,
            permissionProtectionLevel = permissionMeta?.protectionLevelRaw,
            evidence = fact.evidence,
        )
    }
}
