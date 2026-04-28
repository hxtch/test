package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.zip.ZipFile
import kotlin.io.path.extension
import kotlin.streams.toList

object ArtifactDiscovery {
    fun collect(inputPath: Path, inputType: InputTypeMode): List<ScanArtifact> {
        val artifacts = if (Files.isDirectory(inputPath)) {
            Files.walk(inputPath).use { stream ->
                stream
                    .filter { Files.isRegularFile(it) && isSupportedArtifactPath(it) }
                    .map { detectArtifact(it, inputType) }
                    .sorted(compareBy<ScanArtifact> { it.path })
                    .toList()
            }
        } else {
            listOf(detectArtifact(inputPath, inputType))
        }
        require(artifacts.isNotEmpty()) { "输入路径下没有找到可扫描文件: $inputPath" }
        return artifacts
    }

    fun resolveAndroidJar(androidPlatforms: Path?): String? {
        if (androidPlatforms == null) {
            return null
        }
        require(Files.exists(androidPlatforms)) { "Android 平台路径不存在: $androidPlatforms" }
        if (Files.isRegularFile(androidPlatforms)) {
            require(androidPlatforms.fileName.toString() == "android.jar") { "Android 平台文件必须是 android.jar: $androidPlatforms" }
            return androidPlatforms.toAbsolutePath().toString()
        }

        val directJar = androidPlatforms.resolve("android.jar")
        if (Files.isRegularFile(directJar)) {
            return directJar.toAbsolutePath().toString()
        }

        val candidates = Files.walk(androidPlatforms, 2).use { stream ->
            stream
                .filter { Files.isRegularFile(it) && it.fileName.toString() == "android.jar" }
                .sorted(compareByDescending<Path> { extractApiLevel(it.parent?.fileName?.toString()) }.thenByDescending { it.toString() })
                .toList()
        }
        require(candidates.isNotEmpty()) { "Android 平台目录下没有找到 android.jar: $androidPlatforms" }
        return candidates.first().toAbsolutePath().toString()
    }

    fun requiresAndroidPlatforms(artifact: ScanArtifact): Boolean {
        return artifact.artifactType == ArtifactType.DEX_JAR || artifact.artifactType == ArtifactType.APK
    }

    private fun detectArtifact(path: Path, inputType: InputTypeMode): ScanArtifact {
        val absolutePath = path.toAbsolutePath()
        val artifactType = when (inputType) {
            InputTypeMode.CLASS_JAR -> ArtifactType.CLASS_JAR
            InputTypeMode.DEX_JAR -> ArtifactType.DEX_JAR
            InputTypeMode.APK -> ArtifactType.APK
            InputTypeMode.AUTO -> detectArtifactTypeAutomatically(absolutePath)
        }
        return ScanArtifact(absolutePath.toString(), artifactType)
    }

    private fun detectArtifactTypeAutomatically(path: Path): ArtifactType {
        return when (path.extension.lowercase()) {
            "apk" -> ArtifactType.APK
            "jar", "zip" -> if (archiveContainsDex(path)) ArtifactType.DEX_JAR else ArtifactType.CLASS_JAR
            else -> error("不支持的输入文件类型: $path")
        }
    }

    private fun archiveContainsDex(path: Path): Boolean {
        ZipFile(path.toFile()).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (!entry.isDirectory && entry.name.lowercase().endsWith(".dex")) {
                    return true
                }
            }
        }
        return false
    }

    private fun isSupportedArtifactPath(path: Path): Boolean {
        return when (path.extension.lowercase()) {
            "jar", "zip", "apk" -> true
            else -> false
        }
    }

    private fun extractApiLevel(name: String?): Int {
        if (name == null) {
            return -1
        }
        return Regex("""android-(\d+)""")
            .find(name)
            ?.groupValues
            ?.getOrNull(1)
            ?.toIntOrNull()
            ?: -1
    }
}
