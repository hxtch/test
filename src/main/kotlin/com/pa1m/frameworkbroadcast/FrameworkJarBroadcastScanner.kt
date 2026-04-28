package com.pa1m.frameworkbroadcast

import soot.G
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.options.Options
import soot.tagkit.LineNumberTag
import soot.tagkit.SourceLnPosTag
import java.io.File
import java.nio.file.Path

open class FrameworkJarBroadcastScanner(
    private val progressReporter: ScanProgressReporter = ScanProgressReporter(),
    private val scanAllReceivers: Boolean = false,
    private val packagePrefix: String? = null,
) {
    fun scan(
        jarDir: Path,
        protectedBroadcasts: ProtectedBroadcastMatcher,
        permissions: Map<String, PermissionMeta>,
    ): ScanResult {
        return scan(
            inputPath = jarDir,
            inputType = InputTypeMode.AUTO,
            protectedBroadcasts = protectedBroadcasts,
            permissions = permissions,
            androidPlatforms = null,
        )
    }

    fun scan(
        inputPath: Path,
        inputType: InputTypeMode,
        protectedBroadcasts: ProtectedBroadcastMatcher,
        permissions: Map<String, PermissionMeta>,
        androidPlatforms: Path? = null,
    ): ScanResult {
        val artifacts = ArtifactDiscovery.collect(inputPath, inputType)
        val environment = createScanEnvironment(artifacts, androidPlatforms)
        val jarResults = mutableListOf<JarScanResult>()
        progressReporter.onScanStarted(artifacts.size)
        for ((index, artifact) in artifacts.withIndex()) {
            val jarResult = scanSingleArtifact(artifact, environment, protectedBroadcasts, permissions)
            jarResults += jarResult
            progressReporter.onJarFinished(
                currentIndex = index + 1,
                totalJars = artifacts.size,
                jarResult = jarResult,
                dangerousTotal = jarResults.sumOf { it.dangerousCount },
            )
        }
        progressReporter.onScanCompleted()
        return ScanResult(
            dangerousRecords = jarResults.flatMap { it.dangerousRecords },
            allRecords = jarResults.flatMap { it.allRecords },
            jarResults = jarResults,
        )
    }

    fun scanSingleArtifact(
        artifact: ScanArtifact,
        protectedBroadcasts: ProtectedBroadcastMatcher,
        permissions: Map<String, PermissionMeta>,
        androidPlatforms: Path? = null,
    ): JarScanResult {
        val environment = createScanEnvironment(listOf(artifact), androidPlatforms)
        return scanSingleArtifact(artifact, environment, protectedBroadcasts, permissions)
    }

    protected open fun scanSingleArtifact(
        artifact: ScanArtifact,
        environment: ScanEnvironment,
        protectedBroadcasts: ProtectedBroadcastMatcher,
        permissions: Map<String, PermissionMeta>,
    ): JarScanResult {
        val dangerousRecords = mutableListOf<DangerousBroadcastRecord>()
        val allRecords = mutableListOf<AllDynamicBroadcastRecord>()
        return try {
            G.reset()
            initSootForArtifact(artifact, environment)

            val classes = Scene.v().applicationClasses
                .toList()
                .asSequence()
                .filter { shouldScanClass(it.name) }
                .sortedBy(SootClass::getName)
                .toList()
            for (sootClass in classes) {
                for (method in sootClass.methods.filter { it.isConcrete }) {
                    val facts = scanMethod(artifact.path, method)
                    for (fact in facts) {
                        if (scanAllReceivers) {
                            allRecords += toAllRecord(fact, permissions)
                        }
                        DangerousBroadcastFilter.filter(fact, protectedBroadcasts, permissions)?.let {
                            dangerousRecords += it
                        }
                    }
                }
            }
            JarScanResult(
                jarPath = artifact.path,
                artifactType = artifact.artifactType,
                status = JarScanStatus.SUCCESS,
                dangerousRecords = dangerousRecords,
                allRecords = allRecords,
            )
        } catch (e: Exception) {
            JarScanResult(
                jarPath = artifact.path,
                artifactType = artifact.artifactType,
                status = if (dangerousRecords.isEmpty()) JarScanStatus.FAILED else JarScanStatus.PARTIAL,
                dangerousRecords = dangerousRecords.toList(),
                allRecords = allRecords.toList(),
                errorType = e::class.simpleName ?: "UnknownException",
                errorMessage = singleLineErrorMessage(e),
            )
        }
    }

    private fun createScanEnvironment(artifacts: List<ScanArtifact>, androidPlatforms: Path?): ScanEnvironment {
        val classpathJars = artifacts
            .filter { it.artifactType == ArtifactType.CLASS_JAR }
            .map { it.path }
            .sorted()
        val androidJar = if (artifacts.any { ArtifactDiscovery.requiresAndroidPlatforms(it) }) {
            ArtifactDiscovery.resolveAndroidJar(androidPlatforms)
                ?: error("扫描 dex-jar 或 apk 时必须提供 --android-platforms")
        } else {
            null
        }
        return ScanEnvironment(classpathJars = classpathJars, androidJar = androidJar)
    }

    private fun initSootForArtifact(artifact: ScanArtifact, environment: ScanEnvironment) {
        when (artifact.artifactType) {
            ArtifactType.CLASS_JAR -> {
                Options.v().set_src_prec(Options.src_prec_class)
                Options.v().set_process_dir(listOf(artifact.path))
                Options.v().set_soot_classpath(environment.classpathJars.joinToString(File.pathSeparator))
                Options.v().set_prepend_classpath(true)
            }

            ArtifactType.DEX_JAR,
            ArtifactType.APK,
            -> {
                val androidJar = environment.androidJar
                    ?: error("扫描 ${artifact.artifactType.cliValue} 时缺少 android.jar")
                Options.v().set_src_prec(Options.src_prec_apk)
                Options.v().set_process_dir(listOf(artifact.path))
                Options.v().set_search_dex_in_archives(true)
                Options.v().set_process_multiple_dex(true)
                Options.v().set_force_android_jar(androidJar)
                Options.v().set_soot_classpath(
                    (environment.classpathJars + androidJar)
                        .distinct()
                        .joinToString(File.pathSeparator)
                )
                Options.v().set_prepend_classpath(true)
            }
        }

        Options.v().set_allow_phantom_refs(true)
        Options.v().set_whole_program(true)
        Options.v().set_output_format(Options.output_format_none)
        Options.v().set_keep_line_number(true)
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore)
        Options.v().set_validate(false)
        Options.v().set_verbose(false)
        Options.v().set_debug(false)
        Options.v().set_exclude(listOf("java.*", "javax.*", "sun.*", "kotlin.*", "org.jetbrains.*"))
        Options.v().set_no_bodies_for_excluded(true)
        Scene.v().loadNecessaryClasses()
    }

    private fun scanMethod(jarPath: String, method: SootMethod): List<BroadcastScanFact> {
        val body = try {
            method.retrieveActiveBody()
        } catch (_: Exception) {
            return emptyList()
        }
        val resolver = MethodLocalResolver(body)
        val results = mutableListOf<BroadcastScanFact>()

        for (unit in body.units) {
            val stmt = unit as? soot.jimple.Stmt ?: continue
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr
            val methodRef = invokeExpr.methodRef
            if (!RegisterReceiverApi.matches(methodRef)) {
                continue
            }

            val filterIndex = RegisterReceiverApi.filterIndex(methodRef) ?: continue
            val permissionIndex = RegisterReceiverApi.permissionIndex(methodRef)
            val flagsIndex = RegisterReceiverApi.flagsIndex(methodRef)

            val filterValue = invokeExpr.getArg(filterIndex)
            val permissionValue = permissionIndex?.let { invokeExpr.getArg(it) }
            val flagsValueExpr = flagsIndex?.let { invokeExpr.getArg(it) }

            val actions = resolver.resolveActions(filterValue, stmt)
            val permission = permissionValue?.let { resolver.resolveString(it, stmt) }
                ?: StringResolution(ResolutionStatus.NULL_VALUE, null)
            val flags = flagsValueExpr?.let { resolver.resolveInt(it, stmt) }
                ?: IntResolution(ResolutionStatus.NULL_VALUE, null)

            results += BroadcastScanFact(
                jarPath = jarPath,
                declaringClass = method.declaringClass.name,
                declaringMethod = method.signature,
                intentFilterActions = actions.actions,
                broadcastPermission = permission.value,
                flagsValue = flags.value,
                isNotExported = isNotExported(flags.value),
                sourceLine = sourceLine(stmt),
                evidence = stmt.toString(),
            )
        }

        return results
    }

    private fun sourceLine(stmt: soot.jimple.Stmt): Int? {
        val lineTag = stmt.getTag("LineNumberTag") as? LineNumberTag
        if (lineTag != null) {
            return lineTag.lineNumber
        }
        val sourceTag = stmt.getTag("SourceLnPosTag") as? SourceLnPosTag
        return sourceTag?.startLn()
    }

    private fun isNotExported(value: Int?): Boolean {
        if (value == null) {
            return false
        }
        return (value and 0x4) != 0
    }

    private fun singleLineErrorMessage(e: Exception): String {
        val message = e.message?.replace(Regex("\\s+"), " ")?.trim()
        return if (message.isNullOrEmpty()) e.toString() else message
    }

    private fun toAllRecord(fact: BroadcastScanFact, permissions: Map<String, PermissionMeta>): AllDynamicBroadcastRecord {
        return AllDynamicBroadcastRecord(
            jarPath = fact.jarPath,
            declaringClass = fact.declaringClass,
            declaringMethod = fact.declaringMethod,
            sourceLine = fact.sourceLine,
            actionList = fact.intentFilterActions.toList(),
            broadcastPermission = fact.broadcastPermission,
            permissionProtectionLevel = fact.broadcastPermission?.let { permissions[it]?.protectionLevelRaw },
            evidence = fact.evidence,
        )
    }

    private fun shouldScanClass(className: String): Boolean {
        if (!packagePrefix.isNullOrBlank()) {
            return className.startsWith(packagePrefix)
        }
        return true
    }

    protected data class ScanEnvironment(
        val classpathJars: List<String>,
        val androidJar: String?,
    )
}
