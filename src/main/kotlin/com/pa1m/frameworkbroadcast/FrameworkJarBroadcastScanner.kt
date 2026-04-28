package com.pa1m.frameworkbroadcast

import soot.G
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.options.Options
import soot.tagkit.LineNumberTag
import soot.tagkit.SourceLnPosTag
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.streams.toList

open class FrameworkJarBroadcastScanner {
    fun scan(jarDir: Path, protectedBroadcasts: Set<String>, permissions: Map<String, PermissionMeta>): ScanResult {
        val jars = Files.list(jarDir)
            .use { stream -> stream.filter { Files.isRegularFile(it) && it.extension == "jar" }.sorted().toList() }
        require(jars.isNotEmpty()) { "jar 目录下没有找到 .jar 文件: $jarDir" }

        val allJars = jars.map { it.toAbsolutePath().toString() }
        val jarResults = mutableListOf<JarScanResult>()
        for (jar in jars) {
            jarResults += scanSingleJar(jar.toAbsolutePath(), allJars, protectedBroadcasts, permissions)
        }
        return ScanResult(
            dangerousRecords = jarResults.flatMap { it.dangerousRecords },
            jarResults = jarResults,
        )
    }

    protected open fun scanSingleJar(
        targetJar: Path,
        classpathJars: List<String>,
        protectedBroadcasts: Set<String>,
        permissions: Map<String, PermissionMeta>,
    ): JarScanResult {
        val dangerousRecords = mutableListOf<DangerousBroadcastRecord>()
        return try {
            G.reset()
            Options.v().set_src_prec(Options.src_prec_class)
            Options.v().set_process_dir(listOf(targetJar.toString()))
            Options.v().set_soot_classpath(classpathJars.joinToString(File.pathSeparator))
            Options.v().set_prepend_classpath(true)
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

            val classes = Scene.v().applicationClasses.toList().sortedBy(SootClass::getName)
            for (sootClass in classes) {
                for (method in sootClass.methods.filter { it.isConcrete }) {
                    val facts = scanMethod(targetJar.toString(), method)
                    dangerousRecords += facts.mapNotNull {
                        DangerousBroadcastFilter.filter(it, protectedBroadcasts, permissions)
                    }
                }
            }
            JarScanResult(
                jarPath = targetJar.toString(),
                status = JarScanStatus.SUCCESS,
                dangerousRecords = dangerousRecords,
            )
        } catch (e: Exception) {
            JarScanResult(
                jarPath = targetJar.toString(),
                status = if (dangerousRecords.isEmpty()) JarScanStatus.FAILED else JarScanStatus.PARTIAL,
                dangerousRecords = dangerousRecords.toList(),
                errorType = e::class.simpleName ?: "UnknownException",
                errorMessage = singleLineErrorMessage(e),
            )
        }
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
}
