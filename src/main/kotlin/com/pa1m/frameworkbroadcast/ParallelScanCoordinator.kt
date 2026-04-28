package com.pa1m.frameworkbroadcast

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import kotlin.io.path.absolutePathString

object ParallelScanCoordinator {
    fun scan(config: ScanCliConfig): ScanResult {
        val artifacts = ArtifactDiscovery.collect(Path.of(config.inputPath), config.inputType)
        if (artifacts.size <= 1 || config.jobs <= 1) {
            val protectedBroadcasts = ProtectedBroadcastParser.parse(Path.of(config.protectedBroadcasts))
            val permissions = PermissionDefinitionsParser.parse(Path.of(config.permissions))
            return FrameworkJarBroadcastScanner(
                scanAllReceivers = config.scanAllReceivers,
                packagePrefix = config.packagePrefix,
            ).scan(
                inputPath = Path.of(config.inputPath),
                inputType = config.inputType,
                protectedBroadcasts = protectedBroadcasts,
                permissions = permissions,
                androidPlatforms = config.androidPlatforms?.let(Path::of),
            )
        }

        if (artifacts.any { ArtifactDiscovery.requiresAndroidPlatforms(it) }) {
            require(!config.androidPlatforms.isNullOrBlank()) { "扫描 dex-jar 或 apk 时必须提供 --android-platforms" }
            ArtifactDiscovery.resolveAndroidJar(Path.of(config.androidPlatforms))
        }

        val progressReporter = ScanProgressReporter()
        progressReporter.onScanStarted(artifacts.size)
        val executor = Executors.newFixedThreadPool(config.jobs.coerceAtMost(artifacts.size))
        val completionService = ExecutorCompletionService<Pair<Int, JarScanResult>>(executor)
        val tempRoot = Files.createTempDirectory("fbscan-workers")
        val results = arrayOfNulls<JarScanResult>(artifacts.size)

        try {
            artifacts.forEachIndexed { index, artifact ->
                completionService.submit(Callable {
                    index to runWorker(config, artifact, tempRoot.resolve("worker-$index"))
                })
            }

            var dangerousTotal = 0
            repeat(artifacts.size) {
                val (index, result) = completionService.take().get()
                results[index] = result
                dangerousTotal += result.dangerousCount
                progressReporter.onJarFinished(
                    currentIndex = results.count { it != null },
                    totalJars = artifacts.size,
                    jarResult = result,
                    dangerousTotal = dangerousTotal,
                )
            }
        } finally {
            executor.shutdownNow()
            progressReporter.onScanCompleted()
        }

        val jarResults = results.mapIndexed { index, result ->
            result ?: JarScanResult(
                jarPath = artifacts[index].path,
                artifactType = artifacts[index].artifactType,
                status = JarScanStatus.FAILED,
                dangerousRecords = emptyList(),
                allRecords = emptyList(),
                errorType = "WorkerMissingResult",
                errorMessage = "worker 未返回结果",
            )
        }

        return ScanResult(
            dangerousRecords = jarResults.flatMap { it.dangerousRecords },
            allRecords = jarResults.flatMap { it.allRecords },
            jarResults = jarResults,
        )
    }

    private fun runWorker(config: ScanCliConfig, artifact: ScanArtifact, workerDir: Path): JarScanResult {
        Files.createDirectories(workerDir)
        val resultFile = workerDir.resolve("worker-result.bin")
        val command = mutableListOf(
            currentJavaExecutable(),
            "-cp",
            System.getProperty("java.class.path"),
            "com.pa1m.frameworkbroadcast.MainKt",
            "--worker-artifact",
            artifact.path,
            "--worker-artifact-type",
            artifact.artifactType.cliValue,
            "--worker-result-file",
            resultFile.absolutePathString(),
            "--protected-broadcasts",
            config.protectedBroadcasts,
            "--permissions",
            config.permissions,
            "--out-dir",
            workerDir.resolve("out").absolutePathString(),
        )
        if (config.scanAllReceivers) {
            command += "--scan-all-receivers"
        }
        if (!config.packagePrefix.isNullOrBlank()) {
            command += listOf("--package-prefix", config.packagePrefix)
        }
        if (!config.androidPlatforms.isNullOrBlank()) {
            command += listOf("--android-platforms", config.androidPlatforms)
        }

        val process = ProcessBuilder(command)
            .directory(Path.of(System.getProperty("user.dir")).toFile())
            .redirectErrorStream(true)
            .redirectOutput(workerDir.resolve("worker.log").toFile())
            .start()
        val exitCode = process.waitFor()
        if (exitCode != 0) {
            val message = Files.readString(workerDir.resolve("worker.log")).ifBlank { "worker 进程退出码: $exitCode" }
            return JarScanResult(
                jarPath = artifact.path,
                artifactType = artifact.artifactType,
                status = JarScanStatus.FAILED,
                dangerousRecords = emptyList(),
                allRecords = emptyList(),
                errorType = "WorkerProcessFailed",
                errorMessage = message.replace(Regex("\\s+"), " ").trim(),
            )
        }
        require(Files.isRegularFile(resultFile)) { "worker 未生成结果文件: $resultFile" }
        return WorkerProtocol.readResult(resultFile)
    }

    private fun currentJavaExecutable(): String {
        val javaHome = System.getProperty("java.home")
        val executable = Path.of(javaHome, "bin", if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java")
        return executable.absolutePathString()
    }
}
