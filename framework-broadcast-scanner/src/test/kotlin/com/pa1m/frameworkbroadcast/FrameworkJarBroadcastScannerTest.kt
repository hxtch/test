package com.pa1m.frameworkbroadcast

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import soot.G
import java.io.FileOutputStream
import java.io.IOException
import java.io.PrintStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import javax.tools.ToolProvider
import kotlin.streams.toList

class FrameworkJarBroadcastScannerTest {
    @Test
    fun `parsers load protected broadcasts and permission levels`() {
        val dir = Files.createTempDirectory("broadcast-parser")
        val protectedXml = dir.resolve("proaction.xml")
        Files.writeString(
            protectedXml,
            """
            <root>
              <protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />
              <protected-broadcast android:name="android.intent.action.ACTION_SET_GLOBAL_AUTO_PARAM_DONE" />
            </root>
            """.trimIndent()
        )
        val permissions = dir.resolve("permission.txt")
        Files.writeString(
            permissions,
            """
            All Permissions:
            + permission:android.permission.NORMAL_PERMISSION
              protectionLevel:normal
            + permission:android.permission.SIGNATURE_ONLY
              protectionLevel:signature|role
            """.trimIndent()
        )

        val actions = ProtectedBroadcastParser.parse(protectedXml)
        val permissionMap = PermissionDefinitionsParser.parse(permissions)

        assertTrue("android.intent.action.BOOT_COMPLETED" in actions)
        assertEquals(false, permissionMap.getValue("android.permission.NORMAL_PERMISSION").highProtection)
        assertEquals(true, permissionMap.getValue("android.permission.SIGNATURE_ONLY").highProtection)
    }

    @Test
    fun `mixed actions do not get skipped by protected broadcast rule`() {
        val fact = BroadcastScanFact(
            jarPath = "a.jar",
            declaringClass = "test.Sample",
            declaringMethod = "m",
            intentFilterActions = setOf("android.intent.action.BOOT_COMPLETED", "com.test.CUSTOM"),
            broadcastPermission = "android.permission.NORMAL_PERMISSION",
            flagsValue = null,
            isNotExported = false,
            sourceLine = 12,
            evidence = "invoke",
        )
        val record = DangerousBroadcastFilter.filter(
            fact,
            protectedBroadcasts = setOf("android.intent.action.BOOT_COMPLETED"),
            permissions = mapOf(
                "android.permission.NORMAL_PERMISSION" to PermissionMeta(
                    "android.permission.NORMAL_PERMISSION",
                    "normal",
                    setOf("normal"),
                    false
                )
            )
        )
        requireNotNull(record)
        assertEquals(listOf("android.intent.action.BOOT_COMPLETED", "com.test.CUSTOM"), record.actionList)
        assertEquals("normal", record.permissionProtectionLevel)
    }

    @Test
    fun `scanner extracts candidates and protected cases from jar`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-scan")
        val jarDir = tempDir.resolve("jars")
        Files.createDirectories(jarDir)
        val classesDir = tempDir.resolve("classes")
        Files.createDirectories(classesDir)

        val sources = mapOf(
            "android/content/BroadcastReceiver.java" to """
                package android.content;
                public abstract class BroadcastReceiver {}
            """.trimIndent(),
            "android/content/Intent.java" to """
                package android.content;
                public class Intent {}
            """.trimIndent(),
            "android/content/IntentFilter.java" to """
                package android.content;
                public class IntentFilter {
                    public IntentFilter() {}
                    public IntentFilter(String action) {}
                    public void addAction(String action) {}
                }
            """.trimIndent(),
            "android/os/Handler.java" to """
                package android.os;
                public class Handler {}
            """.trimIndent(),
            "android/content/Context.java" to """
                package android.content;
                import android.os.Handler;
                public abstract class Context {
                    public static final int RECEIVER_EXPORTED = 0x2;
                    public static final int RECEIVER_NOT_EXPORTED = 0x4;
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler) { return null; }
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler, int flags) { return null; }
                }
            """.trimIndent(),
            "com/huawei/sample/SampleReceiver.java" to """
                package com.huawei.sample;
                import android.content.BroadcastReceiver;
                public class SampleReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "com/huawei/sample/DummyContext.java" to """
                package com.huawei.sample;
                import android.content.Context;
                public class DummyContext extends Context {}
            """.trimIndent(),
            "com/huawei/sample/RegisterCases.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class RegisterCases {
                    private final Context context = new DummyContext();
                    public void legacyNoPermission() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.CUSTOM");
                        context.registerReceiver(receiver, filter);
                    }
                    public void signaturePermission() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.CUSTOM_SIG");
                        context.registerReceiver(receiver, filter, "android.permission.SIGNATURE_ONLY", null);
                    }
                    public void protectedOnly() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("android.intent.action.BOOT_COMPLETED");
                        context.registerReceiver(receiver, filter);
                    }
                    public void mixedActionNeedsPermissionCheck() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("android.intent.action.BOOT_COMPLETED");
                        filter.addAction("com.test.CUSTOM_MIXED");
                        context.registerReceiver(receiver, filter, "android.permission.NORMAL_PERMISSION", null);
                    }
                    public void notExported() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.PRIVATE");
                        context.registerReceiver(receiver, filter, null, null, Context.RECEIVER_NOT_EXPORTED);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("sample.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(
            protectedXml,
            """
            <protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />
            """.trimIndent()
        )
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(
            permissionTxt,
            """
            All Permissions:
            + permission:android.permission.NORMAL_PERMISSION
              protectionLevel:normal
            + permission:android.permission.SIGNATURE_ONLY
              protectionLevel:signature|role
            """.trimIndent()
        )

        val scanner = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.")
        val protectedActions = ProtectedBroadcastParser.parse(protectedXml)
        val permissions = PermissionDefinitionsParser.parse(permissionTxt)

        val scanResult = scanner.scan(jarDir, protectedActions, permissions)
        val records = scanResult.dangerousRecords
        val byMethod = records.associateBy { it.declaringMethod.substringAfterLast(" ").substringBefore("(") }

        assertEquals(2, records.size)
        assertEquals(1, scanResult.jarResults.size)
        assertEquals(JarScanStatus.SUCCESS, scanResult.jarResults.single().status)
        assertTrue("legacyNoPermission" in byMethod)
        assertTrue("mixedActionNeedsPermissionCheck" in byMethod)
        assertNull(byMethod.getValue("legacyNoPermission").broadcastPermission)
        assertNull(byMethod.getValue("legacyNoPermission").permissionProtectionLevel)
        assertEquals("normal", byMethod.getValue("mixedActionNeedsPermissionCheck").permissionProtectionLevel)
        assertEquals(
            listOf("android.intent.action.BOOT_COMPLETED", "com.test.CUSTOM_MIXED"),
            byMethod.getValue("mixedActionNeedsPermissionCheck").actionList
        )
        assertTrue(records.all { it.declaringClass.startsWith("com.huawei.") })
        G.reset()
    }

    @Test
    fun `scanner finds jars recursively in nested directories`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-recursive")
        val jarDir = tempDir.resolve("jars")
        val nestedDir = jarDir.resolve("level1/level2")
        Files.createDirectories(nestedDir)
        val classesDir = tempDir.resolve("classes")
        Files.createDirectories(classesDir)

        val sources = mapOf(
            "android/content/BroadcastReceiver.java" to """
                package android.content;
                public abstract class BroadcastReceiver {}
            """.trimIndent(),
            "android/content/Intent.java" to """
                package android.content;
                public class Intent {}
            """.trimIndent(),
            "android/content/IntentFilter.java" to """
                package android.content;
                public class IntentFilter {
                    public IntentFilter() {}
                    public IntentFilter(String action) {}
                    public void addAction(String action) {}
                }
            """.trimIndent(),
            "android/os/Handler.java" to """
                package android.os;
                public class Handler {}
            """.trimIndent(),
            "android/content/Context.java" to """
                package android.content;
                import android.os.Handler;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler) { return null; }
                }
            """.trimIndent(),
            "com/huawei/sample/SampleReceiver.java" to """
                package com.huawei.sample;
                import android.content.BroadcastReceiver;
                public class SampleReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "com/huawei/sample/DummyContext.java" to """
                package com.huawei.sample;
                import android.content.Context;
                public class DummyContext extends Context {}
            """.trimIndent(),
            "com/huawei/sample/RegisterCases.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class RegisterCases {
                    private final Context context = new DummyContext();
                    public void nestedJarHit() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.NESTED");
                        context.registerReceiver(receiver, filter, "android.permission.NORMAL_PERMISSION", null);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, nestedDir.resolve("nested-sample.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(
            permissionTxt,
            """
            All Permissions:
            + permission:android.permission.NORMAL_PERMISSION
              protectionLevel:normal
            """.trimIndent()
        )

        val scanner = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.")
        val result = scanner.scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, result.jarResults.size)
        assertTrue(result.jarResults.single().jarPath.endsWith("nested-sample.jar"))
        assertEquals(1, result.dangerousRecords.size)
        assertEquals(
            "<com.huawei.sample.RegisterCases: void nestedJarHit()>",
            result.dangerousRecords.single().declaringMethod
        )
        G.reset()
    }

    @Test
    fun `scanner filters by package prefix when configured`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-filter")
        val jarDir = tempDir.resolve("jars")
        Files.createDirectories(jarDir)
        val classesDir = tempDir.resolve("classes")
        Files.createDirectories(classesDir)

        val sources = mapOf(
            "android/content/BroadcastReceiver.java" to """
                package android.content;
                public abstract class BroadcastReceiver {}
            """.trimIndent(),
            "android/content/Intent.java" to """
                package android.content;
                public class Intent {}
            """.trimIndent(),
            "android/content/IntentFilter.java" to """
                package android.content;
                public class IntentFilter {
                    public IntentFilter() {}
                    public IntentFilter(String action) {}
                    public void addAction(String action) {}
                }
            """.trimIndent(),
            "android/os/Handler.java" to """
                package android.os;
                public class Handler {}
            """.trimIndent(),
            "android/content/Context.java" to """
                package android.content;
                import android.os.Handler;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler) { return null; }
                }
            """.trimIndent(),
            "com/huawei/test/HuaweiReceiver.java" to """
                package com.huawei.test;
                import android.content.BroadcastReceiver;
                public class HuaweiReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "com/huawei/test/HuaweiContext.java" to """
                package com.huawei.test;
                import android.content.Context;
                public class HuaweiContext extends Context {}
            """.trimIndent(),
            "com/huawei/test/HuaweiRegister.java" to """
                package com.huawei.test;
                import android.content.Context;
                import android.content.IntentFilter;
                public class HuaweiRegister {
                    private final Context context = new HuaweiContext();
                    public void keepMe() {
                        HuaweiReceiver receiver = new HuaweiReceiver();
                        IntentFilter filter = new IntentFilter("com.test.HUAWEI_ONLY");
                        context.registerReceiver(receiver, filter, null, null);
                    }
                }
            """.trimIndent(),
            "sample/OtherReceiver.java" to """
                package sample;
                import android.content.BroadcastReceiver;
                public class OtherReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "sample/OtherContext.java" to """
                package sample;
                import android.content.Context;
                public class OtherContext extends Context {}
            """.trimIndent(),
            "sample/OtherRegister.java" to """
                package sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class OtherRegister {
                    private final Context context = new OtherContext();
                    public void skipMe() {
                        OtherReceiver receiver = new OtherReceiver();
                        IntentFilter filter = new IntentFilter("com.test.NON_HUAWEI");
                        context.registerReceiver(receiver, filter, null, null);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("mixed.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(permissionTxt, "All Permissions:\n")

        val result = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.").scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, result.dangerousRecords.size)
        assertEquals("com.huawei.test.HuaweiRegister", result.dangerousRecords.single().declaringClass)
        assertEquals("<com.huawei.test.HuaweiRegister: void keepMe()>", result.dangerousRecords.single().declaringMethod)
        G.reset()
    }

    @Test
    fun `scanner scans all classes by default`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-scan-all")
        val jarDir = tempDir.resolve("jars")
        Files.createDirectories(jarDir)
        val classesDir = tempDir.resolve("classes")
        Files.createDirectories(classesDir)

        val sources = mapOf(
            "android/content/BroadcastReceiver.java" to """
                package android.content;
                public abstract class BroadcastReceiver {}
            """.trimIndent(),
            "android/content/Intent.java" to """
                package android.content;
                public class Intent {}
            """.trimIndent(),
            "android/content/IntentFilter.java" to """
                package android.content;
                public class IntentFilter {
                    public IntentFilter() {}
                    public IntentFilter(String action) {}
                    public void addAction(String action) {}
                }
            """.trimIndent(),
            "android/os/Handler.java" to """
                package android.os;
                public class Handler {}
            """.trimIndent(),
            "android/content/Context.java" to """
                package android.content;
                import android.os.Handler;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler) { return null; }
                }
            """.trimIndent(),
            "com/huawei/test/HuaweiReceiver.java" to """
                package com.huawei.test;
                import android.content.BroadcastReceiver;
                public class HuaweiReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "com/huawei/test/HuaweiContext.java" to """
                package com.huawei.test;
                import android.content.Context;
                public class HuaweiContext extends Context {}
            """.trimIndent(),
            "com/huawei/test/HuaweiRegister.java" to """
                package com.huawei.test;
                import android.content.Context;
                import android.content.IntentFilter;
                public class HuaweiRegister {
                    private final Context context = new HuaweiContext();
                    public void keepMe() {
                        HuaweiReceiver receiver = new HuaweiReceiver();
                        IntentFilter filter = new IntentFilter("com.test.HUAWEI_ONLY");
                        context.registerReceiver(receiver, filter, null, null);
                    }
                }
            """.trimIndent(),
            "sample/OtherReceiver.java" to """
                package sample;
                import android.content.BroadcastReceiver;
                public class OtherReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "sample/OtherContext.java" to """
                package sample;
                import android.content.Context;
                public class OtherContext extends Context {}
            """.trimIndent(),
            "sample/OtherRegister.java" to """
                package sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class OtherRegister {
                    private final Context context = new OtherContext();
                    public void keepMeToo() {
                        OtherReceiver receiver = new OtherReceiver();
                        IntentFilter filter = new IntentFilter("com.test.NON_HUAWEI");
                        context.registerReceiver(receiver, filter, null, null);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("mixed-all.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(permissionTxt, "All Permissions:\n")

        val result = FrameworkJarBroadcastScanner().scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(2, result.dangerousRecords.size)
        assertTrue(result.dangerousRecords.any { it.declaringClass == "com.huawei.test.HuaweiRegister" })
        assertTrue(result.dangerousRecords.any { it.declaringClass == "sample.OtherRegister" })
        G.reset()
    }

    @Test
    fun `parse args supports package prefix option`() {
        val tempDir = Files.createTempDirectory("scan-args")
        val jarDir = tempDir.resolve("jars")
        Files.createDirectories(jarDir)
        val protectedXml = tempDir.resolve("proaction.xml")
        val permissions = tempDir.resolve("permission.txt")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        Files.writeString(permissions, "All Permissions:\n")

        val withPrefix = parseArgs(
            arrayOf(
                "--jar-dir", jarDir.toString(),
                "--protected-broadcasts", protectedXml.toString(),
                "--permissions", permissions.toString(),
                "--package-prefix", "com.huawei",
            )
        )
        val defaultAll = parseArgs(
            arrayOf(
                "--jar-dir", jarDir.toString(),
                "--protected-broadcasts", protectedXml.toString(),
                "--permissions", permissions.toString(),
            )
        )

        assertEquals("com.huawei", withPrefix.packagePrefix)
        assertNull(defaultAll.packagePrefix)
        assertTrue(defaultAll.scanAllReceivers)
    }

    @Test
    fun `parse args keeps scan all receivers flag for compatibility`() {
        val tempDir = Files.createTempDirectory("scan-args-compat")
        val jarDir = tempDir.resolve("jars")
        Files.createDirectories(jarDir)
        val protectedXml = tempDir.resolve("proaction.xml")
        val permissions = tempDir.resolve("permission.txt")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        Files.writeString(permissions, "All Permissions:\n")

        val flagOnly = parseArgs(
            arrayOf(
                "--jar-dir", jarDir.toString(),
                "--protected-broadcasts", protectedXml.toString(),
                "--permissions", permissions.toString(),
                "--scan-all-receivers",
            )
        )

        assertTrue(flagOnly.scanAllReceivers)
    }

    @Test
    fun `report writer emits dangerous list files with final fields`() {
        val outDir = Files.createTempDirectory("broadcast-report")
        val records = listOf(
            DangerousBroadcastRecord(
                jarPath = "/tmp/sample.jar",
                declaringClass = "sample.RegisterCases",
                declaringMethod = "<sample.RegisterCases: void legacyNoPermission()>",
                sourceLine = 42,
                actionList = listOf("com.test.CUSTOM"),
                broadcastPermission = null,
                permissionProtectionLevel = null,
                evidence = "virtualinvoke context.registerReceiver(receiver, filter)"
            )
        )
        val scanResult = ScanResult(
            dangerousRecords = records,
            jarResults = listOf(
                JarScanResult(
                    jarPath = "/tmp/sample.jar",
                    status = JarScanStatus.SUCCESS,
                    dangerousRecords = records,
                )
            )
        )

        ReportWriter.write(outDir, scanResult)

        val jsonl = Files.readString(outDir.resolve("dangerous_dynamic_broadcasts.jsonl"))
        val markdown = Files.readString(outDir.resolve("dangerous_dynamic_broadcasts.md"))
        val summary = Files.readString(outDir.resolve("scan_summary.json"))
        val partialJsonl = Files.readString(outDir.resolve("partial_jars.jsonl"))
        val failedJsonl = Files.readString(outDir.resolve("failed_jars.jsonl"))

        assertTrue(jsonl.contains("\"jar_path\":\"/tmp/sample.jar\""))
        assertTrue(jsonl.contains("\"action_list\":[\"com.test.CUSTOM\"]"))
        assertTrue(jsonl.contains("\"permission_protection_level\":null"))
        assertTrue(markdown.contains("Dangerous Dynamic Broadcasts"))
        assertTrue(markdown.contains("broadcast_permission"))
        assertTrue(summary.contains("\"dangerous_broadcasts\":1"))
        assertTrue(summary.contains("\"success_jars\":1"))
        assertTrue(partialJsonl.isEmpty())
        assertTrue(failedJsonl.isEmpty())
    }

    @Test
    fun `scanner keeps dangerous records for partial jar and reports failed jar`() {
        val jarDir = Files.createTempDirectory("scan-status-jars")
        val goodJar = jarDir.resolve("good.jar")
        val partialJar = jarDir.resolve("partial.jar")
        val failedJar = jarDir.resolve("failed.jar")
        Files.write(goodJar, byteArrayOf())
        Files.write(partialJar, byteArrayOf())
        Files.write(failedJar, byteArrayOf())

        val dangerous = DangerousBroadcastRecord(
            jarPath = partialJar.toString(),
            declaringClass = "sample.Partial",
            declaringMethod = "<sample.Partial: void run()>",
            sourceLine = 7,
            actionList = listOf("com.test.PARTIAL"),
            broadcastPermission = null,
            permissionProtectionLevel = null,
            evidence = "invoke"
        )
        val scanner = object : FrameworkJarBroadcastScanner() {
            override fun scanSingleJar(
                targetJar: Path,
                classpathJars: List<String>,
                protectedBroadcasts: Set<String>,
                permissions: Map<String, PermissionMeta>,
            ): JarScanResult {
                return when (targetJar.fileName.toString()) {
                    "good.jar" -> JarScanResult(targetJar.toString(), JarScanStatus.SUCCESS, emptyList())
                    "partial.jar" -> JarScanResult(
                        targetJar.toString(),
                        JarScanStatus.PARTIAL,
                        listOf(dangerous),
                        "RuntimeException",
                        "boom after partial results"
                    )
                    else -> JarScanResult(
                        targetJar.toString(),
                        JarScanStatus.FAILED,
                        emptyList(),
                        "IOException",
                        "cannot parse jar"
                    )
                }
            }
        }

        val result = scanner.scan(jarDir, emptySet(), emptyMap())

        assertEquals(1, result.dangerousRecords.size)
        assertEquals(partialJar.toString(), result.dangerousRecords.single().jarPath)
        assertEquals(1, result.jarResults.count { it.status == JarScanStatus.SUCCESS })
        assertEquals(1, result.jarResults.count { it.status == JarScanStatus.PARTIAL })
        assertEquals(1, result.jarResults.count { it.status == JarScanStatus.FAILED })
    }

    @Test
    fun `progress reporter prints readable non tty progress`() {
        val buffer = ByteArrayOutputStream()
        val reporter = ScanProgressReporter(PrintStream(buffer, true), interactive = false)

        reporter.onScanStarted(2)
        reporter.onJarFinished(
            currentIndex = 1,
            totalJars = 2,
            jarResult = JarScanResult("/tmp/a.jar", JarScanStatus.SUCCESS, emptyList()),
            dangerousTotal = 0,
        )
        reporter.onJarFinished(
            currentIndex = 2,
            totalJars = 2,
            jarResult = JarScanResult("/tmp/b.jar", JarScanStatus.PARTIAL, emptyList(), "RuntimeException", "boom"),
            dangerousTotal = 3,
        )
        reporter.onScanCompleted()

        val output = buffer.toString(Charsets.UTF_8)
        assertTrue(output.contains("scan started: total_jars=2"))
        assertTrue(output.contains("progress: 1/2 success=1 partial=0 failed=0 dangerous=0 status=success current=a.jar"))
        assertTrue(output.contains("progress: 2/2 success=1 partial=1 failed=0 dangerous=3 status=partial current=b.jar"))
    }

    @Test
    fun `report writer emits summary and status files`() {
        val outDir = Files.createTempDirectory("broadcast-summary")
        val dangerous = DangerousBroadcastRecord(
            jarPath = "/tmp/partial.jar",
            declaringClass = "sample.Partial",
            declaringMethod = "<sample.Partial: void run()>",
            sourceLine = 7,
            actionList = listOf("com.test.PARTIAL"),
            broadcastPermission = null,
            permissionProtectionLevel = null,
            evidence = "invoke"
        )
        val scanResult = ScanResult(
            dangerousRecords = listOf(dangerous),
            jarResults = listOf(
                JarScanResult("/tmp/good.jar", JarScanStatus.SUCCESS, emptyList()),
                JarScanResult("/tmp/partial.jar", JarScanStatus.PARTIAL, listOf(dangerous), "RuntimeException", "boom"),
                JarScanResult("/tmp/failed.jar", JarScanStatus.FAILED, emptyList(), "IOException", "broken")
            )
        )

        ReportWriter.write(outDir, scanResult)

        val summary = Files.readString(outDir.resolve("scan_summary.json"))
        val partialJsonl = Files.readString(outDir.resolve("partial_jars.jsonl"))
        val failedJsonl = Files.readString(outDir.resolve("failed_jars.jsonl"))
        val errorLog = Files.readString(outDir.resolve("scan_errors.log"))

        assertTrue(summary.contains("\"total_jars\":3"))
        assertTrue(summary.contains("\"success_jars\":1"))
        assertTrue(summary.contains("\"partial_jars\":1"))
        assertTrue(summary.contains("\"failed_jars\":1"))
        assertTrue(summary.contains("\"dangerous_broadcasts\":1"))
        assertTrue(partialJsonl.contains("\"status\":\"partial\""))
        assertTrue(partialJsonl.contains("\"jar_path\":\"/tmp/partial.jar\""))
        assertTrue(failedJsonl.contains("\"status\":\"failed\""))
        assertTrue(failedJsonl.contains("\"jar_path\":\"/tmp/failed.jar\""))
        assertTrue(errorLog.contains("jar_path: /tmp/partial.jar"))
        assertTrue(errorLog.contains("jar_path: /tmp/failed.jar"))
        assertFalse(errorLog.contains("jar_path: /tmp/good.jar"))
    }

    private fun compileJavaSources(sources: Map<String, String>, classesDir: Path) {
        val sourceDir = Files.createTempDirectory("broadcast-java-src")
        for ((relativePath, content) in sources) {
            val file = sourceDir.resolve(relativePath)
            Files.createDirectories(file.parent)
            Files.writeString(file, content)
        }

        val compiler = ToolProvider.getSystemJavaCompiler()
        requireNotNull(compiler) { "当前测试环境缺少 JavaCompiler" }
        val javaFiles = Files.walk(sourceDir).use { stream ->
            stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".java") }.toList()
        }
        val fileManager = compiler.getStandardFileManager(null, null, null)
        fileManager.use { manager ->
            val units = manager.getJavaFileObjectsFromFiles(javaFiles.map { it.toFile() })
            val options = listOf("-g", "-d", classesDir.toString())
            val ok = compiler.getTask(null, manager, null, options, null, units).call()
            check(ok) { "测试样例编译失败" }
        }
    }

    private fun createJarFromClasses(classesDir: Path, jarPath: Path) {
        JarOutputStream(FileOutputStream(jarPath.toFile())).use { jar ->
            Files.walk(classesDir).use { stream ->
                stream.filter { Files.isRegularFile(it) }.forEach { file ->
                    val entryName = classesDir.relativize(file).toString().replace("\\", "/")
                    jar.putNextEntry(JarEntry(entryName))
                    Files.copy(file, jar)
                    jar.closeEntry()
                }
            }
        }
    }
}
