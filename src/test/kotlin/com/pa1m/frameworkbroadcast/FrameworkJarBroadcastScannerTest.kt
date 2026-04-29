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
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
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

        assertTrue(actions.matches("android.intent.action.BOOT_COMPLETED"))
        assertEquals(false, permissionMap.getValue("android.permission.NORMAL_PERMISSION").highProtection)
        assertEquals(true, permissionMap.getValue("android.permission.SIGNATURE_ONLY").highProtection)
    }

    @Test
    fun `protected broadcast parser supports plain action list with wildcard prefix and trims spaces`() {
        val dir = Files.createTempDirectory("broadcast-parser-plain")
        val protectedList = dir.resolve("package_dump.txt")
        Files.writeString(
            protectedList,
            """
              android.intent.action.BOOT_COMPLETED  
              com.huawei.hwid.*   
            """.trimIndent()
        )

        val matcher = ProtectedBroadcastParser.parse(protectedList)

        assertTrue(matcher.matches("android.intent.action.BOOT_COMPLETED"))
        assertTrue(matcher.matches("com.huawei.hwid.LOGIN"))
        assertTrue(matcher.matches("com.huawei.hwid.abc.def"))
        assertFalse(matcher.matches("com.huawei.hwidd.LOGIN"))
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
            protectedBroadcasts = ProtectedBroadcastMatcher(
                exactActions = setOf("android.intent.action.BOOT_COMPLETED"),
                prefixActions = emptySet(),
            ),
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
        assertEquals(listOf("com.test.CUSTOM"), record.actionList)
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
        assertTrue(scanResult.allRecords.isEmpty())
        assertEquals(1, scanResult.jarResults.size)
        assertEquals(JarScanStatus.SUCCESS, scanResult.jarResults.single().status)
        assertTrue("legacyNoPermission" in byMethod)
        assertTrue("mixedActionNeedsPermissionCheck" in byMethod)
        assertNull(byMethod.getValue("legacyNoPermission").broadcastPermission)
        assertNull(byMethod.getValue("legacyNoPermission").permissionProtectionLevel)
        assertEquals("normal", byMethod.getValue("mixedActionNeedsPermissionCheck").permissionProtectionLevel)
        assertEquals(
            listOf("com.test.CUSTOM_MIXED"),
            byMethod.getValue("mixedActionNeedsPermissionCheck").actionList
        )
        assertTrue(records.all { it.declaringClass.startsWith("com.huawei.") })
        G.reset()
    }

    @Test
    fun `scanner resolves actions when filter local is aliased before registerReceiver`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-alias")
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
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
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
            "com/huawei/sample/AliasRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class AliasRegister {
                    private final Context context = new DummyContext();
                    public void aliasFilter() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter original = new IntentFilter();
                        IntentFilter alias = original;
                        alias.addAction("com.test.ALIAS_ACTION");
                        context.registerReceiver(receiver, alias);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("alias.jar"))

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
        assertEquals(listOf("com.test.ALIAS_ACTION"), result.dangerousRecords.single().actionList)
        G.reset()
    }

    @Test
    fun `scanner merges actions across multiple filter aliases`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-multi-alias")
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
            "android/content/Context.java" to """
                package android.content;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
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
            "com/huawei/sample/AliasMergeRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class AliasMergeRegister {
                    private final Context context = new DummyContext();
                    public void aliasMerge() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter();
                        IntentFilter alias1 = filter;
                        IntentFilter alias2 = alias1;
                        alias1.addAction("com.test.ACTION_A");
                        alias2.addAction("com.test.ACTION_B");
                        context.registerReceiver(receiver, alias2);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("alias-merge.jar"))

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
        assertEquals(listOf("com.test.ACTION_A", "com.test.ACTION_B"), result.dangerousRecords.single().actionList)
        G.reset()
    }

    @Test
    fun `scanner keeps merged actions across simple branches`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-branches")
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
            "android/content/Context.java" to """
                package android.content;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
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
            "com/huawei/sample/BranchRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class BranchRegister {
                    private final Context context = new DummyContext();
                    public void branchAddAction(boolean chooseA) {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter();
                        if (chooseA) {
                            filter.addAction("com.test.BRANCH_A");
                        } else {
                            filter.addAction("com.test.BRANCH_B");
                        }
                        context.registerReceiver(receiver, filter);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("branch.jar"))

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
        assertEquals(listOf("com.test.BRANCH_A", "com.test.BRANCH_B"), result.dangerousRecords.single().actionList)
        G.reset()
    }

    @Test
    fun `scanner resolves permission and flags from static final fields and locals`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-consts")
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
                    public static final int RECEIVER_VISIBLE_TO_INSTANT_APPS = 0x1;
                    public static final int RECEIVER_EXPORTED = 0x2;
                    public static final int RECEIVER_NOT_EXPORTED = 0x4;
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
            "com/huawei/sample/FieldConstRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class FieldConstRegister {
                    private static final String NORMAL_PERMISSION = "android.permission.NORMAL_PERMISSION";
                    private static final int PRIVATE_FLAGS = Context.RECEIVER_NOT_EXPORTED | Context.RECEIVER_VISIBLE_TO_INSTANT_APPS;
                    private final Context context = new DummyContext();
                    public void fromStaticField() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.FIELD_PERMISSION");
                        String permission = NORMAL_PERMISSION;
                        context.registerReceiver(receiver, filter, permission, null);
                    }
                    public void fromStaticFlags() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.PRIVATE_FLAGS");
                        int flags = PRIVATE_FLAGS;
                        context.registerReceiver(receiver, filter, null, null, flags);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("field-consts.jar"))

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

        val allResult = FrameworkJarBroadcastScanner(scanAllReceivers = true, packagePrefix = "com.huawei.").scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, allResult.dangerousRecords.size)
        val dangerous = allResult.dangerousRecords.single()
        assertEquals("<com.huawei.sample.FieldConstRegister: void fromStaticField()>", dangerous.declaringMethod)
        assertEquals("android.permission.NORMAL_PERMISSION", dangerous.broadcastPermission)
        assertEquals("normal", dangerous.permissionProtectionLevel)
        assertTrue(allResult.allRecords.any { it.declaringMethod == "<com.huawei.sample.FieldConstRegister: void fromStaticFlags()>" })
        assertFalse(allResult.dangerousRecords.any { it.declaringMethod == "<com.huawei.sample.FieldConstRegister: void fromStaticFlags()>" })
        G.reset()
    }

    @Test
    fun `scanner resolves actions and permission from final instance string fields`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-instance-fields")
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
            "com/huawei/sample/InstanceFieldRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class InstanceFieldRegister {
                    public final String ACTION_FOO = "com.test.INSTANCE_FIELD_ACTION";
                    public final String NORMAL_PERMISSION = "android.permission.NORMAL_PERMISSION";
                    private final Context context = new DummyContext();
                    public void fromInstanceFields() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter();
                        filter.addAction(this.ACTION_FOO);
                        context.registerReceiver(receiver, filter, this.NORMAL_PERMISSION, null);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("instance-fields.jar"))

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

        val result = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.").scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, result.dangerousRecords.size)
        assertEquals(listOf("com.test.INSTANCE_FIELD_ACTION"), result.dangerousRecords.single().actionList)
        assertEquals("android.permission.NORMAL_PERMISSION", result.dangerousRecords.single().broadcastPermission)
        assertEquals("normal", result.dangerousRecords.single().permissionProtectionLevel)
        G.reset()
    }

    @Test
    fun `scanner resolves actions and permission from zero arg string helper methods`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-helper-methods")
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
            "com/huawei/sample/ActionDefs.java" to """
                package com.huawei.sample;
                public class ActionDefs {
                    public static String customAction() {
                        return "com.test.HELPER_ACTION";
                    }
                    public static String normalPermission() {
                        String value = "android.permission.NORMAL_PERMISSION";
                        return value;
                    }
                }
            """.trimIndent(),
            "com/huawei/sample/HelperMethodRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class HelperMethodRegister {
                    private final Context context = new DummyContext();
                    public void fromHelperMethods() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter(ActionDefs.customAction());
                        context.registerReceiver(receiver, filter, ActionDefs.normalPermission(), null);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("helper-methods.jar"))

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

        val result = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.").scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, result.dangerousRecords.size)
        assertEquals(listOf("com.test.HELPER_ACTION"), result.dangerousRecords.single().actionList)
        assertEquals("android.permission.NORMAL_PERMISSION", result.dangerousRecords.single().broadcastPermission)
        assertEquals("normal", result.dangerousRecords.single().permissionProtectionLevel)
        G.reset()
    }

    @Test
    fun `scanner resolves actions from this filter field and local alias`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-filter-field")
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
            "android/content/Context.java" to """
                package android.content;
                public abstract class Context {
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
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
            "com/huawei/sample/FieldFilterRegister.java" to """
                package com.huawei.sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class FieldFilterRegister {
                    private final Context context = new DummyContext();
                    private final IntentFilter filter = new IntentFilter();
                    public void directField() {
                        SampleReceiver receiver = new SampleReceiver();
                        this.filter.addAction("com.test.FIELD_DIRECT");
                        context.registerReceiver(receiver, this.filter);
                    }
                    public void aliasField() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter alias = this.filter;
                        alias.addAction("com.test.FIELD_ALIAS");
                        context.registerReceiver(receiver, alias);
                    }
                }
            """.trimIndent(),
        )

        compileJavaSources(sources, classesDir)
        createJarFromClasses(classesDir, jarDir.resolve("field-filter.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(permissionTxt, "All Permissions:\n")

        val result = FrameworkJarBroadcastScanner(packagePrefix = "com.huawei.").scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(2, result.dangerousRecords.size)
        val byMethod = result.dangerousRecords.associateBy { it.declaringMethod }
        assertEquals(
            listOf("com.test.FIELD_DIRECT"),
            byMethod.getValue("<com.huawei.sample.FieldFilterRegister: void directField()>").actionList
        )
        assertEquals(
            listOf("com.test.FIELD_ALIAS"),
            byMethod.getValue("<com.huawei.sample.FieldFilterRegister: void aliasField()>").actionList
        )
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
        assertTrue(result.allRecords.isEmpty())
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
        assertTrue(result.allRecords.isEmpty())
        assertTrue(result.dangerousRecords.any { it.declaringClass == "com.huawei.test.HuaweiRegister" })
        assertTrue(result.dangerousRecords.any { it.declaringClass == "sample.OtherRegister" })
        G.reset()
    }

    @Test
    fun `scan all receivers collects full dynamic broadcast list`() {
        val tempDir = Files.createTempDirectory("framework-broadcast-all-records")
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
                    public static final int RECEIVER_NOT_EXPORTED = 0x4;
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) { return null; }
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler) { return null; }
                    public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String permission, Handler scheduler, int flags) { return null; }
                }
            """.trimIndent(),
            "sample/SampleReceiver.java" to """
                package sample;
                import android.content.BroadcastReceiver;
                public class SampleReceiver extends BroadcastReceiver {}
            """.trimIndent(),
            "sample/DummyContext.java" to """
                package sample;
                import android.content.Context;
                public class DummyContext extends Context {}
            """.trimIndent(),
            "sample/RegisterCases.java" to """
                package sample;
                import android.content.Context;
                import android.content.IntentFilter;
                public class RegisterCases {
                    private final Context context = new DummyContext();
                    public void customOnly() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.CUSTOM_ONLY");
                        context.registerReceiver(receiver, filter);
                    }
                    public void protectedOnly() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("android.intent.action.BOOT_COMPLETED");
                        context.registerReceiver(receiver, filter);
                    }
                    public void signaturePermission() {
                        SampleReceiver receiver = new SampleReceiver();
                        IntentFilter filter = new IntentFilter("com.test.CUSTOM_SIG");
                        context.registerReceiver(receiver, filter, "android.permission.SIGNATURE_ONLY", null);
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
        createJarFromClasses(classesDir, jarDir.resolve("all-records.jar"))

        val protectedXml = tempDir.resolve("proaction.xml")
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        val permissionTxt = tempDir.resolve("permission.txt")
        Files.writeString(
            permissionTxt,
            """
            All Permissions:
            + permission:android.permission.SIGNATURE_ONLY
              protectionLevel:signature|role
            """.trimIndent()
        )

        val result = FrameworkJarBroadcastScanner(scanAllReceivers = true).scan(
            jarDir,
            ProtectedBroadcastParser.parse(protectedXml),
            PermissionDefinitionsParser.parse(permissionTxt),
        )

        assertEquals(1, result.dangerousRecords.size)
        assertEquals(4, result.allRecords.size)
        assertTrue(result.allRecords.any { it.actionList == listOf("com.test.CUSTOM_ONLY") })
        assertTrue(result.allRecords.any { it.actionList == listOf("android.intent.action.BOOT_COMPLETED") })
        assertTrue(result.allRecords.any { it.broadcastPermission == "android.permission.SIGNATURE_ONLY" })
        assertTrue(result.allRecords.any { it.actionList == listOf("com.test.PRIVATE") })
        G.reset()
    }

    @Test
    fun `artifact discovery detects class jar dex jar and apk`() {
        val tempDir = Files.createTempDirectory("artifact-discovery")
        val classJar = tempDir.resolve("sample-class.jar")
        val dexJar = tempDir.resolve("sample-dex.jar")
        val apk = tempDir.resolve("sample.apk")
        createZipArchive(classJar, mapOf("Sample.class" to "abc".toByteArray(StandardCharsets.UTF_8)))
        createZipArchive(dexJar, mapOf("classes.dex" to "dex".toByteArray(StandardCharsets.UTF_8)))
        createZipArchive(apk, mapOf("classes.dex" to "dex".toByteArray(StandardCharsets.UTF_8)))

        val artifacts = ArtifactDiscovery.collect(tempDir, InputTypeMode.AUTO)

        val byName = artifacts.associateBy { Path.of(it.path).fileName.toString() }
        assertEquals(ArtifactType.CLASS_JAR, byName.getValue("sample-class.jar").artifactType)
        assertEquals(ArtifactType.DEX_JAR, byName.getValue("sample-dex.jar").artifactType)
        assertEquals(ArtifactType.APK, byName.getValue("sample.apk").artifactType)
    }

    @Test
    fun `scanner supports dex jar and apk inputs`() {
        val androidPlatforms = Path.of("/Users/pa1m/workspace/appshark/config/tools/platforms")
        val androidJar = Path.of(ArtifactDiscovery.resolveAndroidJar(androidPlatforms)!!)
        val tempDir = Files.createTempDirectory("framework-broadcast-dex-apk")
        val classesDir = tempDir.resolve("classes")
        Files.createDirectories(classesDir)
        val samplesDir = tempDir.resolve("samples")
        Files.createDirectories(samplesDir)

        val sources = mapOf(
            "com/huawei/sample/RegisterCases.java" to """
                package com.huawei.sample;
                import android.content.BroadcastReceiver;
                import android.content.Context;
                import android.content.IntentFilter;
                public class RegisterCases {
                    public void customNormal(Context context, BroadcastReceiver receiver) {
                        IntentFilter filter = new IntentFilter("com.test.DEX_CUSTOM");
                        context.registerReceiver(receiver, filter, "android.permission.NORMAL_PERMISSION", null);
                    }
                    public void protectedOnly(Context context, BroadcastReceiver receiver) {
                        IntentFilter filter = new IntentFilter("android.intent.action.BOOT_COMPLETED");
                        context.registerReceiver(receiver, filter);
                    }
                }
            """.trimIndent()
        )

        compileJavaSources(sources, classesDir, classpath = listOf(androidJar))
        val inputJar = samplesDir.resolve("input-classes.jar")
        createJarFromClasses(classesDir, inputJar)
        val dexOutputDir = samplesDir.resolve("dex-out")
        runD8(inputJar, androidJar, dexOutputDir)
        val dexJar = samplesDir.resolve("sample-dex.jar")
        val apk = samplesDir.resolve("sample.apk")
        val classesDex = dexOutputDir.resolve("classes.dex")
        createZipArchive(dexJar, mapOf("classes.dex" to Files.readAllBytes(classesDex)))
        createZipArchive(
            apk,
            mapOf(
                "classes.dex" to Files.readAllBytes(classesDex),
                "AndroidManifest.xml" to """
                    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.huawei.sample">
                      <application />
                    </manifest>
                """.trimIndent().toByteArray(StandardCharsets.UTF_8)
            )
        )

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

        val scanner = FrameworkJarBroadcastScanner(scanAllReceivers = true, packagePrefix = "com.huawei.")
        val protectedActions = ProtectedBroadcastParser.parse(protectedXml)
        val permissions = PermissionDefinitionsParser.parse(permissionTxt)

        val dexResult = scanner.scan(
            inputPath = dexJar,
            inputType = InputTypeMode.DEX_JAR,
            protectedBroadcasts = protectedActions,
            permissions = permissions,
            androidPlatforms = androidPlatforms,
        )
        val apkResult = scanner.scan(
            inputPath = apk,
            inputType = InputTypeMode.APK,
            protectedBroadcasts = protectedActions,
            permissions = permissions,
            androidPlatforms = androidPlatforms,
        )

        assertEquals(1, dexResult.dangerousRecords.size)
        assertEquals(2, dexResult.allRecords.size)
        assertEquals(listOf("com.test.DEX_CUSTOM"), dexResult.dangerousRecords.single().actionList)
        assertEquals("normal", dexResult.dangerousRecords.single().permissionProtectionLevel)
        assertEquals(ArtifactType.DEX_JAR, dexResult.jarResults.single().artifactType)

        assertEquals(1, apkResult.dangerousRecords.size)
        assertEquals(2, apkResult.allRecords.size)
        assertEquals(listOf("com.test.DEX_CUSTOM"), apkResult.dangerousRecords.single().actionList)
        assertEquals(ArtifactType.APK, apkResult.jarResults.single().artifactType)
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
        assertFalse(defaultAll.scanAllReceivers)
        assertEquals(jarDir.toString(), withPrefix.inputPath)
        assertEquals(InputTypeMode.AUTO, withPrefix.inputType)
        assertEquals(1, withPrefix.jobs)
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
    fun `parse args supports input type android platforms and jobs`() {
        val tempDir = Files.createTempDirectory("scan-args-new")
        val apk = tempDir.resolve("sample.apk")
        val protectedXml = tempDir.resolve("proaction.xml")
        val permissions = tempDir.resolve("permission.txt")
        val platforms = tempDir.resolve("platforms")
        Files.write(apk, byteArrayOf(0x50, 0x4b, 0x03, 0x04))
        Files.createDirectories(platforms)
        Files.writeString(protectedXml, """<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />""")
        Files.writeString(permissions, "All Permissions:\n")

        val parsed = parseArgs(
            arrayOf(
                "--input-path", apk.toString(),
                "--input-type", "apk",
                "--protected-broadcasts", protectedXml.toString(),
                "--permissions", permissions.toString(),
                "--android-platforms", platforms.toString(),
                "-j", "4",
            )
        )

        assertEquals(apk.toString(), parsed.inputPath)
        assertEquals(InputTypeMode.APK, parsed.inputType)
        assertEquals(platforms.toString(), parsed.androidPlatforms)
        assertEquals(4, parsed.jobs)
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
            allRecords = emptyList(),
            jarResults = listOf(
                JarScanResult(
                    jarPath = "/tmp/sample.jar",
                    status = JarScanStatus.SUCCESS,
                    dangerousRecords = records,
                    allRecords = emptyList(),
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
        assertTrue(summary.contains("\"all_dynamic_broadcasts\":0"))
        assertTrue(summary.contains("\"success_jars\":1"))
        assertTrue(partialJsonl.isEmpty())
        assertTrue(failedJsonl.isEmpty())
        assertFalse(Files.exists(outDir.resolve("all_dynamic_broadcasts.jsonl")))
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
            override fun scanSingleArtifact(
                artifact: ScanArtifact,
                environment: ScanEnvironment,
                protectedBroadcasts: ProtectedBroadcastMatcher,
                permissions: Map<String, PermissionMeta>,
            ): JarScanResult {
                return when (Path.of(artifact.path).fileName.toString()) {
                    "good.jar" -> JarScanResult(artifact.path, JarScanStatus.SUCCESS, emptyList(), emptyList())
                    "partial.jar" -> JarScanResult(
                        artifact.path,
                        JarScanStatus.PARTIAL,
                        listOf(dangerous),
                        listOf(
                            AllDynamicBroadcastRecord(
                                jarPath = partialJar.toString(),
                                declaringClass = "sample.Partial",
                                declaringMethod = "<sample.Partial: void run()>",
                                sourceLine = 7,
                                actionList = listOf("com.test.PARTIAL"),
                                broadcastPermission = null,
                                permissionProtectionLevel = null,
                                evidence = "invoke"
                            )
                        ),
                        "RuntimeException",
                        "boom after partial results",
                        artifactType = artifact.artifactType,
                    )
                    else -> JarScanResult(
                        artifact.path,
                        JarScanStatus.FAILED,
                        emptyList(),
                        emptyList(),
                        "IOException",
                        "cannot parse jar",
                        artifactType = artifact.artifactType,
                    )
                }
            }
        }

        val result = scanner.scan(
            inputPath = jarDir,
            inputType = InputTypeMode.CLASS_JAR,
            protectedBroadcasts = ProtectedBroadcastMatcher(emptySet(), emptySet()),
            permissions = emptyMap(),
        )

        assertEquals(1, result.dangerousRecords.size)
        assertEquals(1, result.allRecords.size)
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
            jarResult = JarScanResult("/tmp/a.jar", JarScanStatus.SUCCESS, emptyList(), emptyList()),
            dangerousTotal = 0,
        )
        reporter.onJarFinished(
            currentIndex = 2,
            totalJars = 2,
            jarResult = JarScanResult("/tmp/b.jar", JarScanStatus.PARTIAL, emptyList(), emptyList(), "RuntimeException", "boom"),
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
            allRecords = listOf(
                AllDynamicBroadcastRecord(
                    jarPath = "/tmp/partial.jar",
                    declaringClass = "sample.Partial",
                    declaringMethod = "<sample.Partial: void run()>",
                    sourceLine = 7,
                    actionList = listOf("com.test.PARTIAL"),
                    broadcastPermission = null,
                    permissionProtectionLevel = null,
                    evidence = "invoke"
                )
            ),
            jarResults = listOf(
                JarScanResult("/tmp/good.jar", JarScanStatus.SUCCESS, emptyList(), emptyList()),
                JarScanResult(
                    "/tmp/partial.jar",
                    JarScanStatus.PARTIAL,
                    listOf(dangerous),
                    listOf(
                        AllDynamicBroadcastRecord(
                            jarPath = "/tmp/partial.jar",
                            declaringClass = "sample.Partial",
                            declaringMethod = "<sample.Partial: void run()>",
                            sourceLine = 7,
                            actionList = listOf("com.test.PARTIAL"),
                            broadcastPermission = null,
                            permissionProtectionLevel = null,
                            evidence = "invoke"
                        )
                    ),
                    "RuntimeException",
                    "boom"
                ),
                JarScanResult("/tmp/failed.jar", JarScanStatus.FAILED, emptyList(), emptyList(), "IOException", "broken")
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
        assertTrue(summary.contains("\"all_dynamic_broadcasts\":1"))
        assertTrue(partialJsonl.contains("\"status\":\"partial\""))
        assertTrue(partialJsonl.contains("\"jar_path\":\"/tmp/partial.jar\""))
        assertTrue(failedJsonl.contains("\"status\":\"failed\""))
        assertTrue(failedJsonl.contains("\"jar_path\":\"/tmp/failed.jar\""))
        assertTrue(errorLog.contains("jar_path: /tmp/partial.jar"))
        assertTrue(errorLog.contains("jar_path: /tmp/failed.jar"))
        assertFalse(errorLog.contains("jar_path: /tmp/good.jar"))
    }

    @Test
    fun `report writer emits all dynamic broadcast files when requested`() {
        val outDir = Files.createTempDirectory("broadcast-all-report")
        val dangerous = DangerousBroadcastRecord(
            jarPath = "/tmp/sample.jar",
            declaringClass = "sample.RegisterCases",
            declaringMethod = "<sample.RegisterCases: void customOnly()>",
            sourceLine = 11,
            actionList = listOf("com.test.CUSTOM"),
            broadcastPermission = null,
            permissionProtectionLevel = null,
            evidence = "invoke"
        )
        val allRecords = listOf(
            AllDynamicBroadcastRecord(
                jarPath = dangerous.jarPath,
                declaringClass = dangerous.declaringClass,
                declaringMethod = dangerous.declaringMethod,
                sourceLine = dangerous.sourceLine,
                actionList = dangerous.actionList,
                broadcastPermission = dangerous.broadcastPermission,
                permissionProtectionLevel = dangerous.permissionProtectionLevel,
                evidence = dangerous.evidence
            ),
            AllDynamicBroadcastRecord(
                jarPath = "/tmp/sample.jar",
                declaringClass = "sample.RegisterCases",
                declaringMethod = "<sample.RegisterCases: void protectedOnly()>",
                sourceLine = 17,
                actionList = listOf("android.intent.action.BOOT_COMPLETED"),
                broadcastPermission = null,
                permissionProtectionLevel = null,
                evidence = "invoke"
            )
        )
        val scanResult = ScanResult(
            dangerousRecords = listOf(dangerous),
            allRecords = allRecords,
            jarResults = listOf(
                JarScanResult(
                    jarPath = "/tmp/sample.jar",
                    status = JarScanStatus.SUCCESS,
                    dangerousRecords = listOf(dangerous),
                    allRecords = allRecords,
                )
            )
        )

        ReportWriter.write(outDir, scanResult, writeAllRecords = true)

        val allJsonl = Files.readString(outDir.resolve("all_dynamic_broadcasts.jsonl"))
        val allMarkdown = Files.readString(outDir.resolve("all_dynamic_broadcasts.md"))
        val summary = Files.readString(outDir.resolve("scan_summary.json"))

        assertTrue(allJsonl.contains("\"action_list\":[\"android.intent.action.BOOT_COMPLETED\"]"))
        assertTrue(allMarkdown.contains("All Dynamic Broadcasts"))
        assertTrue(summary.contains("\"all_dynamic_broadcasts\":2"))
    }

    private fun compileJavaSources(
        sources: Map<String, String>,
        classesDir: Path,
        classpath: List<Path> = emptyList(),
    ) {
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
            val options = mutableListOf("-g", "-d", classesDir.toString())
            if (classpath.isNotEmpty()) {
                options += listOf("-classpath", classpath.joinToString(File.pathSeparator) { it.toString() })
            }
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

    private fun createZipArchive(zipPath: Path, entries: Map<String, ByteArray>) {
        ZipOutputStream(Files.newOutputStream(zipPath)).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
    }

    private fun runD8(inputJar: Path, androidJar: Path, outputDir: Path) {
        Files.createDirectories(outputDir)
        val r8Jar = findR8Jar()
        val javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val process = ProcessBuilder(
            listOf(
                javaExecutable,
                "-cp",
                r8Jar,
                "com.android.tools.r8.D8",
                "--lib",
                androidJar.toString(),
                "--min-api",
                "21",
                "--output",
                outputDir.toString(),
                inputJar.toString(),
            )
        )
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.readBytes().toString(StandardCharsets.UTF_8)
        val exitCode = process.waitFor()
        check(exitCode == 0) { "D8 执行失败: $output" }
        check(Files.isRegularFile(outputDir.resolve("classes.dex"))) { "D8 未生成 classes.dex: $output" }
    }

    private fun findR8Jar(): String {
        return System.getProperty("java.class.path")
            .split(File.pathSeparator)
            .firstOrNull { it.contains("r8", ignoreCase = true) && it.endsWith(".jar") }
            ?: error("测试运行时 classpath 中未找到 r8 jar")
    }
}
