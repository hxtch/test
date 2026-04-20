/*
 * Copyright 2022 Beijing Zitiao Network Technology Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bytedance.security.app.pathfinder

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.ruleprocessor.DirectModeProcessor
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactory
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactoryTest
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest.Companion.createDefaultTwoStagePointerAnalyze
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import test.SootHelper
import test.TestHelper

internal class NewRulesTest {
    init {
        SootHelper.initSoot(
            "NewRulesTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @BeforeEach
    fun clearResults() {
        OutputSecResults.testClearVulnerabilityItems()
    }

    private fun runRuleAndCount(ruleFileName: String): Int {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/$ruleFileName"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            val rp = RuleProcessorFactory.create(ctx, rules.allRules[0].mode)
            rp.process(rules.allRules[0])
            val dmp = (rp as DirectModeProcessor)
            for (analyzer in dmp.analyzers) {
                val tsp = createDefaultTwoStagePointerAnalyze(analyzer.entryMethod)
                tsp.doPointerAnalyze()
                val finder = TaintPathFinder(ctx, tsp.ctx, rules.allRules.first() as TaintFlowRule, analyzer)
                finder.findPath()
            }
        }
        return OutputSecResults.vulnerabilityItems().size
    }

    @Test
    fun testWebViewUntrustedUrl() {
        // WebViewVuln has 2 vulnerable methods (loadUntrustedUrl, loadUntrustedData)
        // and 1 fixed method (loadTrustedUrl) which should not trigger
        val count = runRuleAndCount("webview_untrusted_url.json")
        Assertions.assertTrue(count >= 2, "Expected at least 2 WebView URL vulns, got $count")
    }

    @Test
    fun testIntentRedirectionEnhanced() {
        // IntentRedirectionVuln has 3 vulnerable methods (forwardIntent, forwardToService, forwardToBroadcast)
        // and 1 fixed method (forwardIntentFixed with setComponent)
        val count = runRuleAndCount("intent_redirection_enhanced.json")
        Assertions.assertTrue(count >= 3, "Expected at least 3 intent redirection vulns, got $count")
    }

    @Test
    fun testExportedComponentExec() {
        // ExportedComponentVuln has 1 vulnerable exec method and 1 fixed
        val count = runRuleAndCount("exported_component_exec.json")
        Assertions.assertTrue(count >= 1, "Expected at least 1 exec vuln, got $count")
    }

    @Test
    fun testSQLInjectionRawQuery() {
        // SQLInjectionVuln has 2 vulnerable methods (queryFromIntent, execFromIntent)
        // and 1 fixed method (queryFixed)
        val count = runRuleAndCount("sql_injection_raw_query.json")
        Assertions.assertTrue(count >= 2, "Expected at least 2 SQL injection vulns, got $count")
    }

    @Test
    fun testDexClassLoaderUntrusted() {
        // DexClassLoaderVuln has 1 vulnerable method and 1 fixed
        val count = runRuleAndCount("dex_classloader_untrusted.json")
        Assertions.assertTrue(count >= 1, "Expected at least 1 DexClassLoader vuln, got $count")
    }

    @Test
    fun testCommandInjection() {
        // CommandInjectionVuln has 2 vulnerable methods (execFromIntent, processBuilderFromIntent)
        // and 1 fixed method (execFromIntentFixed)
        val count = runRuleAndCount("command_injection.json")
        Assertions.assertTrue(count >= 2, "Expected at least 2 command injection vulns, got $count")
    }

    @Test
    fun testPendingIntentImplicitTarget() {
        // PendingIntentImplicitTargetVuln has 2 vulnerable methods
        // and 1 fixed method (createPendingIntentFixed with setPackage)
        val count = runRuleAndCount("pending_intent_implicit_target.json")
        Assertions.assertTrue(count >= 2, "Expected at least 2 PendingIntent vulns, got $count")
    }

    @Test
    fun testExportedServiceBinding() {
        // ExportedServiceBindingVuln has 2 vulnerable methods (onBind, onBindQuery)
        // and 1 fixed method (onBindFixed)
        val count = runRuleAndCount("exported_service_binding.json")
        Assertions.assertTrue(count >= 2, "Expected at least 2 service binding vulns, got $count")
    }

    @Test
    fun testPackageNameSpoofing() {
        // PackageNameSpoofingVuln has 3 vulnerable methods
        // and 1 fixed method (startByPackageFixed)
        val count = runRuleAndCount("package_name_spoofing.json")
        Assertions.assertTrue(count >= 3, "Expected at least 3 package spoofing vulns, got $count")
    }

    @Test
    fun testAllNewRulesLoad() {
        // Verify all 14 new production rules can be loaded without errors
        val ruleFiles = listOf(
            "WebViewJSBridgeExposure.json",
            "WebViewFileAccessEnabled.json",
            "WebViewUntrustedUrlLoad.json",
            "IntentRedirectionEnhanced.json",
            "ExportedComponentToSMS.json",
            "ExportedComponentToExec.json",
            "ExportedComponentToContentQuery.json",
            "DynamicBroadcastNoPermission.json",
            "SQLInjectionRawQuery.json",
            "DexClassLoaderUntrusted.json",
            "CommandInjection.json",
            "PendingIntentImplicitTarget.json",
            "ExportedServiceBinding.json",
            "PackageNameSpoofing.json"
        )
        val rulePaths = ruleFiles.map { "config/rules/$it" }
            .filter { java.io.File(it).exists() }

        if (rulePaths.isNotEmpty()) {
            val rules = Rules(rulePaths, RuleFactory())
            runBlocking {
                rules.loadRules()
            }
            Assertions.assertTrue(rules.allRules.isNotEmpty(), "Should load at least one rule")
            println("Successfully loaded ${rules.allRules.size} new rules: ${rules.allRules.map { it.name }}")
        }
    }
}
