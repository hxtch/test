---
name: android-appshark-real-vuln-scan
description: End-to-end Android APK vulnerability scanning with AppShark static analysis + LLM verdict review. Scans APK with taint-analysis rules, extracts evidence from scan results, then uses LLM to judge whether each finding is a real vulnerability, likely false positive, or needs manual review.
---

# Android AppShark Real Vulnerability Scan

## When to Use This Skill

Use this skill when the user asks to:
- Scan an Android APK for real vulnerabilities (not just rule matches)
- Run AppShark and interpret the results with LLM reasoning
- Audit an Android app's security with evidence-based verdicts
- Distinguish real vulnerabilities from false positives in static analysis results

## Prerequisites

- JDK 11 on PATH
- Target APK file accessible on disk
- AppShark JAR and rules are bundled in this skill at `{SKILL_ROOT}/appshark/`

## Tool Layout

```
{SKILL_ROOT}/
├── appshark/
│   ├── build/libs/AppShark-0.1.2-all.jar   # Pre-built scanner
│   ├── config/rules/                         # JSON rule files
│   ├── config/llm-verdict-schema.json        # Verdict schema
│   ├── config/llm-verdict-samples/           # Sample verdicts
│   └── ...                                   # Full AppShark project
└── SKILL.md
```

**Note on rules**: Rules are plain JSON files under `config/rules/`. Adding or editing a rule JSON does **not** require rebuilding the JAR. Only changes to Kotlin/Java source code require recompilation.

## Workflow

### Phase 1: Configure and Run AppShark

1. Create a scan config for the target APK:
   ```json5
   {
     "apkPath": "<path-to-apk>",
     "out": "out",
     "rules": "<comma-separated rule names or empty for all>",
     "javaSource": true
   }
   ```
   Write this to a temp config file, e.g., `/tmp/appshark-scan-config.json5`.

2. Run AppShark using the bundled JAR:
   ```bash
   cd {SKILL_ROOT}/appshark && java -jar build/libs/AppShark-0.1.2-all.jar /tmp/appshark-scan-config.json5
   ```

3. Wait for completion. Results will be in `{SKILL_ROOT}/appshark/out/results.json`.

### Phase 2: Extract Evidence from Results

1. Read `{SKILL_ROOT}/appshark/out/results.json`.
2. For each finding in `SecurityInfo.<category>.<ruleName>.vulners[]`:
   - Extract `details.Source`, `details.Sink`, `details.target` (taint path), `details.entryMethod`, `details.position`
   - Extract `hash` as finding_id
3. From `BasicInfo.ComponentsInfo`, extract manifest context:
   - Whether the component is exported
   - Permission requirements
   - Intent filters
4. Construct a verdict input object per finding following the schema in `{SKILL_ROOT}/appshark/config/llm-verdict-schema.json`.

### Phase 3: LLM Verdict Review

For EACH finding, apply the following judgment protocol:

#### Required Checks (ALL must be evaluated):
1. **Reachability**: Is the source actually controllable by an external attacker?
   - Is the component exported? With or without permission?
   - What protection level does the permission have?
2. **Taint Path Validity**: Does the taint path make logical sense?
   - Are there implicit sanitizers not captured by static analysis?
   - Could the path be broken by runtime conditions?
3. **Sanitizer Coverage**: Were any sanitizers detected?
   - If yes, is the sanitizer sufficient to prevent exploitation?
   - If no, is there evidence of custom validation the rules missed?
4. **Exploitability**: Can an attacker actually exploit this?
   - Is the sink dangerous enough to cause real harm?
   - Are there OS-level mitigations (e.g., SELinux, app sandbox)?
5. **False Positive Indicators**:
   - Internal-only component usage patterns
   - Hard-coded safe values in the path
   - Test/debug code that won't ship in production

#### Verdict Rules:
- `real_vulnerability`: All of: (1) attacker-reachable source, (2) valid taint path to dangerous sink, (3) no effective sanitizer, (4) exploitable impact
- `likely_false_positive`: Any of: (1) signature-level permission blocks access, (2) sanitizer effectively prevents exploitation, (3) source is not attacker-controllable, (4) sink is benign
- `needs_manual_review`: Evidence is ambiguous or insufficient. DEFAULT when uncertain.

#### CRITICAL RULES:
- NEVER judge `real_vulnerability` solely because a rule matched. Always verify reachability + exploitability.
- NEVER fabricate evidence. Only cite what's in the scan results and manifest.
- When in doubt, output `needs_manual_review` with specific follow-up actions.
- Confidence < 0.6 MUST result in `needs_manual_review`.

### Phase 4: Generate Report

Output two files:

1. **Final Report** (`appshark-vuln-report.md`): Contains ONLY `real_vulnerability` and `needs_manual_review` findings.
2. **Process Data** (`process-data/false-positives.json`): Contains all `likely_false_positive` findings with reasoning for audit and rule tuning.

#### Final Report (`appshark-vuln-report.md`) structure:

```markdown
# AppShark Vulnerability Report

## Scan Metadata
- **APK Path**: ...
- **Scan Timestamp**: ...
- **Rules Used**: ...
- **Total Findings (after filtering)**: ...

## Verdicts Summary
| Verdict | Count |
|---------|-------|
| Real Vulnerability | 0 |
| Needs Manual Review | 0 |

*(Likely False Positives are excluded from this report; see `process-data/false-positives.json`)*

## Findings

### 1. [Rule Name] - [verdict]
**Confidence**: [0.0-1.0]

**Source**: ...

**Sink**: ...

**Taint Path**:
1. ...
2. ...

**Evidence For**:
- ...

**Evidence Against**:
- ...

**Reasoning**: ...

**Required Follow-up** (if needs_manual_review):
- ...

---
```

#### Process Data (`process-data/false-positives.json`) structure:

```json
{
  "process_metadata": {
    "scan_timestamp": "...",
    "total_false_positives": 0,
    "note": "These findings were filtered out as likely false positives. Retain for rule tuning and audit trails."
  },
  "false_positives": [
    {
      "rule_name": "...",
      "finding_id": "...",
      "source": "...",
      "sink": "...",
      "confidence": 0.0,
      "reasoning": "Why this was judged as likely false positive",
      "evidence_against": ["..."]
    }
  ]
}
```

## Output Format

The final report MUST:
1. Clearly separate "rule matches" from "verified vulnerabilities"
2. Include evidence chains for every verdict
3. List all `needs_manual_review` items with specific follow-up actions
4. Never claim certainty without sufficient evidence

## Available Rules

### Taint-Flow Rules (SliceMode)
- `WebViewUntrustedUrlLoad` - External URL → WebView.loadUrl
- `IntentRedirectionEnhanced` - Nested Intent → startActivity/startService/sendBroadcast
- `ExportedComponentToSMS` - Intent input → SmsManager.sendTextMessage
- `ExportedComponentToExec` - Intent input → Runtime.exec
- `ExportedComponentToContentQuery` - Intent input → ContentResolver.query
- `SQLInjectionRawQuery` - Untrusted input → SQLiteDatabase.rawQuery / execSQL
- `DexClassLoaderUntrusted` - Untrusted path → DexClassLoader loading malicious code
- `CommandInjection` - Untrusted input → Runtime.exec / ProcessBuilder
- `PendingIntentImplicitTarget` - Untrusted Intent → PendingIntent without explicit target
- `ExportedServiceBinding` - Exported Service onBind receives untrusted input forwarded to dangerous sinks
- `PackageNameSpoofing` - Untrusted input controls Intent package/class name without signature verification
- `ContentProviderPathTraversal` - Uri path → File open (existing)
- `unZipSlip` - ZipEntry.getName → FileOutputStream (existing)
- `PendingIntentMutable` - Implicit Intent → PendingIntent.get* (existing)
- `IntentRedirectionBabyVersion` - Parcelable extra → startActivity (existing)

### API Presence Rules (APIMode)
- `WebViewJSBridgeExposure` - addJavascriptInterface usage
- `WebViewFileAccessEnabled` - setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs
- `DynamicBroadcastNoPermission` - registerReceiver without permission
- `mac` - MAC address access (existing)

### Compliance Rules
- `broadcastIMEI` - IMEI sent via broadcast (existing)
- `logSerial` - Serial number logged (existing)

## References

- Verdict schema: `{SKILL_ROOT}/appshark/config/llm-verdict-schema.json`
- Sample verdicts: `{SKILL_ROOT}/appshark/config/llm-verdict-samples/`
  - `sample-real-vulnerability.json` - single finding verdict example
  - `sample-false-positive.json` - false positive verdict example
  - `sample-needs-review.json` - ambiguous finding verdict example
  - `sample-insecurebankv2-scan.json` - full end-to-end scan results (3 findings)
- Rule files: `{SKILL_ROOT}/appshark/config/rules/`
- Rule authoring guide: `{SKILL_ROOT}/appshark/doc/en/how_to_write_rules.md`
