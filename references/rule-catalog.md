# AppShark Rule Catalog for Real Vulnerability Scan

## Taint-Flow Rules (SliceMode)

| Rule | Category | Detection target |
| --- | --- | --- |
| `WebViewUntrustedUrlLoad` | `WebViewRisk` | Untrusted URL or Intent data flowing into `WebView.loadUrl`, `loadData`, or `loadDataWithBaseURL` in exported components |
| `IntentRedirectionEnhanced` | `IntentRedirection` | Nested `Intent` objects forwarded from exported components into `startActivity`, `startService`, `startForegroundService`, `sendBroadcast`, `sendOrderedBroadcast`, or `setResult` without effective target validation |
| `ExportedComponentToSMS` | `ExportedComponentRisk` | Intent-controlled data from exported components reaching `SmsManager.sendTextMessage` or `sendMultipartTextMessage` |
| `ExportedComponentToExec` | `ExportedComponentRisk` | Intent-controlled data from exported components reaching `Runtime.exec` or `ProcessBuilder.start` |
| `ExportedComponentToContentQuery` | `ExportedComponentRisk` | Intent-controlled URI or string input from exported components reaching `ContentResolver.query`, `insert`, `update`, or `delete` |
| `ContentProviderPathTraversal` | `Provider` | `ContentProvider.openFile` URI input reaching `ParcelFileDescriptor.open` without canonicalization or traversal filtering |
| `unZipSlip` | `FileRisk` | `ZipEntry.getName()` data reaching file creation APIs such as `FileWriter` or `FileOutputStream` without traversal checks |
| `PendingIntentMutable` | `PendingIntent` | Mutable or insufficiently constrained `PendingIntent` creation from tainted `Intent` instances |
| `IntentRedirectionBabyVersion` | `IntentRedirection` | Basic nested `Intent` forwarding into activity launch APIs |

## API Presence Rules (APIMode)

| Rule | Category | Detection target |
| --- | --- | --- |
| `WebViewJSBridgeExposure` | `WebViewRisk` | Calls to `WebView.addJavascriptInterface` exposing native methods to JavaScript |
| `WebViewFileAccessEnabled` | `WebViewRisk` | Calls to `WebSettings.setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` |
| `DynamicBroadcastNoPermission` | `ExportedComponentRisk` | Dynamic `registerReceiver` usage without a permission gate |
| `MAC` | `ComplianceInfo` | Calls that retrieve MAC addresses from Bluetooth, Wi-Fi, or network interfaces |

## Compliance Rules

| Rule key | Declared name | Category | Detection target |
| --- | --- | --- | --- |
| `broadcastIMEI` | `IMEI_SendBroadcast` | `ComplianceInfo` | IMEI/device ID data flowing into broadcast APIs |
| `logSerial` | `serial_Log` | `ComplianceInfo` | `Build.SERIAL` flowing into Android logging APIs |

## Common Sanitizers / Validation Signals

- `WebViewUntrustedUrlLoad`: `urlWhitelist`, `uriHostCheck`
- `IntentRedirectionEnhanced`: `setComponent`, `setClassName`, `setPackage`, `setClass`, `resolveActivity`, `removeFlags`
- `ExportedComponentToSMS`: `checkCallingPermission`
- `ExportedComponentToExec`: regex-style input validation via `String.matches`
- `ExportedComponentToContentQuery`: authority comparison via `Uri.getAuthority` and `String.equals`
- `ContentProviderPathTraversal`: `getCanonicalFile`, traversal checks such as `contains("..")`
- `unZipSlip`: canonical path checks and `..` detection
- `PendingIntentMutable`: immutable flags and explicit component/package binding
