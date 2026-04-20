package net.bytedance.security.app.pathfinder.testdata;

public class ExportedComponentVuln {

    // Vulnerable: sends SMS using data from Intent
    public void sendSmsFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String phoneNumber = intent.getStringExtra("phone");
        String message = intent.getStringExtra("message");
        WebViewTestStubs.SmsManager sms = WebViewTestStubs.SmsManager.getDefault();
        sms.sendTextMessage(phoneNumber, null, message, null, null);  // SINK
    }

    // Vulnerable: executes command from Intent
    public void execFromIntent(WebViewTestStubs.Activity activity) throws Exception {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String cmd = intent.getStringExtra("command");
        Runtime.getRuntime().exec(cmd);  // SINK
    }

    // Vulnerable: queries content provider with untrusted URI
    public void queryFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String uriStr = intent.getStringExtra("content_uri");
        WebViewTestStubs.ContentResolver resolver = activity.getContentResolver();
        resolver.query(uriStr, null, null, null, null);  // SINK
    }

    // Fixed: validates command against whitelist
    public void execFromIntentFixed(WebViewTestStubs.Activity activity) throws Exception {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String cmd = intent.getStringExtra("command");
        if (cmd != null && cmd.matches("^(ls|pwd|whoami)$")) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    public void f() throws Exception {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        sendSmsFromIntent(activity);
        execFromIntent(activity);
        queryFromIntent(activity);
        execFromIntentFixed(activity);
    }
}
