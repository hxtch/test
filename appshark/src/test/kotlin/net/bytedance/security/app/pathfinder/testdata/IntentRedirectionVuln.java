package net.bytedance.security.app.pathfinder.testdata;

public class IntentRedirectionVuln {

    // Vulnerable: forwards nested Intent without validation
    public void forwardIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        Object nested = intent.getParcelableExtra("next_intent");
        if (nested instanceof WebViewTestStubs.Intent) {
            activity.startActivity((WebViewTestStubs.Intent) nested);  // SINK
        }
    }

    // Fixed: sets explicit component before forwarding
    public void forwardIntentFixed(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        Object nested = intent.getParcelableExtra("next_intent");
        if (nested instanceof WebViewTestStubs.Intent) {
            WebViewTestStubs.Intent forwardIntent = (WebViewTestStubs.Intent) nested;
            forwardIntent.setComponent("com.example.SafeActivity");
            activity.startActivity(forwardIntent);
        }
    }

    // Vulnerable: forwards to service
    public void forwardToService(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        Object nested = intent.getParcelableExtra("service_intent");
        if (nested instanceof WebViewTestStubs.Intent) {
            activity.startService((WebViewTestStubs.Intent) nested);  // SINK
        }
    }

    // Vulnerable: forwards to broadcast
    public void forwardToBroadcast(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        Object nested = intent.getParcelableExtra("broadcast_intent");
        if (nested instanceof WebViewTestStubs.Intent) {
            activity.sendBroadcast((WebViewTestStubs.Intent) nested);  // SINK
        }
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        forwardIntent(activity);
        forwardIntentFixed(activity);
        forwardToService(activity);
        forwardToBroadcast(activity);
    }
}
