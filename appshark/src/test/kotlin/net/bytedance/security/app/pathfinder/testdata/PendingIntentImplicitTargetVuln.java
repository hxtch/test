package net.bytedance.security.app.pathfinder.testdata;

public class PendingIntentImplicitTargetVuln {

    public void createPendingIntentFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        WebViewTestStubs.Intent nested = (WebViewTestStubs.Intent) received.getParcelableExtra("nested_intent");
        WebViewTestStubs.PendingIntent.getActivity(activity, 0, nested, 0);
    }

    public void createPendingIntentFixed(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        WebViewTestStubs.Intent nested = (WebViewTestStubs.Intent) received.getParcelableExtra("nested_intent");
        if (nested != null) {
            nested.setPackage("com.example.safe");
        }
        WebViewTestStubs.PendingIntent.getActivity(activity, 0, nested, 0);
    }

    public void createBroadcastPendingIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        WebViewTestStubs.Intent nested = (WebViewTestStubs.Intent) received.getParcelableExtra("broadcast_intent");
        WebViewTestStubs.PendingIntent.getBroadcast(activity, 0, nested, 0);
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        createPendingIntentFromIntent(activity);
        createPendingIntentFixed(activity);
        createBroadcastPendingIntent(activity);
    }
}
