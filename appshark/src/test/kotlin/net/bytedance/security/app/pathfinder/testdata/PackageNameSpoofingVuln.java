package net.bytedance.security.app.pathfinder.testdata;

public class PackageNameSpoofingVuln {

    public void startByPackageFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        String pkg = received.getStringExtra("target_pkg");
        WebViewTestStubs.Intent launch = new WebViewTestStubs.Intent();
        launch.setPackage(pkg);
        activity.startActivity(launch);
    }

    public void startByPackageFixed(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent launch = new WebViewTestStubs.Intent();
        launch.setPackage("com.example.trusted");
        activity.startActivity(launch);
    }

    public void startByClassNameFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        String className = received.getStringExtra("target_class");
        WebViewTestStubs.Intent launch = new WebViewTestStubs.Intent();
        launch.setClassName(activity, className);
        activity.startService(launch);
    }

    public void startByComponentFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent received = activity.getIntent();
        String component = received.getStringExtra("target_component");
        WebViewTestStubs.Intent launch = new WebViewTestStubs.Intent();
        launch.setComponent(component);
        activity.sendBroadcast(launch);
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        startByPackageFromIntent(activity);
        startByPackageFixed(activity);
        startByClassNameFromIntent(activity);
        startByComponentFromIntent(activity);
    }
}
