package net.bytedance.security.app.pathfinder.testdata;

public class CommandInjectionVuln {

    public void execFromIntent(WebViewTestStubs.Activity activity) throws Exception {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String cmd = intent.getStringExtra("command");
        Runtime.getRuntime().exec(cmd);
    }

    public void execFromIntentFixed(WebViewTestStubs.Activity activity) throws Exception {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String cmd = intent.getStringExtra("command");
        if (cmd != null && cmd.matches("^(ls|pwd|whoami)$")) {
            Runtime.getRuntime().exec(cmd);
        }
    }

    public void processBuilderFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String cmd = intent.getStringExtra("command");
        new ProcessBuilder(new String[]{cmd});
    }

    public void f() throws Exception {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        execFromIntent(activity);
        execFromIntentFixed(activity);
        processBuilderFromIntent(activity);
    }
}
