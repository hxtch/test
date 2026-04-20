package net.bytedance.security.app.pathfinder.testdata;

public class ExportedServiceBindingVuln {

    public WebViewTestStubs.Intent onBind(WebViewTestStubs.Intent intent) throws Exception {
        String cmd = intent.getStringExtra("command");
        Runtime.getRuntime().exec(cmd);
        return null;
    }

    public WebViewTestStubs.Intent onBindFixed(WebViewTestStubs.Intent intent) throws Exception {
        String cmd = intent.getStringExtra("command");
        if (cmd != null && cmd.matches("^(ls|pwd)$")) {
            Runtime.getRuntime().exec(cmd);
        }
        return null;
    }

    public WebViewTestStubs.Intent onBindQuery(WebViewTestStubs.Intent intent) {
        String uri = intent.getStringExtra("uri");
        WebViewTestStubs.ContentResolver resolver = new WebViewTestStubs.ContentResolver();
        resolver.query(uri, null, null, null, null);
        return null;
    }

    public void f() throws Exception {
        WebViewTestStubs.Intent intent = new WebViewTestStubs.Intent();
        onBind(intent);
        onBindFixed(intent);
        onBindQuery(intent);
    }
}
