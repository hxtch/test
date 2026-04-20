package net.bytedance.security.app.pathfinder.testdata;

public class WebViewVuln {

    // Vulnerable: loads untrusted URL from Intent into WebView
    public void loadUntrustedUrl(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String url = intent.getStringExtra("url");
        WebViewTestStubs.WebView webView = new WebViewTestStubs.WebView();
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl(url);  // SINK: untrusted URL flows into loadUrl
    }

    // Fixed: validates URL with whitelist before loading
    public void loadTrustedUrl(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String url = intent.getStringExtra("url");
        if (url != null && url.startsWith("https://trusted.example.com")) {
            WebViewTestStubs.WebView webView = new WebViewTestStubs.WebView();
            webView.loadUrl(url);
        }
    }

    // Vulnerable: loads untrusted data into WebView
    public void loadUntrustedData(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String htmlData = intent.getStringExtra("html");
        WebViewTestStubs.WebView webView = new WebViewTestStubs.WebView();
        webView.loadData(htmlData, "text/html", "UTF-8");  // SINK
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        loadUntrustedUrl(activity);
        loadTrustedUrl(activity);
        loadUntrustedData(activity);
    }
}
