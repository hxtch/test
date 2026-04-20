package net.bytedance.security.app.pathfinder.testdata;

public class DexClassLoaderVuln {

    // Vulnerable: loads dex from external storage path
    public void loadDexFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String dexPath = intent.getStringExtra("dexPath");
        ClassLoader parent = this.getClass().getClassLoader();
        new WebViewTestStubs.DexClassLoader(dexPath, "/tmp", null, parent);
    }

    // Fixed: only loads from app-private directory
    public void loadDexFixed(WebViewTestStubs.Activity activity) {
        String dexPath = "/data/data/app/private/classes.dex";
        ClassLoader parent = this.getClass().getClassLoader();
        new WebViewTestStubs.DexClassLoader(dexPath, "/tmp", null, parent);
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        loadDexFromIntent(activity);
        loadDexFixed(activity);
    }
}
