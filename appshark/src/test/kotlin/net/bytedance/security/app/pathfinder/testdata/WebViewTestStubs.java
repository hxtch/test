package net.bytedance.security.app.pathfinder.testdata;

// Minimal stubs for Android WebView APIs used by testdata
public class WebViewTestStubs {
    // Stub for WebView
    public static class WebView {
        public void addJavascriptInterface(Object obj, String name) {}
        public void loadUrl(String url) {}
        public void loadData(String data, String mimeType, String encoding) {}
        public void loadDataWithBaseURL(String baseUrl, String data, String mimeType, String encoding, String historyUrl) {}
        public WebSettings getSettings() { return new WebSettings(); }
    }

    // Stub for WebSettings
    public static class WebSettings {
        public void setJavaScriptEnabled(boolean flag) {}
        public void setAllowFileAccessFromFileURLs(boolean flag) {}
        public void setAllowUniversalAccessFromFileURLs(boolean flag) {}
        public void setAllowFileAccess(boolean flag) {}
    }

    // Stub for Intent
    public static class Intent {
        public String getStringExtra(String name) { return ""; }
        public Object getParcelableExtra(String name) { return null; }
        public Uri getData() { return new Uri(); }
        public Intent setComponent(String componentName) { return this; }
        public Intent setPackage(String packageName) { return this; }
        public Intent setClassName(Object context, String className) { return this; }
        public void removeFlags(int flags) {}
        public static Intent parseUri(String uri, int flags) { return new Intent(); }
    }

    // Stub for SmsManager
    public static class SmsManager {
        public static SmsManager getDefault() { return new SmsManager(); }
        public void sendTextMessage(String dest, String scAddr, String text, Object sentIntent, Object deliveryIntent) {}
    }

    // Stub for ContentResolver
    public static class ContentResolver {
        public Object query(Object uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
        public int delete(Object uri, String selection, String[] selectionArgs) { return 0; }
    }

    // Stub for Context
    public static class Context {
        public void startActivity(Intent intent) {}
        public void startService(Intent intent) {}
        public void sendBroadcast(Intent intent) {}
        public Object registerReceiver(Object receiver, Object filter) { return null; }
        public ContentResolver getContentResolver() { return new ContentResolver(); }
    }

    // Stub for Activity
    public static class Activity extends Context {
        public Intent getIntent() { return new Intent(); }
        public void setResult(int resultCode, Intent data) {}
    }

    // Stub for Runtime
    // java.lang.Runtime is already available, no stub needed

    // Stub for SQLiteDatabase
    public static class SQLiteDatabase {
        public Object rawQuery(String sql, String[] selectionArgs) { return null; }
        public void execSQL(String sql) {}
    }

    // Stub for DexClassLoader
    public static class DexClassLoader {
        public DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent) {}
    }

    // Stub for PendingIntent
    public static class PendingIntent {
        public static PendingIntent getActivity(Object context, int requestCode, Intent intent, int flags) { return new PendingIntent(); }
        public static PendingIntent getService(Object context, int requestCode, Intent intent, int flags) { return new PendingIntent(); }
        public static PendingIntent getBroadcast(Object context, int requestCode, Intent intent, int flags) { return new PendingIntent(); }
    }

    // Stub for Service
    public static class Service extends Context {
        public Intent getIntent() { return new Intent(); }
        public Intent onBind(Intent intent) { return null; }
    }

    // Stub for Bundle
    public static class Bundle {
        public String getString(String key) { return ""; }
    }

    // Stub for Uri
    public static class Uri {
        public String getQueryParameter(String key) { return ""; }
        public String getPath() { return ""; }
    }
}
