package net.bytedance.security.app.pathfinder.testdata;

public class SQLInjectionVuln {

    // Vulnerable: rawQuery with untrusted input
    public void queryFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String selection = intent.getStringExtra("selection");
        WebViewTestStubs.SQLiteDatabase db = new WebViewTestStubs.SQLiteDatabase();
        db.rawQuery("SELECT * FROM users WHERE name = '" + selection + "'", null);
    }

    // Fixed: uses parameterized query (selection string not concatenated)
    public void queryFixed(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String selection = intent.getStringExtra("selection");
        WebViewTestStubs.SQLiteDatabase db = new WebViewTestStubs.SQLiteDatabase();
        db.rawQuery("SELECT * FROM users WHERE name = ?", new String[]{selection});
    }

    // Vulnerable: execSQL with untrusted input
    public void execFromIntent(WebViewTestStubs.Activity activity) {
        WebViewTestStubs.Intent intent = activity.getIntent();
        String sql = intent.getStringExtra("sql");
        WebViewTestStubs.SQLiteDatabase db = new WebViewTestStubs.SQLiteDatabase();
        db.execSQL(sql);
    }

    public void f() {
        WebViewTestStubs.Activity activity = new WebViewTestStubs.Activity();
        queryFromIntent(activity);
        queryFixed(activity);
        execFromIntent(activity);
    }
}
