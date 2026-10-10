package com.example.app;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ContentProvider;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.File;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

/* Deliberately vulnerable fixture for tests/smoke.sh (vuln-scan semgrep rules). Not real code. */
public class VulnActivity extends Activity {
    WebView web;
    SQLiteDatabase db;
    String key = "This is the super secret key 123";            // hardcoded-key-material-field
    byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0};                  // hardcoded-key-material-field
    String keyAlias = "upload_key";                             // must NOT match

    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Uri data = getIntent().getData();
        String url = data.getQueryParameter("url");
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setAllowUniversalAccessFromFileURLs(true);
        web.addJavascriptInterface(new Bridge(), "Android");
        web.loadUrl(url);                                       // webview-url-from-intent
        web.loadUrl("https://static.example.com/help");         // constant: must NOT match
        Intent next = (Intent) getIntent().getParcelableExtra("next");
        startActivity(next);                                    // intent-redirection
        String id = getIntent().getStringExtra("id");
        db.rawQuery("SELECT * FROM users WHERE id=" + id, null); // sql-injection-concat
        Runtime.getRuntime().exec("sh -c " + id);               // command-execution
        Runtime.getRuntime().exec("id");                        // constant: must NOT match
        PendingIntent.getActivity(this, 0, new Intent(), PendingIntent.FLAG_MUTABLE);
    }

    byte[] enc(byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");  // weak-cipher-mode
        c.init(1, new SecretKeySpec("0123456789abcdef".getBytes(), "AES")); // hardcoded-crypto-key
        Cipher ok = Cipher.getInstance("AES/GCM/NoPadding");    // must NOT match
        return c.doFinal(in);
    }

    static class Bridge {}

    Object misc(java.io.InputStream in, String path) throws Exception {
        android.content.SharedPreferences sp = getSharedPreferences("p", MODE_WORLD_READABLE);   // world-readable-file
        dalvik.system.DexClassLoader cl = new dalvik.system.DexClassLoader(path, getCacheDir().getPath(), null, getClassLoader()); // dynamic-code-loading
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance(); // xxe-documentbuilder
        java.util.Random r = new java.util.Random();                                           // insecure-random-for-secrets
        return new java.io.ObjectInputStream(in).readObject();                                 // java-deserialization
    }

    static class Prefs extends android.preference.PreferenceActivity {
        protected boolean isValidFragment(String f) { return true; }                            // fragment-injection
    }

    static class Client extends WebViewClient {
        public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) {
            handler.proceed();                                  // webview-ssl-error-proceed
        }
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}   // trustmanager-accepts-all
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class TrustOk implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) { if (c.length == 0) throw new IllegalArgumentException(); }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class AllowAll implements HostnameVerifier {
        public boolean verify(String h, SSLSession s) { return true; }   // hostname-verifier-accepts-all
    }

    abstract static class FileProv extends ContentProvider {
        public ParcelFileDescriptor openFile(Uri uri, String mode) throws java.io.FileNotFoundException {
            File f = new File(getContext().getFilesDir(), uri.getLastPathSegment()); // provider-path-traversal
            return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
        }
    }
}
