package com.github.tvbox.osc.util.SSL;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.github.tvbox.osc.R;

import java.io.InputStream;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;

/**
 * musebox 的统一 HTTPS 兼容层（anzhuo44tvbox 的解法移植到 Q 版）：
 *
 * 1. TLS 版本：API&lt;22 的设备由 {@link Tls12SocketFactory} 显式启用 TLS1.2/1.1/1.0，
 *    解决老盒子对仅支持 TLS1.2+ 的现代站点握手失败。
 * 2. 根证书：API&lt;26 的设备证书库缺少 ISRG Root X1/X2 与 DigiCert Global Root G2，
 *    由 {@link LegacyCertificateTrust} 用内置 PEM 补充信任锚，校验逻辑不变
 *    （完整链路校验 + OkHttp 默认域名校验，不再信任所有证书）。
 * 3. 连接规格：MODERN_TLS → COMPATIBLE_TLS → 明文 三档回退，
 *    老服务器/老设备协商不出第一档时自动落到兼容档，而不是直接失败。
 *
 * 在 App 启动时 {@link #init(Context)} 一次，之后所有 OkHttpClient.Builder
 * 通过 {@link #applyTo(OkHttpClient.Builder)} 接入。
 */
public final class LegacyTls {

    private static final String TAG = "LegacyTls";

    private static SSLSocketFactory socketFactory;
    private static X509TrustManager trustManager;

    private LegacyTls() {
    }

    public static synchronized void init(Context context) {
        if (socketFactory != null) {
            return;
        }
        int sdk = Build.VERSION.SDK_INT;
        // 首选：系统信任 + 补充根（老系统），socket 工厂再包一层 TLS1.2 启用。
        if (sdk < 26) {
            InputStream roots = null;
            try {
                roots = context.getResources().openRawResource(R.raw.trusted_roots);
                X509TrustManager tm = LegacyCertificateTrust.fromRoots(roots);
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{tm}, null);
                trustManager = tm;
                socketFactory = Tls12SocketFactory.wrap(ctx.getSocketFactory(), sdk);
                return;
            } catch (Exception e) {
                Log.e(TAG, "Bundled roots setup failed; falling back to system trust", e);
            } finally {
                if (roots != null) {
                    try {
                        roots.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        // 回退/新系统：系统默认信任，仍按需启用 TLS1.2。
        try {
            X509TrustManager system = LegacyCertificateTrust.systemDefault();
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{system}, null);
            trustManager = system;
            socketFactory = Tls12SocketFactory.wrap(ctx.getSocketFactory(), sdk);
        } catch (Exception e) {
            Log.e(TAG, "System trust setup failed", e);
            socketFactory = null;
            trustManager = null;
        }
    }

    /** 把统一的 SSLSocketFactory 与连接规格装到给定的 OkHttp 构建器上。 */
    public static void applyTo(OkHttpClient.Builder builder) {
        if (socketFactory != null && trustManager != null) {
            builder.sslSocketFactory(socketFactory, trustManager);
        }
        builder.connectionSpecs(Arrays.asList(
                ConnectionSpec.MODERN_TLS,
                ConnectionSpec.COMPATIBLE_TLS,
                ConnectionSpec.CLEARTEXT));
    }

    /** 供 HttpsURLConnection 等非 OkHttp 通道复用的 socket 工厂（可能为 null）。 */
    public static SSLSocketFactory socketFactory() {
        return socketFactory;
    }
}
