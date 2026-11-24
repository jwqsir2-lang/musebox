package com.github.tvbox.osc.util.SSL;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * 从 anzhuo44tvbox 移植：为老系统补充受信任的公共根证书，同时保持完整
 * PKIX 链路校验（不放行自签名证书）。
 *
 * <p>为什么需要这三个根：
 * <ul>
 *   <li>ISRG Root X1（RSA，2015）：Let's Encrypt 老链（R 系列中间证书）的回溯终点。
 *       Android 4.4 的 2013 年证书库不含它。</li>
 *   <li>ISRG Root X2（ECDSA，2020）：新链（E 系列 / YE 系列中间证书）的回溯终点。
 *       部分站点（如使用 YE 系列叶子证书的 MacCMS 源）整条链要经过 X2 才能回到 X1，
 *       老系统缺 X2 会在中间证书校验处直接失败。</li>
 *   <li>DigiCert Global Root G2（2013）：豆瓣等站点使用
 *       （*.douban.com → GeoTrust TLS RSA CA G1 → DigiCert Global Root G2）。
 *       Android 4.4 的老证书库只有 2006 年的 DigiCert 根，没有 G2。</li>
 * </ul>
 *
 * <p>指纹为硬编码白名单：传入的 PEM 只要有一张对不上就抛异常，
 * 避免被替换成任意根证书。
 */
public final class LegacyCertificateTrust implements X509TrustManager {

    /** ISRG Root X1 — SHA-256 指纹。 */
    static final String ROOT_X1_SHA256 =
            "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6";
    /** ISRG Root X2 — SHA-256 指纹。 */
    static final String ROOT_X2_SHA256 =
            "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470";
    /** DigiCert Global Root G2 — SHA-256 指纹。 */
    static final String DIGICERT_G2_SHA256 =
            "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f";

    /** 单张根证书的指纹白名单。 */
    static final String[] ROOT_SHA256_WHITELIST = {
            ROOT_X1_SHA256, ROOT_X2_SHA256, DIGICERT_G2_SHA256
    };

    private final X509TrustManager system;
    private final X509TrustManager additional;

    LegacyCertificateTrust(X509TrustManager system, X509TrustManager additional) {
        this.system = system;
        this.additional = additional;
    }

    /**
     * 从一组 PEM 根证书构建信任管理器。每张证书都必须匹配白名单中的某个指纹，
     * 否则整体拒绝（宁可退回系统信任库，也不静默接受未知根）。
     */
    public static X509TrustManager fromRoots(InputStream combinedPem)
            throws GeneralSecurityException, java.io.IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        java.util.Collection<? extends java.security.cert.Certificate> parsed =
                factory.generateCertificates(combinedPem);
        if (parsed == null || parsed.isEmpty()) {
            throw new CertificateException("No bundled roots found");
        }

        KeyStore roots = KeyStore.getInstance(KeyStore.getDefaultType());
        roots.load(null, null);

        int index = 0;
        for (java.security.cert.Certificate c : parsed) {
            X509Certificate root = (X509Certificate) c;
            String actual = fingerprintSha256(root);
            if (!inWhitelist(actual)) {
                throw new CertificateException(
                        "Unexpected bundled root fingerprint: " + actual);
            }
            root.checkValidity();
            root.verify(root.getPublicKey());
            roots.setCertificateEntry("bundled-root-" + index, root);
            index++;
        }
        return new LegacyCertificateTrust(trustManager(null), trustManager(roots));
    }

    private static boolean inWhitelist(String sha256) {
        for (String expected : ROOT_SHA256_WHITELIST) {
            if (expected.equals(sha256)) {
                return true;
            }
        }
        return false;
    }

    static String fingerprintSha256(X509Certificate cert) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format(java.util.Locale.US, "%02x", b & 0xff));
        }
        return sb.toString();
    }

    static X509TrustManager trustManager(KeyStore store) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager) {
                return (X509TrustManager) manager;
            }
        }
        throw new GeneralSecurityException("No X509 trust manager");
    }

    /** 系统默认信任管理器。 */
    public static X509TrustManager systemDefault() throws GeneralSecurityException {
        return trustManager(null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty server chain");
        }
        try {
            system.checkServerTrusted(chain, authType);
        } catch (CertificateException systemFailure) {
            // 回退：仍走完整链路校验，只是把补充根加入信任锚点。
            additional.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        system.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] first = system.getAcceptedIssuers();
        X509Certificate[] second = additional.getAcceptedIssuers();
        X509Certificate[] all = new X509Certificate[first.length + second.length];
        System.arraycopy(first, 0, all, 0, first.length);
        System.arraycopy(second, 0, all, first.length, second.length);
        return all;
    }
}
