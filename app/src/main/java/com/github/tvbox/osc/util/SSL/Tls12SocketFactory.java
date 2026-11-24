package com.github.tvbox.osc.util.SSL;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * 从 anzhuo44tvbox 移植的 TLS 1.2 启用工厂。
 *
 * Android 4.x（API 16~19）与 5.0/5.1（API 20~21）的 SSLSocket 支持 TLSv1.2，
 * 但默认不启用，只启用 TLSv1，导致对仅支持 TLS1.2+ 的现代服务握手失败
 * （点播源 https 接口在老盒子上打不开的主要原因）。
 *
 * 本工厂在每个 socket 上显式启用设备支持的全部 TLS 版本（1.2/1.1/1.0，
 * 按设备实际支持列表过滤），不改信任策略、不禁用校验。
 * 与原版（只启用 TLSv1.2）的差异：同时保留 1.1/1.0，兼容只提供旧协议的老服务器，
 * 协商时仍会优先用双方都支持的最高版本。
 */
public final class Tls12SocketFactory extends SSLSocketFactory {

    private static final String[] WANTED = {"TLSv1.2", "TLSv1.1", "TLSv1"};

    private final SSLSocketFactory delegate;

    private Tls12SocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    /** API<22 时包装给定的工厂以启用 TLS1.2；否则原样返回。 */
    public static SSLSocketFactory wrap(SSLSocketFactory delegate, int sdkInt) {
        return sdkInt < 22 ? new Tls12SocketFactory(delegate) : delegate;
    }

    /** 用系统默认信任构建一个启用 TLS1.2 的工厂；API>=22 或失败时返回 null。 */
    public static SSLSocketFactory createIfNecessary(int sdkInt) {
        if (sdkInt < 22) {
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, null, null);
                return new Tls12SocketFactory(context.getSocketFactory());
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        return enableTls(delegate.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket(String host, int port)
            throws IOException, UnknownHostException {
        return enableTls(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return enableTls(delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return enableTls(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                               int localPort) throws IOException {
        return enableTls(delegate.createSocket(address, port, localAddress, localPort));
    }

    private static Socket enableTls(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket ssl = (SSLSocket) socket;
            String[] supported = ssl.getSupportedProtocols();
            List<String> enable = new ArrayList<String>();
            for (String want : WANTED) {
                for (String s : supported) {
                    if (want.equals(s)) {
                        enable.add(want);
                        break;
                    }
                }
            }
            if (!enable.isEmpty()) {
                ssl.setEnabledProtocols(enable.toArray(new String[enable.size()]));
            }
        }
        return socket;
    }
}
