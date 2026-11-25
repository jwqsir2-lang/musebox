package com.github.tvbox.osc.util;

import java.io.IOException;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/**
 * musebox: 移植 anzhuo44tvbox 的豆瓣请求头处理。
 * 豆瓣系域名（API 与图片 CDN doubanio.com 均校验）需浏览器 UA + Referer，
 * 否则图片请求被 418 拒绝、首页豆瓣热播海报不显示。
 * 仅对 host 含 "douban" 的请求补头，其余请求原样放行。
 */
public class DoubanHeaderInterceptor implements Interceptor {

    private static final String DOUBAN_UA =
            "Mozilla/5.0 (Linux; Android 4.4.4) AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36";

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request r = chain.request();
        String host = r.url().host();
        if (host.contains("douban")) {
            Request.Builder b = r.newBuilder();
            if (r.header("Referer") == null) {
                b.header("Referer", "https://m.douban.com/");
                b.header("Origin", "https://m.douban.com");
            }
            if (r.header("User-Agent") == null) {
                b.header("User-Agent", DOUBAN_UA);
            }
            r = b.build();
        }
        return chain.proceed(r);
    }
}
