# musebox

在 TVBox Q 版（q215613905/TVBoxOS @ 3988b4e，即打包版 20230302-0924）的源码上，
把 anzhuo44tvbox 项目验证过的 HTTPS 兼容方案移植进来，做成的"双合体"版本。
界面与功能保持 Q 版原样，只动网络层。

## 改了什么（相对 20230302-0924）

1. **TLS 1.2 显式启用**（新增 `util/SSL/Tls12SocketFactory.java`，移植自 anzhuo44tvbox）：
   Android 4.x/5.x 的 SSLSocket 支持 TLS1.2 但默认不启用，老盒子对仅支持
   TLS1.2+ 的现代站点握手失败——这是 https 点播源打不开的主要原因。
   本实现启用设备支持的全部 TLS 版本（1.2/1.1/1.0）。
2. **补充根证书**（新增 `util/SSL/LegacyCertificateTrust.java` + `res/raw/trusted_roots.pem`）：
   老系统证书库缺少 ISRG Root X1/X2（Let's Encrypt）与 DigiCert Global Root G2，
   内置这三张根（SHA-256 指纹白名单校验）补齐信任锚，校验逻辑不变。
3. **连接规格三档回退**：MODERN_TLS → COMPATIBLE_TLS → 明文，
   协商不出第一档时自动落兼容档，不再直接失败。
4. 接入点：OkGo 全局客户端、播放器（Exo）客户端、DoH 引导客户端、字幕下载
   客户端统一走 `LegacyTls.applyTo()`；`HttpsURLConnection` 设置默认工厂兜底。
5. **ijkPlayer 的 native TLS**（`player/IjkMediaPlayer.java`）：ijk 走 native
   ffmpeg 自己握手，不经 Java 层；API<22 时设 `tls_verify=0` 关掉它的证书
   校验，绕过老系统 native 证书库过旧。此项为参考 newbox 交接清单补入，
   只影响 ijk 播放链路，Exo 链路仍走完整校验。
5. 版本号 20230302-0924-musebox.1（versionCode 2），包名不变
   （com.github.tvbox.osc），使用 musebox 项目自有签名——与社区打包版签名
   不同，首次安装需先卸载旧版。

## 与原 Q 版的行为差异（重要）

原 Q 版的 SSL 是"信任所有证书 + 跳过域名校验"。本版改为 anzhuo44tvbox 的
严格校验（完整链路 + 域名校验 + 补充根）。证书正常的主流 https 源（含
Let's Encrypt 链）都能打开；但自签名、过期、域名不符的源会被拒绝——
这是原方案的取舍，不是 bug。

## 构建

GitHub Actions（JDK 11 + Android SDK 30）执行 `./gradlew assembleRelease`，
产物在 Actions 的 musebox-apk artifact 与 Releases 中。
