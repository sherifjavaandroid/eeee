// Frida script for SSL pinning bypass

Java.perform(function() {
    console.log('[*] SSL Pinning Bypass Script Loaded');

    // Generic TrustManager bypass
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // Create a custom TrustManager
        var TrustManagerImpl = Java.registerClass({
            name: 'com.custom.TrustManagerImpl',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) { },
                checkServerTrusted: function(chain, authType) { },
                getAcceptedIssuers: function() { return []; }
            }
        });

        // Override SSLContext.init()
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(keyManager, trustManager, secureRandom) {
            console.log('[+] Overriding SSLContext.init()');
            this.init(keyManager, [TrustManagerImpl.$new()], secureRandom);
        };

        console.log('[+] Generic TrustManager bypass applied');
    } catch (e) {
        console.log('[-] Generic TrustManager bypass failed: ' + e);
    }

    // OkHttp3 pinning bypass
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
            return;
        };

        console.log('[+] OkHttp3 pinning bypass applied');
    } catch (e) {
        console.log('[-] OkHttp3 pinning bypass failed: ' + e);
    }

    // Retrofit pinning bypass (if using OkHttp)
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        Retrofit.baseUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[+] Retrofit baseUrl: ' + url);
            return this.baseUrl(url);
        };
    } catch (e) {
        console.log('[-] Retrofit hook failed: ' + e);
    }

    // Conscrypt (Google's TLS library) bypass
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.implementation = function(x509tm, chain, authType, engine) {
            console.log('[+] Conscrypt checkServerTrusted() bypassed');
            return;
        };
    } catch (e) {
        console.log('[-] Conscrypt bypass failed: ' + e);
    }

    // Apache HttpClient bypass
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean')
            .implementation = function(host, cns, subjectAlts, strictWithSubDomains) {
            console.log('[+] Apache HttpClient verify() bypassed for: ' + host);
            return;
        };
    } catch (e) {
        console.log('[-] Apache HttpClient bypass failed: ' + e);
    }

    // PhoneGap/Cordova bypass
    try {
        var CordovaWebViewClient = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] Cordova WebView SSL error bypassed');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] Cordova bypass failed: ' + e);
    }

    // WebView SSL Error Handler bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] WebView SSL error bypassed');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] WebView SSL error bypass failed: ' + e);
    }

    // HostnameVerifier bypass
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');

        var MyHostnameVerifier = Java.registerClass({
            name: 'com.custom.MyHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log('[+] HostnameVerifier bypassed for: ' + hostname);
                    return true;
                }
            }
        });

        // Hook HttpsURLConnection.setDefaultHostnameVerifier
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[+] Setting custom HostnameVerifier');
            this.setDefaultHostnameVerifier(MyHostnameVerifier.$new());
        };

        console.log('[+] HostnameVerifier bypass applied');
    } catch (e) {
        console.log('[-] HostnameVerifier bypass failed: ' + e);
    }

    console.log('[*] SSL pinning bypass script execution completed');
});