// Frida script for API monitoring

Java.perform(function() {
    console.log('[*] API Monitor Script Loaded');

    var apiCalls = [];
    var endpoints = new Set();

    // HTTP URLConnection monitoring
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');

        URL.openConnection.overload().implementation = function() {
            var connection = this.openConnection();
            var url = this.toString();
            console.log('[+] URL.openConnection(): ' + url);
            endpoints.add(url);
            return connection;
        };

        HttpURLConnection.setRequestMethod.implementation = function(method) {
            console.log('[+] HTTP Method: ' + method);
            this.setRequestMethod(method);
        };

        HttpURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
            console.log('[+] Request Header: ' + key + ': ' + value);
            this.setRequestProperty(key, value);
        };
    } catch (e) {
        console.log('[-] HttpURLConnection hooks failed: ' + e);
    }

    // OkHttp monitoring
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var RequestBody = Java.use('okhttp3.RequestBody');

        // Monitor requests
        OkHttpClient.newCall.implementation = function(request) {
            var url = request.url().toString();
            var method = request.method();
            console.log('[+] OkHttp Request: ' + method + ' ' + url);

            // Log headers
            var headers = request.headers();
            var headerNames = headers.names();
            var iterator = headerNames.iterator();
            while (iterator.hasNext()) {
                var name = iterator.next();
                console.log('  Header: ' + name + ': ' + headers.get(name));
            }

            // Log request body if exists
            var body = request.body();
            if (body) {
                var contentType = body.contentType();
                if (contentType) {
                    console.log('  Content-Type: ' + contentType.toString());
                }
            }

            endpoints.add(url);
            apiCalls.push({
                method: method,
                url: url,
                timestamp: new Date().toISOString()
            });

            return this.newCall(request);
        };
    } catch (e) {
        console.log('[-] OkHttp hooks failed: ' + e);
    }

    // Retrofit monitoring
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        var ServiceMethod = Java.use('retrofit2.ServiceMethod');

        Retrofit.baseUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[+] Retrofit Base URL: ' + url);
            endpoints.add(url);
            return this.baseUrl(url);
        };
    } catch (e) {
        console.log('[-] Retrofit hooks failed: ' + e);
    }

    // Volley monitoring
    try {
        var Request = Java.use('com.android.volley.Request');
        var StringRequest = Java.use('com.android.volley.toolbox.StringRequest');

        Request.getUrl.implementation = function() {
            var url = this.getUrl();
            console.log('[+] Volley Request URL: ' + url);
            endpoints.add(url);
            return url;
        };
    } catch (e) {
        console.log('[-] Volley hooks failed: ' + e);
    }

    // WebView monitoring
    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[+] WebView.loadUrl(): ' + url);
            endpoints.add(url);
            this.loadUrl(url);
        };

        WebView.postUrl.implementation = function(url, postData) {
            console.log('[+] WebView.postUrl(): ' + url);
            endpoints.add(url);
            this.postUrl(url, postData);
        };
    } catch (e) {
        console.log('[-] WebView hooks failed: ' + e);
    }

    // SharedPreferences monitoring
    // SharedPreferences monitoring
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        var SharedPreferencesEditor = Java.use('android.content.SharedPreferences$Editor');

        SharedPreferencesEditor.putString.implementation = function(key, value) {
            console.log('[+] SharedPreferences.putString(): ' + key + ' = ' + value);
            return this.putString(key, value);
        };

        SharedPreferencesImpl.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defValue) {
            var value = this.getString(key, defValue);
            console.log('[+] SharedPreferences.getString(): ' + key + ' = ' + value);
            return value;
        };
    } catch (e) {
        console.log('[-] SharedPreferences hooks failed: ' + e);
    }

    // SQLite monitoring
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            console.log('[+] SQLite execSQL: ' + sql);
            this.execSQL(sql);
        };

        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
            console.log('[+] SQLite rawQuery: ' + sql);
            if (selectionArgs) {
                console.log('  Args: ' + selectionArgs.join(', '));
            }
            return this.rawQuery(sql, selectionArgs);
        };
    } catch (e) {
        console.log('[-] SQLite hooks failed: ' + e);
    }

    // Crypto monitoring
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var MessageDigest = Java.use('java.security.MessageDigest');

        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log('[+] Cipher.getInstance(): ' + transformation);
            return this.getInstance(transformation);
        };

        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
            console.log('[+] MessageDigest.getInstance(): ' + algorithm);
            return this.getInstance(algorithm);
        };
    } catch (e) {
        console.log('[-] Crypto hooks failed: ' + e);
    }

    // File operations monitoring
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        var FileOutputStream = Java.use('java.io.FileOutputStream');

        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log('[+] FileInputStream: ' + path);
            this.$init(path);
        };

        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log('[+] FileOutputStream: ' + path);
            this.$init(path);
        };
    } catch (e) {
        console.log('[-] File operations hooks failed: ' + e);
    }

    // Periodic summary
    setInterval(function() {
        console.log('[*] API Monitor Summary:');
        console.log('  Total API calls: ' + apiCalls.length);
        console.log('  Unique endpoints: ' + endpoints.size);

        if (endpoints.size > 0) {
            console.log('  Discovered endpoints:');
            endpoints.forEach(function(endpoint) {
                console.log('    - ' + endpoint);
            });
        }
    }, 10000);

    console.log('[*] API monitor script execution completed');
});