// Frida script for root detection bypass

Java.perform(function() {
    console.log('[*] Root Detection Bypass Script Loaded');

    // Common root check files
    var rootFiles = [
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
    ];

    // Common root packages
    var rootPackages = [
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclean",
        "com.zhiqupk.root.global"
    ];

    // File.exists() hook
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootFiles.length; i++) {
                if (path.indexOf(rootFiles[i]) !== -1) {
                    console.log('[+] File.exists() check bypassed for: ' + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch (e) {
        console.log('[-] File.exists() hook failed: ' + e);
    }

    // Runtime.exec() hook
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var exec = Runtime.exec.overload('java.lang.String');
        exec.implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                console.log('[+] Runtime.exec() blocked for: ' + cmd);
                return null;
            }
            return exec.call(this, cmd);
        };
    } catch (e) {
        console.log('[-] Runtime.exec() hook failed: ' + e);
    }

    // System.getProperty() hook
    try {
        var System = Java.use("java.lang.System");
        System.getProperty.overload('java.lang.String').implementation = function(key) {
            if (key === "ro.build.tags") {
                console.log('[+] System.getProperty() returning "release-keys" for: ' + key);
                return "release-keys";
            }
            return this.getProperty(key);
        };
    } catch (e) {
        console.log('[-] System.getProperty() hook failed: ' + e);
    }

    // RootBeer library bypass
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() bypassed');
            return false;
        };
    } catch (e) {
        console.log('[-] RootBeer bypass failed: ' + e);
    }

    // Package Manager hooks
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        // getPackageInfo() hook
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    console.log('[+] PackageManager.getPackageInfo() blocked for: ' + packageName);
                    throw new Error("Package not found");
                }
            }
            return this.getPackageInfo(packageName, flags);
        };

        // getApplicationInfo() hook
        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (packageName === rootPackages[i]) {
                    console.log('[+] PackageManager.getApplicationInfo() blocked for: ' + packageName);
                    throw new Error("Application not found");
                }
            }
            return this.getApplicationInfo(packageName, flags);
        };
    } catch (e) {
        console.log('[-] PackageManager hooks failed: ' + e);
    }

    // BuildConfig.DEBUG hook
    try {
        var BuildConfig = Java.use("android.BuildConfig");
        BuildConfig.DEBUG.value = false;
        console.log('[+] BuildConfig.DEBUG set to false');
    } catch (e) {
        console.log('[-] BuildConfig.DEBUG hook failed: ' + e);
    }

    // Native library hooks
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.overload('java.lang.String').implementation = function(libName) {
            if (libName.indexOf('substrate') !== -1 || libName.indexOf('frida') !== -1) {
                console.log('[+] System.loadLibrary() blocked for: ' + libName);
                return;
            }
            return this.loadLibrary(libName);
        };
    } catch (e) {
        console.log('[-] System.loadLibrary() hook failed: ' + e);
    }

    console.log('[*] Root detection bypass script execution completed');
});