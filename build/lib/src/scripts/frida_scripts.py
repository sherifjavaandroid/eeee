"""Collection of Frida scripts for mobile app testing"""

FRIDA_SCRIPTS = {
    'ssl_bypass': """
    // SSL Pinning Bypass
    Java.perform(function() {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
            console.log('[+] SSL Pinning Bypassed');
            return array_list.$new();
        };
    });
    """,

    'root_bypass': """
    // Root Detection Bypass
    Java.perform(function() {
        var RootPackages = ["com.topjohnwu.magisk"];
        var RootBinaries = ["su", "busybox", "magisk"];
        
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (RootBinaries.indexOf(cmd) != -1) {
                console.log('[+] Root check bypassed');
                return null;
            }
            return this.exec(cmd);
        };
    });
    """,

    'biometric_bypass': """
    // Biometric Authentication Bypass
    Java.perform(function() {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        
        BiometricPrompt.onAuthenticationSucceeded.implementation = function(result) {
            console.log('[+] Biometric Auth Bypass - Success forced');
            this.onAuthenticationSucceeded(result);
        };
    });
    """,

    'debug_bypass': """
    // Debug Detection Bypass
    Java.perform(function() {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            console.log('[+] Debug detection bypassed');
            return false;
        };
    });
    """
}