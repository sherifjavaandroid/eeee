import os

def create_structure(base_dir):
    # قائمة بجميع المجلدات التي يجب إنشاؤها
    directories = [
        os.path.join(base_dir, 'config'),
        os.path.join(base_dir, 'src'),
        os.path.join(base_dir, 'src/core'),
        os.path.join(base_dir, 'src/modules'),
        os.path.join(base_dir, 'src/modules/android'),
        os.path.join(base_dir, 'src/modules/ios'),
        os.path.join(base_dir, 'src/modules/static_analysis'),
        os.path.join(base_dir, 'src/modules/dynamic_analysis'),
        os.path.join(base_dir, 'src/modules/exploitation'),
        os.path.join(base_dir, 'src/modules/reporting'),
        os.path.join(base_dir, 'src/utils'),
        os.path.join(base_dir, 'src/scripts'),
        os.path.join(base_dir, 'src/templates'),
        os.path.join(base_dir, 'tests'),
        os.path.join(base_dir, 'data/patterns'),
        os.path.join(base_dir, 'data/wordlists'),
        os.path.join(base_dir, 'output/reports'),
        os.path.join(base_dir, 'output/logs'),
        os.path.join(base_dir, 'output/artifacts'),
    ]

    # إنشاء جميع المجلدات
    for dir_path in directories:
        os.makedirs(dir_path, exist_ok=True)
        print(f'تم إنشاء المجلد: {dir_path}')

    # قائمة بجميع الملفات التي يجب إنشاؤها
    files = [
        # الملفات الرئيسية
        os.path.join(base_dir, 'README.md'),
        os.path.join(base_dir, 'requirements.txt'),
        os.path.join(base_dir, 'setup.py'),
        
        # مجلد config
        os.path.join(base_dir, 'config/__init__.py'),
        os.path.join(base_dir, 'config/config.yaml'),
        os.path.join(base_dir, 'config/logging_config.py'),
        
        # مجلد src
        os.path.join(base_dir, 'src/__init__.py'),
        os.path.join(base_dir, 'src/main.py'),
        
        # مجلد src/core
        os.path.join(base_dir, 'src/core/__init__.py'),
        os.path.join(base_dir, 'src/core/scanner.py'),
        os.path.join(base_dir, 'src/core/analyzer.py'),
        os.path.join(base_dir, 'src/core/exploiter.py'),
        
        # مجلد android
        os.path.join(base_dir, 'src/modules/android/__init__.py'),
        os.path.join(base_dir, 'src/modules/android/apk_analyzer.py'),
        os.path.join(base_dir, 'src/modules/android/manifest_parser.py'),
        os.path.join(base_dir, 'src/modules/android/decompiler.py'),
        os.path.join(base_dir, 'src/modules/android/dynamic_tester.py'),
        
        # مجلد ios
        os.path.join(base_dir, 'src/modules/ios/__init__.py'),
        os.path.join(base_dir, 'src/modules/ios/ipa_analyzer.py'),
        os.path.join(base_dir, 'src/modules/ios/binary_analyzer.py'),
        os.path.join(base_dir, 'src/modules/ios/runtime_analyzer.py'),
        
        # مجلد static_analysis
        os.path.join(base_dir, 'src/modules/static_analysis/__init__.py'),
        os.path.join(base_dir, 'src/modules/static_analysis/secret_scanner.py'),
        os.path.join(base_dir, 'src/modules/static_analysis/vulnerability_scanner.py'),
        os.path.join(base_dir, 'src/modules/static_analysis/code_analyzer.py'),
        
        # مجلد dynamic_analysis
        os.path.join(base_dir, 'src/modules/dynamic_analysis/__init__.py'),
        os.path.join(base_dir, 'src/modules/dynamic_analysis/frida_manager.py'),
        os.path.join(base_dir, 'src/modules/dynamic_analysis/network_interceptor.py'),
        os.path.join(base_dir, 'src/modules/dynamic_analysis/runtime_manipulator.py'),
        
        # مجلد exploitation
        os.path.join(base_dir, 'src/modules/exploitation/__init__.py'),
        os.path.join(base_dir, 'src/modules/exploitation/exploit_generator.py'),
        os.path.join(base_dir, 'src/modules/exploitation/payload_builder.py'),
        os.path.join(base_dir, 'src/modules/exploitation/vulnerability_chainer.py'),
        
        # مجلد reporting
        os.path.join(base_dir, 'src/modules/reporting/__init__.py'),
        os.path.join(base_dir, 'src/modules/reporting/report_generator.py'),
        os.path.join(base_dir, 'src/modules/reporting/vulnerability_reporter.py'),
        os.path.join(base_dir, 'src/modules/reporting/bug_bounty_reporter.py'),
        
        # مجلد utils
        os.path.join(base_dir, 'src/utils/__init__.py'),
        os.path.join(base_dir, 'src/utils/adb_helper.py'),
        os.path.join(base_dir, 'src/utils/file_helper.py'),
        os.path.join(base_dir, 'src/utils/network_helper.py'),
        os.path.join(base_dir, 'src/utils/crypto_helper.py'),
        
        # مجلد scripts
        os.path.join(base_dir, 'src/scripts/__init__.py'),
        os.path.join(base_dir, 'src/scripts/frida_scripts.py'),
        os.path.join(base_dir, 'src/scripts/ssl_bypass.js'),
        os.path.join(base_dir, 'src/scripts/root_detection_bypass.js'),
        os.path.join(base_dir, 'src/scripts/api_monitor.js'),
        
        # مجلد templates
        os.path.join(base_dir, 'src/templates/report_template.html'),
        os.path.join(base_dir, 'src/templates/vulnerability_report.md'),
        os.path.join(base_dir, 'src/templates/bug_bounty_template.md'),
        
        # مجلد tests
        os.path.join(base_dir, 'tests/__init__.py'),
        os.path.join(base_dir, 'tests/test_android_analyzer.py'),
        os.path.join(base_dir, 'tests/test_ios_analyzer.py'),
        os.path.join(base_dir, 'tests/test_vulnerability_scanner.py'),
        
        # مجلد data
        os.path.join(base_dir, 'data/patterns/secrets.json'),
        os.path.join(base_dir, 'data/patterns/vulnerabilities.json'),
        os.path.join(base_dir, 'data/patterns/api_patterns.json'),
        os.path.join(base_dir, 'data/wordlists/android_permissions.txt'),
        os.path.join(base_dir, 'data/wordlists/ios_url_schemes.txt'),
        os.path.join(base_dir, 'data/wordlists/sensitive_apis.txt'),
    ]

    # إنشاء جميع الملفات
    for file_path in files:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                pass  # إنشاء ملف فارغ
            print(f'تم إنشاء الملف: {file_path}')
        else:
            print(f'الملف موجود مسبقاً: {file_path}')

if __name__ == '__main__':
    project_dir = 'mobile_security_automation'
    create_structure(project_dir)
    print('تم إنشاء هيكل المشروع بنجاح!')