from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mobile-security-scanner",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Automated mobile application security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/mobile-security-scanner",
    packages=find_packages(),
    package_dir={'mobile_security_scanner': 'src'},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "frida>=16.1.4",
        "frida-tools>=12.1.1",
        "androguard>=3.4.0",
        "objection>=1.11.0",
        "mitmproxy>=10.1.5",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.2",
        "colorama>=0.4.6",
        "click>=8.1.7",
    ],
    entry_points={
        "console_scripts": [
            "mobile-scanner=src.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        'mobile_security_scanner': [
            'templates/*.html',
            'templates/*.md',
            'scripts/*.js',
            'scripts/*.py',
            '../data/**/*',
            '../config/*.yaml',
        ],
    },
)