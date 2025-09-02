from setuptools import setup, find_packages

setup(
    name="wireless-pcap-analyzer",
    version="0.1.0",
    description="Comprehensive 802.11 wireless packet capture analysis framework",
    author="Your Name",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.0.0",
        "rich>=13.0.0",
        "pandas>=1.5.0",
        "numpy>=1.20.0",
        "cryptography>=3.4.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black",
            "flake8",
            "mypy",
        ],
    },
    entry_points={
        "console_scripts": [
            "wireless-analyzer=wireless_analyzer.cli.main:main",
        ],
    },
    python_requires=">=3.8",
)
