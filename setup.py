#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="claude-runtime-monitor",
    version="0.1.0",
    description="Security monitoring and audit logging for Claude Code",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Security Team",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "claude-monitor=claude_monitor.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
