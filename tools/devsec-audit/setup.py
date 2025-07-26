#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="devsec-audit",
    version="1.0.0",
    description="DevSecOps Security Auditor - Lynis-style tool for development environments",
    author="DevSec Audit Team",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.0.0",
        "gitpython>=3.1.0",
        "docker>=6.0.0",
        "colorama>=0.4.0",
        "tabulate>=0.9.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "devsec-audit=core.cli:main",
        ],
    },
    python_requires=">=3.8",
)