#!/usr/bin/env python3
"""
VulnHunter Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vulnhunter",
    version="1.0.0",
    author="VulnHunter Team",
    author_email="vulnhunter@example.com",
    description="LLM-Powered Web Vulnerability Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vulnhunter/vulnhunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vulnhunter=vulnhunter.main:main",
        ],
    },
    include_package_data=True,
    keywords="security, vulnerability, scanner, llm, ollama, bug-bounty, pentesting",
)
