#!/usr/bin/env python3
"""
Evil-Ollama — Exposed Ollama Instance Hunter, Proxy & API Manipulation Tool
For authorized security research & bug bounty purposes only.
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="evil-ollama",
    version="3.0.0",
    author="evogix",
    author_email="",
    description="🦙 Exposed Ollama Instance Hunter, Proxy & API Manipulation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/evogix/Evil-Ollama",
    project_urls={
        "Documentation": "https://github.com/evogix/Evil-Ollama/blob/main/DOCS.md",
        "Source": "https://github.com/evogix/Evil-Ollama",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "evilollama=evilollama:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Penetration Testing",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="ollama, security, bug-bounty, llm, ai, pentesting, red-team",
    include_package_data=True,
    zip_safe=False,
)
