#!/usr/bin/env python3
"""Setup script for IL2CPP Dumper Python port."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="il2cpp-dumper",
    version="0.1.0",
    author="Python Port",
    description="Extract metadata from Unity IL2CPP compiled games",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/il2cpp-dumper-py",
    packages=find_packages(),
    package_data={
        "il2cpp_dumper_py": ["config.json"],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Disassemblers",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies for core functionality
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.0",
        ],
        "lz4": [
            "lz4>=4.0.0",  # For LZ4 compressed files
        ],
    },
    entry_points={
        "console_scripts": [
            "il2cpp-dumper=il2cpp_dumper_py.cli:main",
        ],
    },
)
