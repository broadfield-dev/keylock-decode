# setup.py
from setuptools import setup, find_packages

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Function to extract version from __init__.py to avoid importing the package
def get_version(rel_path):
    import os
    import re
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, rel_path), 'r') as fp:
        for line in fp.read().splitlines():
            if line.startswith('__version__'):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")

VERSION = get_version("keylock_decode/__init__.py")


setup(
    name="keylock-decode", # PyPI distribution name
    version=VERSION,
    author="broadfield-dev",
    author_email="none@example.com",
    description="A library and CLI tool to decode steganographically hidden, encrypted data from PNG images.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/broadfield-dev/keylock-decode",
    packages=find_packages(include=['keylock_decode', 'keylock_decode.*']),
    install_requires=[
        "Pillow>=9.0.0",        # For image manipulation
        "numpy>=1.20.0",        # For array operations on pixels
        "cryptography>=3.4.0",  # For AES-GCM and PBKDF2
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
        "Typing :: Typed",
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'keylock-decode=keylock_decode.cli:main_cli', # CLI command 'keylock-decode'
        ],
    },
    keywords='steganography decoder aes gcm png security key management environment variables API wallet',
) 
