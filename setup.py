from setuptools import setup, find_packages

setup(
    name="database",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=39.0.0",
    ],
)
