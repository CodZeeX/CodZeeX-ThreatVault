from setuptools import setup, find_packages

setup(
    name="threatvault",
    version="2.4.0",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "threatvault=threatvault.cli:main",
        ],
    },
    author="RobsHs (CodZeeX)",
    author_email="fredapacitan@gmail.com",
    description="Enterprise Open-Source Threat Intelligence, Detection Engineering & System Hardening Framework",
    url="https://github.com/CodZeeX/CodZeeX-ThreatVault",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
