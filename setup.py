
from setuptools import setup, find_packages

setup(
    name="WireWolf",
    version="1.0.0",
    author="Larry Orton",
    author_email="larry.orton@berkeley.edu",
    description="A powerful network scanning tool for cybersecurity professionals.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "python-nmap",
        "requests",
        "geoip2",
        "ipwhois"
    ],
    entry_points={
        "console_scripts": [
            "WireWolf=WireWolf.scanner:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
