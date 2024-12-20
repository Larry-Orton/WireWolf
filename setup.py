from setuptools import setup, find_packages

setup(
    name="wirewolf",
    version="1.0.0",
    author="Larry Orton",
    author_email="larry.orton@berkeley.edu",
    description="A modern network scanning tool for cybersecurity professionals.",
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
            "wirewolf=wirewolf.scanner:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
