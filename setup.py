from setuptools import setup

import suricataparser


setup(
    name="suricataparser",
    version=suricataparser.__version__,
    author="Michail Tsyganov",
    url="https://github.com/m-chrome/py-suricataparser",
    description="Suricata rule parser",
    packages=["suricataparser"],
    python_requires=">=3.6",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ]
)
