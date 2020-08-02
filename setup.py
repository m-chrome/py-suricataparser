from setuptools import setup

import suricataparser


setup(
    name="suricataparser",
    version=suricataparser.__version__,
    author="Michail Tsyganov",
    description="Suricata rule parser",
    packages=["suricataparser"],
    python_requires=">=3.6"
)
