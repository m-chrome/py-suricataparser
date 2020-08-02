from setuptools import setup

import suricataparser


setup(
    name="suricataparser",
    version=suricataparser.__version__,
    author="Michail Tsyganov",
    url="https://github.com/m-chrome/py-suricataparser",
    description="Suricata rule parser",
    packages=["suricataparser"],
    python_requires=">=3.6"
)
