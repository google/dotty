#!/usr/bin/env python

from efilter import version
from setuptools import find_packages, setup

setup(name="efilter",
      version=version.get_version(),
      description="EFILTER query language",
      license="Apache 2.0",
      author="Adam Sindelar",
      author_email="adam.sindelar@gmail.com",
      url="https://github.com/google/dotty/",
      packages=find_packages(exclude=["efilter_tests*"]),
      package_dir={"efilter": "efilter"},
      install_requires=[
          "python-dateutil > 2",
          "pytz >= 2011k"])