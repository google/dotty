#!/usr/bin/env python

import re
import subprocess

from setuptools import find_packages, setup

def run_git_log():
    p = subprocess.Popen(
        ["git", "log", "-1", "--format=%cd", "--date=short"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    p.stderr.close()
    return p.stdout.readlines()[0]

def get_efilter_version():
    """Get a version string as date of last commit.

    Example:
        2015.07.10
    """
    return "%s.%s.%s" % re.match(r"(\d+)-(\d+)-(\d+)", run_git_log()).groups()

setup(name="efilter",
      version=get_efilter_version(),
      description="EFILTER query language",
      license="Apache 2.0",
      author="Adam Sindelar",
      author_email="adam.sindelar@gmail.com",
      url="https://github.com/google/dotty/",
      packages=find_packages(exclude=["tests*"]),
      package_dir={"efilter": "efilter"})
