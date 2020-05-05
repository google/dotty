#!/usr/bin/env python
import os
import setuptools

from setuptools import find_packages, setup, Command

current_directory = os.path.dirname(__file__)

ENV = {"__file__": __file__}
exec(open("efilter/_version.py").read(), ENV)
VERSION = ENV["get_versions"]()

if int(setuptools.__version__.split(".")[0]) < 8:
    raise RuntimeError("Rekall requires at least setuptool version 8.0. "
                       "Please upgrade with 'pip install --upgrade setuptools'")


class CleanCommand(Command):
    description = ("custom clean command that forcefully removes "
                   "dist/build directories")
    user_options = []

    def initialize_options(self):
        self.cwd = None

    def finalize_options(self):
        self.cwd = os.getcwd()

    def run(self):
        if os.getcwd() != self.cwd:
            raise RuntimeError('Must be in package root: %s' % self.cwd)

        os.system('rm -rf ./build ./dist')


commands = {}
commands["clean"] = CleanCommand


setup(name="rekall-efilter",
      version=VERSION["pep440"],
      cmdclass=commands,
      description="EFILTER query language",
      long_description=(
          "EFILTER is a general-purpose destructuring and search language "
          "implemented in Python, and suitable for integration with any "
          "Python project that requires a search function for some of its "
          "data."),
      license="Apache 2.0",
      author="Adam Sindelar and Michael Cohen",
      author_email="adam.sindelar@gmail.com and mic@rekall-innovations.com",
      url="https://github.com/google/dotty/",
      packages=find_packages(".", exclude=["efilter_tests*"]),
      package_dir={"efilter": "efilter"},
      install_requires=[
          "python-dateutil > 2",
          "future==0.16.0",
          "pytz >= 2011k",
          "six >= 1.4.0"]
)
