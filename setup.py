#!/usr/bin/env python

import sys

try:
    from setuptools import find_packages, setup
except ImportError:
    from distutils.core import find_packages, setup

try:
    from setuptools.commands.bdist_rpm import bdist_rpm
except ImportError:
    from distutils.command.bdist_rpm import bdist_rpm

try:
    from setuptools.command.sdist import sdist
except ImportError:
    from distutils.command.sdist import sdist

# Change PYTHONPATH to include efilter so that we can get the version.
sys.path.insert(0, ".")

from efilter import version


__version__ = version.get_txt_version()


class BdistRPMCommand(bdist_rpm):
    """Custom handler for the bdist_rpm command."""

    def _make_spec_file(self):
        """Generates the text of an RPM spec file.

        Returns:
          A list of strings containing the lines of text.
        """
        # Note that bdist_rpm can be an old style class.
        if issubclass(BdistRPMCommand, object):
            spec_file = super(BdistRPMCommand, self)._make_spec_file()
        else:
            spec_file = bdist_rpm._make_spec_file(self)

        if sys.version_info[0] < 3:
            python_package = "python"
        else:
            python_package = "python3"

        description = []
        summary = ""
        in_description = False

        python_spec_file = []
        for line in spec_file:
            if line.startswith("Summary: "):
                summary = line

            elif line.startswith("BuildRequires: "):
                line = "BuildRequires: {0:s}-setuptools".format(python_package)

            elif line.startswith("Requires: "):
                if python_package == "python3":
                    line = line.replace("python", "python3")

            elif line.startswith("%description"):
                in_description = True

            elif line.startswith("%files"):
                line = "%files -f INSTALLED_FILES -n {0:s}-%{{name}}".format(
                    python_package)

            elif line.startswith("%prep"):
                in_description = False

                python_spec_file.append(
                    "%package -n {0:s}-%{{name}}".format(python_package))
                python_spec_file.append("{0:s}".format(summary))
                python_spec_file.append("")
                python_spec_file.append(
                    "%description -n {0:s}-%{{name}}".format(python_package))
                python_spec_file.extend(description)

            elif in_description:
                # Ignore leading white lines in the description.
                if not description and not line:
                    continue

                description.append(line)

            python_spec_file.append(line)

        return python_spec_file


class SDistCommand(sdist):
    """Custom handler for the sdist command."""

    def run(self):
        global __version__
        __version__ = version.get_version(False)
        with open("version.txt", "w") as fd:
            fd.write(__version__)

        # Need to use old style super class invocation here for
        # backwards compatibility.
        sdist.run(self)


setup(name="efilter",
      version=__version__,
      description="EFILTER query language",
      long_description=(
          "EFILTER is a general-purpose destructuring and search language "
          "implemented in Python, and suitable for integration with any "
          "Python project that requires a search function for some of its "
          "data."),
      license="Apache 2.0",
      author="Adam Sindelar",
      author_email="adam.sindelar@gmail.com",
      url="https://github.com/google/dotty/",
      packages=find_packages(exclude=["efilter_tests*"]),
      package_dir={"efilter": "efilter"},
      cmdclass={
          "bdist_rpm": BdistRPMCommand,
          "sdist": SDistCommand},
      install_requires=[
          "python-dateutil > 2",
          "pytz >= 2011k",
          "six >= 1.4.0"])
