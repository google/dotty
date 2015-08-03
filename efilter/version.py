# EFILTER Forensic Query Language
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
EFILTER versioning scheme.

EFILTER version is the UTC UNIX epoch of the git commit that the package is
being built from. This allows us to disambiguate different builds of the same
major version, and simply map each build back to the commit it came from.

It would be more convenient to just use the git commitish as version strings,
but PEP 0440 mandates that version numbers increment over time, which the
commitish, being output of a hash function, doesn't.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import re

try:
    import datetime
    import pytz
    import subprocess

    # The below functionality is only available if dateutil is installed.
    from dateutil import parser

    def _unix_epoch(date):
        """Convert datetime object to a UTC UNIX timestamp."""
        td =  date - datetime.datetime(1970, 1, 1, tzinfo=pytz.UTC)
        return int(td.total_seconds())

    def run_git_log():
        """Generate version based on date of last commit.

        Returns:
            UTC UNIX timestamp as int on success, or None.
        """
        try:
            p = subprocess.Popen(
                ["git", "log", "-1", "--format=%cd", "--date=iso-strict"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            p.stderr.close()
            output = p.stdout.readlines()[0]
            date = parser.parse(output)
            return _unix_epoch(date)
        except (OSError, IndexError):
            # Even if git log fails (because it's not in a git repo), the call
            # may still 'succeed' as far as subprocess.Popen is concerned,
            # hence the IndexError exception. I don't know why Python sometimes
            # ignores the return code.
            return None
except ImportError:
    # If there's no dateutil then doing the git tango is pointless.
    def run_git_log():
        pass


def get_pkg_version():
    """Get version string by parsing PKG-INFO."""
    try:
        with open("PKG-INFO", "r") as fp:
            rgx = re.compile(r"Version: (\d+)")
            for line in fp.readlines():
                match = rgx.match(line)
                if match:
                    return match.group(1)
    except IOError:
        return None


def get_version():
    """Tries to get the EFILTER version from git or PKG-INFO.

    The EFILTER version is the UTC UNIX epoch of latest git commit.

    Example:
        1438623992
    """
    version = run_git_log()
    if version:
        return version

    version = get_pkg_version()
    if version:
        return version

    raise RuntimeError("Couldn't get git log or PKG-INFO to guess version.")
