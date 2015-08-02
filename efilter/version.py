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
EFILTER versioning.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import datetime
from dateutil import parser
import pytz
import re
import subprocess


def _unix_epoch(date):
    td =  date - datetime.datetime(1970, 1, 1, tzinfo=pytz.UTC)
    return int(td.total_seconds())


def run_git_log():
    """Generate version based on date of last commit."""
    try:
        p = subprocess.Popen(
            ["git", "log", "-1", "--format=%cd", "--date=iso-strict"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        p.stderr.close()
        output = p.stdout.readlines()[0]
        date = parser.parse(output)
        return _unix_epoch(date)
    except (OSError, IndexError):
        # Even if git log fails (because it's not in a git repo), the call may
        # still 'succeed' as far as subprocess.Popen is concerned, hence the
        # IndexError exception. No, I don't know why Python sometimes ignores
        # the return code.
        return None


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
    """Get a version string as date of last commit or else parse PKG-INFO.

    Example:
        2015.07.10
    """
    version = run_git_log()
    if version:
        return version

    version = get_pkg_version()
    if version:
        return version

    raise RuntimeError("Couldn't get git log or PKG-INFO to guess version.")