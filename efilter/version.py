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

EFILTER version is in the following format: YEAR.MONTH.REVCOUNT, where revcount
is the number of commits since initial commit on the master branch. This we
believe strikes a good balance between human readable strings, and ability to
tie a release to the git revision it was built from.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import logging
import re

RELEASE = "Awesome Sauce"
MAJOR = 1
MINOR = 2

ANCHOR_TAG = "v%d.%d" % (MAJOR, MINOR)

try:
    import datetime
    import pytz
    import subprocess

    # The below functionality is only available if dateutil is installed.
    from dateutil import parser

    def git_commits_since_tag(tag):
        try:
            p = subprocess.Popen(
                ["git", "log", "%s..master" % tag, "--oneline"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            errors = p.stderr.read()
            p.stderr.close()
            commits = p.stdout.readlines()

            return commits
        except (OSError, IndexError):
            if errors:
                logging.warn("git log failed with %r" % errors)

            return None

    def git_dev_version():
        commits = git_commits_since_tag(ANCHOR_TAG)
        if not commits:
            return "1!%d.%d.dev0" % (MAJOR, MINOR)

        return "1!%d.%d.dev%d" % (MAJOR, MINOR, len(commits))


except ImportError:
    logging.warn("pytz or dateutil are not available - getting a version "
                 "number from git won't work.")
    # If there's no dateutil then doing the git tango is pointless.

    def git_verbose_version():
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


def get_txt_version():
    """Get version string from version.txt."""
    try:
        with open("version.txt", "r") as fp:
            return fp.read().strip()
    except IOError:
        return None


def get_version(dev_version=False):
    """Generates a version string.

    Arguments:
        dev_version: Generate a verbose development version from git commits.

    Examples:
        1.1
        1.1.dev43 # If 'dev_version' was passed.
    """
    if dev_version:
        version = git_dev_version()
        if not version:
            raise RuntimeError("Could not generate dev version from git.")

        return version

    return "1!%d.%d" % (MAJOR, MINOR)
