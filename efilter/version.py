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

try:
    import datetime
    import pytz
    import subprocess

    # The below functionality is only available if dateutil is installed.
    from dateutil import parser

    def _unix_epoch(date):
        """Convert datetime object to a UTC UNIX timestamp."""
        td = date - datetime.datetime(1970, 1, 1, tzinfo=pytz.UTC)
        return int(td.total_seconds())

    def git_generate_version():
        """Generate version string from git log and revcount."""
        date = git_last_commit_time()
        revcount = git_commit_count()
        if not (date and revcount):
            return None

        return "%d.%d.%d" % (date.year, date.month, revcount)

    def git_last_commit_time():
        """Return the timestamp of the latest git commit on this branch."""
        try:
            p = subprocess.Popen(
                ["git", "log", "-1", "--format=%cd", "--date=iso"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            errors = p.stderr.read()
            p.stderr.close()
            output = p.stdout.readlines()[0]
            date = parser.parse(output)

            return date
        except (OSError, IndexError):
            # Even if git log fails (because it's not in a git repo), the call
            # may still 'succeed' as far as subprocess.Popen is concerned,
            # hence the IndexError exception. I don't know why Python sometimes
            # ignores the return code.
            if errors:
                logging.warn("Git log failed: %r" % errors)

            return None

    def git_commit_count():
        """Return the count of commits on the current branch."""
        try:
            p = subprocess.Popen(
                ["git", "rev-list", "--count", "master"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            errors = p.stderr.read()
            p.stderr.close()
            output = p.stdout.readlines()[0]
            revcount = int(output)

            return revcount
        except (OSError, IndexError):
            if errors:
                logging.warn("Git rev-list failed: %r" % errors)

            return None

except ImportError:
    logging.warn("pytz or dateutil are not available - getting a version "
                 "number from git won't work.")
    # If there's no dateutil then doing the git tango is pointless.

    def git_generate_version():
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


def get_version_txt():
    """Get version string from version.txt."""
    try:
        with open("version.txt", "r") as fp:
            return fp.read().strip()
    except IOError:
        return None


def get_version(generate_version=False):
    """Gets the version from version.txt, PKG_INFO or git, in that order.

    Arguments:
        generate_version: Try git first.

    Example:
        2016.04.42
    """
    if generate_version:
        version = git_generate_version()
        if version:
            return version

    version = get_version_txt()
    if version:
        return version

    version = get_pkg_version()
    if version:
        return version

    logging.warn(
        "Couldn't get version from version.txt or PKG_INFO. Will try git.")

    version = git_generate_version()
    if version:
        return version

    raise RuntimeError(
        "Couldn't get version from version.txt, PKG_INFO or git.")
