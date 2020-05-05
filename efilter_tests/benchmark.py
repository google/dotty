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
EFILTER test helpers.
"""

from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"

import cProfile
import pstats
import six

from efilter_tests import testlib

from efilter import api

from efilter.protocols import counted
from efilter.protocols import repeated


class EfilterBenchmarkCase(object):
    __abstract = True

    _profile = None

    name = None
    fixture_name = None
    query = None

    def profile(self):
        if not self._profile:
            self.benchmark()

        return self._profile

    def fixture_len(self):
        with open(testlib.get_fixture_path(self.fixture_name), "r") as fd:
            return counted.count(repeated.lines(fd))

    def benchmark(self):
        profile = cProfile.Profile()
        profile.enable()
        self.run()
        profile.disable()

        self._profile = profile
        return profile

    def run(self):
        replacements = []
        if self.fixture_name is not None:
            replacements.append(testlib.get_fixture_path(self.fixture_name))

        result = api.apply(self.query, replacements=replacements, allow_io=True)

        # Force lazy results to be realized, but don't do anything with them.
        for _ in repeated.getvalues(result):
            pass

    def summary(self):
        return self.full_stats().split("\n")[0].strip()

    def full_stats(self, sortby="cumulative"):
        stream = six.StringIO()
        ps = pstats.Stats(self.profile(), stream=stream).sort_stats(sortby)
        ps.print_stats()
        return stream.getvalue()
