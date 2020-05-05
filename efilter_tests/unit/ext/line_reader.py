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
EFILTER test suite.
"""

from builtins import next
__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter_tests import testlib

from efilter.ext import line_reader

from efilter.protocols import repeated


class LazyFileReadersTest(testlib.EfilterTestCase):
    def testReading(self):
        """Test that reader reads the same lines as the File object."""
        with open(testlib.get_fixture_path("names.txt"), "r") as fd:
            line_count = len(list(fd))
            # The fact that the fd.tell() is now at EOF shouldn't matter.
            reader = line_reader.LazyLineReader(fd)
            self.assertEqual(len(list(reader)), line_count)

    def testRestarting(self):
        """Test that the reader can restart and support multiple users."""
        with open(testlib.get_fixture_path("names.txt"), "r") as fd:
            reader = line_reader.LazyLineReader(fd)
            iterator = iter(reader)
            iterator2 = iter(reader)

            self.assertEqual(next(iterator), next(iterator2))

    def testCloseInDestructor(self):
        fd = open(testlib.get_fixture_path("names.txt"), "r")
        reader = line_reader.LazyLineReader(fd)

        for _ in reader:
            pass

        reader = None
        self.assertTrue(fd.closed)
