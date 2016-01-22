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

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter_tests import testlib
from efilter_tests.fixtures import small_csv

from efilter.ext import csv_reader

from efilter.protocols import repeated


class LazyFileReadersTest(testlib.EfilterTestCase):
    def testReading(self):
        """Test that reader reads the same lines as the File object."""
        with open(testlib.get_fixture_path("small.csv"), "rb") as fd:
            reader = csv_reader.LazyCSVReader(fd)
            self.assertValuesEqual(reader, repeated.meld(*small_csv.EXPECTED))

    def testDicts(self):
        """Test building dicts."""
        with open(testlib.get_fixture_path("small.csv"), "rb") as fd:
            reader = csv_reader.LazyCSVReader(fd, output_dicts=True)
            first_row = next(iter(reader))
            self.assertEqual(dict(Name="Alice", Age="25", City="Zurich"),
                             first_row)

    def testCloseInDestructor(self):
        fd = open(testlib.get_fixture_path("names.txt"), "rb")
        reader = csv_reader.LazyCSVReader(fd)

        for _ in reader:
            pass

        reader = None
        self.assertTrue(fd.closed)
