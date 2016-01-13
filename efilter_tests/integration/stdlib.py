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

from efilter import api

from efilter.protocols import repeated


class StdlibIntegrationTest(testlib.EfilterTestCase):
    def testFuncCalls(self):
        """Test that function calls are completed."""
        self.assertEqual(api.apply("count((1, 2, 3))"), 3)

    def testDropAndTake(self):
        """Test that dropping and taking works properly."""
        self.assertValuesEqual(
            api.apply("drop(2, (1, 2, 3, 4))"),
            repeated.meld(3, 4))

        self.assertValuesEqual(
            api.apply("drop(3, (1, 2, 3, 4))"), 4)

        self.assertValuesEqual(
            api.apply("take(1, drop(2, (1, 2, 3, 4)))"), 3)

        # Alternate syntax to do the same thing.
        self.assertValuesEqual(
            api.apply("SELECT * FROM (1, 2, 3, 4) LIMIT 1 OFFSET 2"), 3)

    def testCountLists(self):
        """Test that count supports lists and IRepeated."""
        self.assertEqual(api.apply("count((1, 2, 3))"), 3)

        # Lists should work.
        self.assertEqual(api.apply("count([1, 2, 3])"), 3)

        # IRepeated are flat.
        self.assertEqual(api.apply("count((1, (2, 3)))"), 3)

        # Lists are not.
        self.assertEqual(api.apply("count([1, [2, 3]])"), 2)

    def testCountFilter(self):
        self.assertEqual(
            api.apply("count(select * from people where age > 20)",
                      people=[{"age": 10}, {"age": 30}, {"age": 15},
                              {"age": 35}]),
            2)

    def testReverseLists(self):
        """Test that reverse supports both lists and IRepeated."""
        # "lists" are actually Python tuples.
        self.assertEqual(api.apply("reverse([1, 2, 3])"), (3, 2, 1))

        self.assertEqual(api.apply("reverse((1, 2, 3))"),
                         repeated.meld(3, 2, 1))
