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

from efilter.protocols import repeated

from efilter.stdlib import core


class CoreTest(testlib.EfilterTestCase):
    def testTake(self):
        self.assertValuesEqual(
            core.Take()(2, repeated.meld(1, 2, 3, 4)),
            repeated.meld(1, 2))

        # Also should support tuples.
        self.assertValuesEqual(
            core.Take()(2, (1, 2, 3, 4)),
            repeated.meld(1, 2))

        # Exceeding the bounds is fine.
        self.assertValuesEqual(
            core.Take()(10, (1, 2, 3)),
            repeated.meld(1, 2, 3))

        # Taking zero.
        self.assertValuesEqual(
            core.Take()(0, (1, 2, 3)),
            None)

        # Taking from empty.
        self.assertValuesEqual(
            core.Take()(10, ()),
            None)

    def testDrop(self):
        self.assertValuesEqual(
            core.Drop()(2, repeated.meld(1, 2, 3, 4)),
            repeated.meld(3, 4))

        # Also should support tuples.
        self.assertValuesEqual(
            core.Drop()(2, (1, 2, 3, 4)),
            repeated.meld(3, 4))

        # Exceeding bounds is fine.
        self.assertValuesEqual(
            core.Drop()(10, (1, 2, 3)),
            None)

        # Dropping zero.
        self.assertValuesEqual(
            core.Drop()(0, (1, 2, 3)),
            repeated.meld(1, 2, 3))

    def testCount(self):
        self.assertEqual(
            core.Count()(repeated.meld(1, 2, 3, 4)),
            4)

    def testReverse(self):
        self.assertEqual(
            core.Reverse()(repeated.meld(1, 2, 3, 4)),
            repeated.meld(4, 3, 2, 1))

    def testLower(self):
        self.assertEqual(
            core.Lower()("FOO"),
            "foo")
