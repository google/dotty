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

import unittest

from efilter.ext import lazy_repetition

from efilter.protocols import repeated


class LazyRepetitionTest(unittest.TestCase):
    def testRestarting(self):
        def _generator():
            yield "a"
            yield "b"
            yield "c"
            yield "d"

        l = lazy_repetition.LazyRepetition(_generator)

        # Get the type of the first value.
        self.assertEqual(str, l.value_type())

        # But still iterate from idx 0.
        self.assertItemsEqual(l.getvalues(), ("a", "b", "c", "d"))

        # Second iteration should still work!
        self.assertItemsEqual(l.getvalues(), ("a", "b", "c", "d"))

    def testApply(self):
        def _generator():
            yield 1
            yield 2

        l = lazy_repetition.LazyRepetition(_generator)
        self.assertItemsEqual(l.value_apply(lambda x: x * 2).getvalues(),
                              [2, 4])

    def testScalarCompare(self):
        def _generator():
            yield 1

        l = lazy_repetition.LazyRepetition(_generator)
        self.assertTrue(l.value_eq(1))

        self.assertEqual(int, l.value_type())

    def testCompare(self):
        def _generator():
            yield 1
            yield 2
            yield 3

        self.assertEqual(lazy_repetition.LazyRepetition(_generator),
                         repeated.meld(1, 2, 3))
