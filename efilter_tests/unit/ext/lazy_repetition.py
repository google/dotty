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

from efilter.ext import lazy_repetition

from efilter.protocols import applicative
from efilter.protocols import eq
from efilter.protocols import repeated

from efilter_tests import testlib


class LazyRepetitionTest(testlib.EfilterTestCase):
    def testRestarting(self):
        def _generator():
            yield "a"
            yield "b"
            yield "c"
            yield "d"

        l = lazy_repetition.LazyRepetition(_generator)

        # But still iterate from idx 0.
        self.assertItemsEqual(l.getvalues(), ("a", "b", "c", "d"))

        # Second iteration should still work!
        self.assertItemsEqual(l.getvalues(), ("a", "b", "c", "d"))

    def testProtocol(self):
        def _generator():
            yield "a"

        single = lazy_repetition.LazyRepetition(_generator)
        self.assertEqual(list(repeated.getvalues(single)), ["a"])
        self.assertEqual(repeated.getvalue(single), "a")

        def _generator():
            yield "a"
            yield "b"

        double = lazy_repetition.LazyRepetition(_generator)
        self.assertEqual(list(repeated.getvalues(double)), ["a", "b"])
        self.assertEqual(repeated.getvalue(double), "a")

    def testCompare(self):
        def _generator():
            yield 1
            yield 2
            yield 3

        self.assertTrue(
            eq.eq(lazy_repetition.LazyRepetition(_generator),
                  repeated.meld(1, 2, 3)))
