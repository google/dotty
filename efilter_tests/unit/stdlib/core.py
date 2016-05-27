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
    def testFirst(self):
        self.assertEqual(core.First()(repeated.meld(1, 2, 3, 4)), 1)

        self.assertEqual(core.First()(1), 1)

        self.assertEqual(core.First()([1, 2]), [1, 2])

        self.assertEqual(core.First()(None), None)

    # Sigh. Python can't even do lexical scoping properly, which is why this
    # is class-level instead of being function-local below (since the nested
    # function can't see locals from the surrounding scope.)
    __generator_has_run = None

    def testMaterialize(self):
        self.__generator_has_run = False

        def _gen():
            if self.__generator_has_run:
                raise ValueError("This should only run once.")

            self.__generator_has_run = True
            yield 1
            yield 2
            yield 3

        lazyseq = repeated.lazy(_gen)
        self.assertValuesEqual(lazyseq, repeated.repeated(1, 2, 3))

        # Accessing this for a second time should blow up.
        with self.assertRaises(ValueError):
            core.Materialize()(lazyseq)

        # So let's reset and do this with a materialized seq.
        self.__generator_has_run = False
        materialized = core.Materialize()(lazyseq)
        self.assertEqual(materialized, repeated.repeated(1, 2, 3))

        # And a second time.
        self.assertEqual(materialized, repeated.repeated(1, 2, 3))

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

    def testFind(self):
        self.assertEqual(core.Find()("foobar", "bar"), 3)
