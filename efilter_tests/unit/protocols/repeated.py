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

import six
import unittest

from efilter.protocols import repeated


class RepeatedTest(unittest.TestCase):
    def assertValueEq(self, x, y):
        return self.assertTrue(repeated.value_eq(x, y))

    def testCreation(self):
        """Test that creation is reasonable."""
        # This should make a repeated var of two values.
        r = repeated.repeated("foo", "bar")
        # It should be a repeated var.
        self.assertIsInstance(r, repeated.IRepeated)
        # And also have more than one value.
        self.assertTrue(repeated.isrepeating(r))

        # Repeating a single value will still create a repeated var.
        r = repeated.repeated("foo")
        self.assertIsInstance(r, repeated.IRepeated)
        # But it won't be repeating (have more than one value).
        self.assertFalse(repeated.isrepeating(r))

        # Using meld will just return a scalar on one value.
        r = repeated.meld("foo")
        self.assertIsInstance(r, six.string_types)

        # Meld on two values has the same behavior as repeated.
        r = repeated.meld("foo", "foo")
        self.assertIsInstance(r, repeated.IRepeated)

    def testNulls(self):
        r = None
        for _ in repeated.getvalues(r):
            # Should be zero elements but not raise.
            self.assertFail()

        r = repeated.meld(None, None)
        # None should get skipped.
        for _ in repeated.getvalues(r):
            self.assertFail()

    def testTypes(self):
        """Test that types are correctly derived and enforced."""
        with self.assertRaises(TypeError):
            repeated.repeated(1, "foo")

        with self.assertRaises(TypeError):
            repeated.meld(1, "foo")

    def testNesting(self):
        """Test that repeated vars remain flat."""
        r = repeated.repeated("foo", "bar")
        r = repeated.repeated(r, "baz")
        self.assertValueEq(repeated.repeated("foo", "bar", "baz"), r)

        r = repeated.repeated("zoo", r)
        self.assertValueEq(repeated.repeated("zoo", "foo", "bar", "baz"), r)

        # value_eq should ignore order.
        self.assertValueEq(repeated.repeated("bar", "foo", "baz", "zoo"), r)

        # Order should be preserved for getvalues, though.
        self.assertEqual(repeated.getvalues(r), ["zoo", "foo", "bar", "baz"])

        self.assertEqual(repeated.value_type(r), type("foo"))

    def testApplication(self):
        """Test function application across values."""
        self.assertEqual(
            repeated.repeated(2, 4),
            repeated.value_apply(
                repeated.repeated(1, 2),
                lambda x: x * 2))

        # As everything working on values, this should also work on scalars.
        applied = repeated.value_apply(5, lambda x: x * 2)
        self.assertValueEq(10, applied)
