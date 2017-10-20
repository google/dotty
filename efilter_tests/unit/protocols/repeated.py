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

from efilter.protocols import eq
from efilter.protocols import repeated


class RepeatedTest(unittest.TestCase):
    def assertValueEq(self, x, y):
        return self.assertTrue(eq.eq(x, y))

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

        # It is repeating.
        self.assertTrue(repeated.isrepeating(r))

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

    def testNesting(self):
        """Test that repeated vars remain flat."""
        r = repeated.repeated("foo", "bar")
        r = repeated.repeated(r, "baz")
        self.assertValueEq(repeated.repeated("foo", "bar", "baz"), r)

        r = repeated.repeated("zoo", r)
        self.assertValueEq(repeated.repeated("zoo", "foo", "bar", "baz"), r)

        # Order should be preserved for getvalues, though.
        self.assertEqual(repeated.getvalues(r), ["zoo", "foo", "bar", "baz"])
