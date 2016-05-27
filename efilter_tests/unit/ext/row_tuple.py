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

from efilter.protocols import associative
from efilter.protocols import counted
from efilter.protocols import structured

from efilter.ext import row_tuple


class RowTupleTest(testlib.EfilterTestCase):
    def testOrderPreserved(self):
        rt = row_tuple.RowTuple(values=dict(foo="Foo", bar="Bar", car="Car"),
                                ordered_columns=["car", "bar", "foo"])

        self.assertEqual(["Car", "Bar", "Foo"], list(rt))
        self.assertEqual(rt["car"], "Car")
        self.assertEqual(rt[0], "Car")

    def testPartialFill(self):
        rt = row_tuple.RowTuple(ordered_columns=["foo", "bar", "car"])

        # Test that we raise correct exceptions on out-of-bounds access.
        with self.assertRaises(IndexError):
            _ = rt[1]

        with self.assertRaises(KeyError):
            _ = rt["foo"]

        rt["bar"] = "Bar"
        self.assertEqual(rt["bar"], "Bar")
        self.assertEqual(rt[1], "Bar")

    def testStrictColumns(self):
        rt = row_tuple.RowTuple(ordered_columns=["foo", "bar", "car"])

        with self.assertRaises(KeyError):
            rt["baz"] = "Baz"

        with self.assertRaises(IndexError):
            rt[5] = "Bzz"

    def testCompare(self):
        rt = row_tuple.RowTuple(ordered_columns=["foo", "bar", "car"])
        rt2 = row_tuple.RowTuple(ordered_columns=["foo", "bar", "car"])
        self.assertEqual(rt, rt2)

        self.assertEqual(rt, {"foo": None, "bar": None, "car": None})
        self.assertEqual(rt, [None, None, None])

        rt[1] = "Hello"
        self.assertEqual(rt, [None, "Hello", None])
        self.assertEqual(rt, {"foo": None, "bar": "Hello", "car": None})

    def testTupleSet(self):
        rt = row_tuple.RowTuple(ordered_columns=["foo", "bar", "car"])

        rt["foo"] = "Foo"
        rt[0] = "Nope"
        self.assertEqual(rt["foo"], "Nope")

    def testInterfaces(self):
        rt = row_tuple.RowTuple(values=dict(foo="Foo", bar="Bar", car="Car"),
                                ordered_columns=["car", "bar", "foo"])

        self.assertEqual(len(rt), 3)
        self.assertEqual(counted.count(rt), 3)
        self.assertEqual(list(rt), ["Car", "Bar", "Foo"])

        self.assertEqual(associative.select(rt, 2), "Foo")
        with self.assertRaises(KeyError):
            associative.select(rt, "foo")

        with self.assertRaises(KeyError):
            structured.resolve(rt, 2)

        self.assertEqual(structured.resolve(rt, "foo"), "Foo")
