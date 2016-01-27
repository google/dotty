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

from efilter.protocols import indexable
from efilter.ext import indexset

from efilter_tests import testlib


class FakeIndexable(object):
    def __init__(self, indices, value):
        self.indices = indices
        self.value = value

    def __lt__(self, other):
        return self.indices < other.indices

    def __repr__(self):
        return "FakeIndexable(%s)" % repr(self.value)


indexable.IIndexable.implement(
    for_type=FakeIndexable,
    implementations={
        indexable.indices: lambda obj: obj.indices
    }
)


class IndexSetTest(testlib.EfilterTestCase):
    def testSingleSet(self):
        e1 = FakeIndexable(["enum_foo", 1], "foo")
        e2 = FakeIndexable(["enum_bar", 2, "bar"], "bar")
        e3 = FakeIndexable(["enum_baz", 3], "baz")

        iset = indexset.IndexSet([e1, e3])

        self.assertItemsEqual(iset.values, [e1, e3])
        self.assertEqual(e1, iset.get_index(1))
        self.assertEqual(e1, iset.get_index("enum_foo"))

        self.assertEqual(len(iset), 2)
        iset.add(e3)
        self.assertEqual(len(iset), 2)
        iset.add(e2)
        self.assertEqual(len(iset), 3)
        iset.remove(e1)
        self.assertEqual(len(iset), 2)

        with self.assertRaises(KeyError):
            iset.remove(e1)

        self.assertEqual(len(iset), 2)
        self.assertItemsEqual(iset.values, [e2, e3])

        iset.remove(e2)
        iset.discard(e1)
        iset.pop()
        self.assertEqual(len(iset), 0)
        self.assertEqual(bool(iset), False)
        self.assertEqual(iset.values, [])

        iset.add(e1)
        self.assertEqual(iset.pop().value, e1.value)

    def testSetUnion(self):
        elements = [FakeIndexable([i, "s%d" % i, (i, None)], i)
                    for i in range(20)]

        iset1 = indexset.IndexSet(elements[0:9])
        iset2 = indexset.IndexSet(elements[10:19])

        self.assertTrue(iset1.isdisjoint(iset2))

        iset3 = iset1 | iset2
        self.assertTrue(iset3.issuperset(iset1))
        self.assertTrue(iset2.issubset(iset3))

        iset1 |= iset2
        self.assertTrue(iset1.issuperset(iset2))
        self.assertTrue(iset2.issubset(iset2))
        self.assertEqual(iset1, iset3)

    def testSetIntersection(self):
        elements = [FakeIndexable([i, "s%d" % i, (i, None)], i)
                    for i in range(20)]

        iset1 = indexset.IndexSet(elements[0:15])
        iset2 = indexset.IndexSet(elements[10:19])

        iset3 = iset1 & iset2
        self.assertEqual(len(iset3), 5)

        iset1 &= iset2
        self.assertItemsEqual(iset1, iset3)
        self.assertTrue(iset1 == iset3)
