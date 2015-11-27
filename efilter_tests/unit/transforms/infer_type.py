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

from efilter_tests import mocks
from efilter_tests import testlib

from efilter import protocol
from efilter import query as q

from efilter.transforms import infer_type

from efilter.protocols import boolean
from efilter.protocols import number


class InferTypeTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""

    def testVar(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.pid"),
                mocks.MockRootType),
            int)

    def testLiteral(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("42"),
                mocks.MockRootType),
            number.INumber)

    def testVar(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("foo"),
                mocks.MockRootType),
            protocol.AnyType)

    def testEquivalence(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.name == 'init'"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testComplement(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("not Process.name"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testReverse(self):
        """Reverse should preserve the type of the operand."""
        self.assertIsa(
            infer_type.infer_type(
                q.Query(("reverse", ("repeat", 1, 2, 3))),
                mocks.MockRootType),
            number.INumber)

    def testIsInstance(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("proc isa Process"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testBinaryExpression(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("'foo' in ('bar', 'foo')"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testSelect(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process['pid']", syntax="dottysql"),
                mocks.MockRootType),
            number.INumber)

        self.assertEquals(
            infer_type.infer_type(
                q.Query("Process[var_name]", syntax="dottysql"),
                mocks.MockRootType),
            protocol.AnyType)

    def testAny(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("any Process.parent where (name == 'init')"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testEach(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("any Process.children where (name == 'init')"),
                mocks.MockRootType),
            boolean.IBoolean)

    def testVariadicExpression(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("5 + 5"),
                mocks.MockRootType),
            number.INumber)

        self.assertIsa(
            infer_type.infer_type(
                q.Query("10 * (1 - 4) / 5"),
                mocks.MockRootType),
            number.INumber)

    def testApply(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("mock_func(5, 10)", syntax="dottysql"),
                mocks.MockRootType),
            number.INumber)

    def testRepeat(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query(("repeat", 1, 2, 3)),
                mocks.MockRootType),
            number.INumber)

    def testFilter(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("find Process where (parent.pid == 10)"),
                mocks.MockRootType),
            mocks.Process)

    def testSort(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("sort Process where (parent.pid)"),
                mocks.MockRootType),
            mocks.Process)

    def testMap(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.parent where (pid + 10)"),
                mocks.MockRootType),
            number.INumber)

        # Should be the same using shorthand syntax.
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.parent.pid - 1"),
                mocks.MockRootType),
            number.INumber)
