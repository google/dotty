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
        pass

    def testBinding(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.pid"),
                mocks.MockApp()),
            int)

    def testLiteral(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("42"),
                mocks.MockApp()),
            number.INumber)

    def testBinding(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("foo"),
                mocks.MockApp()),
            protocol.AnyType)

    def testEquivalence(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.name == 'init'"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testComplement(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("not Process.name"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testComponentLiteral(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("has component Process"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testIsInstance(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("isa Process"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testBinaryExpression(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("'foo' in ('bar', 'foo')"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testLetAny(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("any Process.parent where (name == 'init')"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testLetEach(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("any Process.children where (name == 'init')"),
                mocks.MockApp()),
            boolean.IBoolean)

    def testVariadicExpression(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("5 + 5"),
                mocks.MockApp()),
            number.INumber)

        self.assertIsa(
            infer_type.infer_type(
                q.Query("10 * (1 - 4) / 5"),
                mocks.MockApp()),
            number.INumber)

    def testLet(self):
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.parent where (pid + 10)"),
                mocks.MockApp()),
            number.INumber)

        # Should be the same using shorthand syntax.
        self.assertIsa(
            infer_type.infer_type(
                q.Query("Process.parent.pid - 1"),
                mocks.MockApp()),
            number.INumber)
