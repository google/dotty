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

from efilter import query

from efilter.transforms import asdotty


class AsDottyTest(unittest.TestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def assertOutput(self, original, output):
        q = query.Query(original, syntax="dotty")
        actual_output = asdotty.asdotty(q)
        self.assertEqual(output, actual_output)

    def testVariadicExpression(self):
        self.assertOutput(original="5 + 5 + 10 == 20",
                          output="5 + 5 + 10 == 20")

    def testMap(self):
        self.assertOutput(original="Process.name == 'foo'",
                          output="Process.name == 'foo'")

    def testWithin(self):
        self.assertOutput(
            original="Process.parent where (name == 'foo' and pid == 5)",
            output="Process.parent where (name == 'foo' and pid == 5)")

    def testAny(self):
        self.assertOutput(
            original="any Process.parent where (name == 'foo')",
            output="any Process.parent where (name == 'foo')")

    def testEach(self):
        self.assertOutput(
            original="each Process.parent where (name == 'foo')",
            output="each Process.parent where (name == 'foo')")

    def testLiteral(self):
        self.assertOutput(
            original="'foo'",
            output="'foo'")

    def testBinding(self):
        self.assertOutput(
            original="foo",
            output="foo")

    def testComplement(self):
        self.assertOutput(
            original="not Process.active",
            output="not Process.active")

        self.assertOutput(
            original="not active",
            output="not active")

        self.assertOutput(
            original="not any Process where (active and sleeping)",
            output="not any Process where (active and sleeping)")

    def testComplementSubExpr(self):
        self.assertOutput(
            original="not (Process.active and Process.sleeping)",
            output="not (Process.active and Process.sleeping)")

    def testComplementOfEquivalence(self):
        """This should correctly yield !=."""
        self.assertOutput(
            original="Process.pid != 10",
            output="Process.pid != 10")

    def testBinaryExpression(self):
        self.assertOutput(
            original="5 in (10, 5)",
            output="5 in (10, 5)")

    def testIsInstance(self):
        self.assertOutput(
            original="adam isa User",
            output="adam isa User")
