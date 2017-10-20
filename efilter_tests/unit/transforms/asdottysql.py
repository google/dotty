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

from efilter import query

from efilter.transforms import asdottysql


class AsDottySQLTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testExpression(self):
        """Get coverage test to shut up."""
        pass

    def assertOutput(self, original, output):
        q = query.Query(original)
        actual_output = asdottysql.asdottysql(q)
        self.assertEqual(output, actual_output)

        actual_root = query.Query(actual_output).root
        self.assertEqual(q.root, actual_root)

    def testLiteral(self):
        self.assertOutput(original="5", output="5")

    def testVar(self):
        self.assertOutput(original=("var", "x"), output="x")

    def testWithin(self):
        self.assertOutput(
            original=("filter", ("var", "x"), ("var", "y")),
            output="filter(x, y)")

        self.assertOutput(
            original="filter(map(x.y, foo + 5), foo.bar == 5)",
            output="filter(map(x.y, foo + 5), foo.bar == 5)")

    def testMap(self):
        self.assertOutput(
            original=(".", (".", ("var", "x"), "y"), "z"),
            output="x.y.z")

    def testLet(self):
        self.assertOutput(
            original="let(x = 5, y = 10) x * y",
            output="let(x = 5, y = 10) x * y")

    def testNumericExpression(self):
        self.assertOutput(
            original="x + y * 10 + z",
            output="x + y * 10 + z")

        self.assertOutput(
            original="(x + y) * 10 + z",
            output="(x + y) * 10 + z")

        self.assertOutput(
            original="(x + y.w) * (10 + z.w)",
            output="(x + y.w) * (10 + z.w)")

    def testRelation(self):
        self.assertOutput(
            original=("==", ("var", "x"), ("var", "y")),
            output="x == y")

        self.assertOutput(
            original=("!", ("==", ("var", "x"), ("var", "y"))),
            output="x != y")

        self.assertOutput(
            original="x != (y and z)",
            output="x != (y and z)")

    def testLogicalOperation(self):
        self.assertOutput(
            original="(x or y.w) and (10 or z.w)",
            output="(x or y.w) and (10 or z.w)")

    def testComplement(self):
        self.assertOutput(
            original=("!", ("+", 5, 5)),
            output="not (5 + 5)")

        self.assertOutput(
            original=("!", (".", ("var", "x"), "y")),
            output="not x.y")

    def testReverse(self):
        self.assertOutput("reverse((1, 2, 3))", "reverse((1, 2, 3))")

    def testAny(self):
        self.assertOutput(
            ("(SELECT ANY pslist WHERE pid == 1) "
             "AND (SELECT ANY netstat WHERE socket.last_pid == 1)"),
            ("any(pslist, pid == 1) and any(netstat, socket.last_pid == 1)"))

    def testCount(self):
        self.assertOutput("count((1, 2, 3))", "count((1, 2, 3))")

    def testBind(self):
        self.assertOutput("bind('x': 1, 'y': 2)", "bind('x': 1, 'y': 2)")

    def testPair(self):
        self.assertOutput(
            original=(":", "x", ("+", 5, 5)),
            output="'x': (5 + 5)")

    def testCast(self):
        self.assertOutput(
            original=("cast", "5", ("var", "int")),
            output="cast('5', int)")

    def testReducer(self):
        q = query.Query(("reducer", ("var", "count"), ("var", "x")))
        self.assertEqual(asdottysql.asdottysql(q),
                         "<Subexpression cannot be formatted as DottySQL.>")

    def testRegexFilter(self):
        self.assertOutput("x =~ '.?'", "x =~ '.?'")

    def testMembership(self):
        self.assertOutput("x in y", "x in y")
        self.assertOutput("x not in y", "x not in y")

    def testApply(self):
        self.assertOutput(
            original=("apply", ("var", "f"), 5, ("+", 5, 5)),
            output="f(5, 5 + 5)")

        self.assertOutput(
            original="func(foo: 10, bar: 15)",
            output="func(foo: 10, bar: 15)")

    def testSelect(self):
        self.assertOutput(
            original="x[5]",
            output="x[5]")

        self.assertOutput(
            original="x[5][5]",
            output="x[5][5]")

        self.assertOutput(
            original="(x or y)[5]",
            output="(x or y)[5]")

    def testResolve(self):
        self.assertOutput(
            original="x.y.z",
            output="x.y.z")

    def testRepeat(self):
        self.assertOutput(
            original="(10, 15, 20 + 5)",
            output="(10, 15, 20 + 5)")

    def testTuple(self):
        self.assertOutput(
            original="[10, 15, 20 + 5]",
            output="[10, 15, 20 + 5]")

    def testIfElse(self):
        self.assertOutput(
            original="if foo then bar else if baz then brr else bzz",
            output="if foo then bar else if baz then brr else bzz")

        self.assertOutput(
            original="if foo then bar",
            output="if foo then bar")
