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

from efilter import ast
from efilter import errors
from efilter import query as q

from efilter.protocols import repeated
from efilter.protocols import superposition

from efilter.transforms import solve

from efilter_tests import mocks
from efilter_tests import testlib


class SolveTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testLiteral(self):
        self.assertEqual(
            solve.solve(q.Query("42"), {}).value,
            42)

    def testVar(self):
        self.assertEqual(
            solve.solve(q.Query("foo"), {"foo": "bar"}).value,
            "bar")

    def testApply(self):
        self.assertEqual(
            solve.solve(q.Query("f(x)", syntax="dottysql"),
                        dict(f=lambda x: x * 2, x=5)).value,
            10)

        self.assertEqual(
            solve.solve(
                q.Query("multiply(x: 5, y: 5)", syntax="dottysql"),
                dict(multiply=lambda x, y: x * y)).value,
            25)

        with self.assertRaises(errors.EfilterError):
            solve.solve(
                q.Query("multiply(x: 5, 'y': 5)", syntax="dottysql"),
                dict(multiply=lambda x, y: x * y))

    def testBind(self):
        query = q.Query("bind('x': 5, 'y': 10)", syntax="dottysql")

        self.assertEqual(
            solve.solve(query, {}).value,
            {"x": 5, "y": 10})

    def testRepeat(self):
        query = q.Query("(1, 2, 3, 4)", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, {}).value,
            repeated.meld(1, 2, 3, 4))

        # Repeated values flatten automatically.
        query = q.Query("(1, (2, 3), 4)", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, {}).value,
            repeated.meld(1, 2, 3, 4))

        # Expressions work.
        query = q.Query("(1, (2 + 2), 3, 4)", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, {}).value,
            repeated.meld(1, 4, 3, 4))

        # Repeated values are mono-types.
        with self.assertRaises(errors.EfilterTypeError):
            query = q.Query("(1, 'foo', 3, 4)", syntax="dottysql")
            solve.solve(query, {})

    def testTuple(self):
        query = q.Query("[1, 2, 3]", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, {}).value,
            (1, 2, 3))

        query = q.Query("[x + 5, 1 == 1, y['foo']]", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, {"x": 2, "y": {"foo": "bar"}}).value,
            (7, True, "bar"))

    def testPair(self):
        query = q.Query("x: y", syntax="dottysql")
        self.assertEqual(
            solve.solve(query, dict(x="foo", y="bar")).value,
            ("foo", "bar"))

    def testReverse(self):
        query = ast.Reverse(
            ast.Repeat(
                ast.Literal(1),
                ast.Literal(2),
                ast.Literal(3)))
        self.assertEquals(
            solve.solve(query, {}).value,
            repeated.meld(3, 2, 1))

    def testMap(self):
        self.assertEqual(
            solve.solve(
                q.Query("foo.bar"), {"foo": {"bar": "baz"}}).value,
            "baz")

    def testSelect(self):
        self.assertEqual(
            solve.solve(q.Query("x['y']", syntax="dottysql"),
                        {"x": {"y": 5}}).value,
            5)

    def testEach(self):
        self.assertEqual(
            solve.solve(
                q.Query("each Process.parent where (pid == 1)"),
                {"Process": {"parent": superposition.superposition(
                    mocks.Process(1, None, None),
                    mocks.Process(2, None, None))}}).value,
            False)

    def testAny(self):
        self.assertEqual(
            solve.solve(
                q.Query("any Process.parent where (pid == 1)"),
                {"Process": {"parent": superposition.superposition(
                    mocks.Process(1, None, None),
                    mocks.Process(2, None, None))}}).value,
            True)

    def testSort(self):
        self.assertEqual(
            solve.solve(
                q.Query("sort Process where pid"),
                {"Process": repeated.meld(
                    mocks.Process(2, None, None),
                    mocks.Process(1, None, None))}).value,
            repeated.meld(
                mocks.Process(1, None, None),
                mocks.Process(2, None, None)))

        # How about nested repeated fields? This should sort the process
        # children and return those.
        self.assertEqual(
            solve.solve(
                q.Query("Process.(sort children where pid)"),
                {"Process": {"children": repeated.meld(
                    mocks.Process(2, None, None),
                    mocks.Process(1, None, None))}}).value,
            repeated.meld(
                mocks.Process(1, None, None),
                mocks.Process(2, None, None)))

    def testFilter(self):
        self.assertEqual(
            solve.solve(
                q.Query("find Process where (pid == 1)"),
                {"Process": repeated.meld(
                    mocks.Process(2, None, None),
                    mocks.Process(1, None, None))}).value,
            mocks.Process(1, None, None))

    def testIsInstance(self):
        self.assertEqual(
            solve.solve(
                q.Query("proc isa Process"),
                {"proc": mocks.Process(None, None, None)}).value,
            True)

    def testComplement(self):
        self.assertEqual(
            solve.solve(
                q.Query("not pid"),
                mocks.Process(1, None, None)).value,
            False)

    def testIntersection(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid and not pid"),
                mocks.Process(1, None, None)).value,
            False)

    def testUnion(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid or not pid"),
                mocks.Process(1, None, None)).value,
            True)

    def testSum(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid + 10 + 20"),
                mocks.Process(1, None, None)).value,
            31)

    def testDifference(self):
        self.assertEqual(
            solve.solve(
                q.Query("(10 - pid) + 5"),
                mocks.Process(1, None, None)).value,
            14)

    def testProduct(self):
        self.assertEqual(
            solve.solve(
                q.Query("5 * 5 * 5"),
                mocks.Process(1, None, None)).value,
            125)

    def testQuotient(self):
        self.assertEqual(
            solve.solve(
                q.Query("10.0 / 4"),
                mocks.Process(1, None, None)).value,
            2.5)

    def testEquivalence(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid == 1"),
                mocks.Process(1, None, None)).value,
            True)

    def testMembership(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid in (1, 2)"),
                mocks.Process(1, None, None)).value,
            True)

    def testRegexFilter(self):
        self.assertTrue(
            solve.solve(
                q.Query("name =~ 'ini.*'"),
                mocks.Process(1, "initd", None)).value)

    def testStrictOrderedSet(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid > 2"),
                mocks.Process(1, None, None)).value,
            False)

    def testPartialOrderedSet(self):
        self.assertEqual(
            solve.solve(
                q.Query("pid >= 2"),
                mocks.Process(2, None, None)).value,
            True)

    def testContainmentOrder(self):
        self.assertEqual(
            solve.solve(
                q.Query(
                    # This guy doesn't (yet) have syntax in any of the parsers.
                    ast.ContainmentOrder(
                        ast.Literal((1, 2)),
                        ast.Literal((1, 2, 3)))),
                None).value,
            True)

    def testMatchTrace(self):
        """Make sure that matching branch is recorded where applicable."""
        result = solve.solve(
            q.Query("pid == 1 or pid == 2 or pid == 3"),
            mocks.Process(2, None, None))

        self.assertEquals(
            q.Query(result.branch),
            q.Query("pid == 2"))

    def testDestructuring(self):
        result = solve.solve(
            q.Query("Process.pid == 1"), {"Process": {"pid": 1}})
        self.assertEqual(True, result.value)

        # Using a let-any form should succeed even if there is only one linked
        # object.
        result = solve.solve(
            q.Query("any Process.parent where (Process.pid == 1 or "
                    "Process.command == 'foo')"),
            {"Process": {"parent": {"Process": {"pid": 1}}}})
        self.assertEqual(True, result.value)

    def testTypeOps(self):
        result = solve.solve(
            q.Query("proc isa Process"),
            {"proc": mocks.Process(None, None, None)})

        self.assertEqual(True, result.value)
