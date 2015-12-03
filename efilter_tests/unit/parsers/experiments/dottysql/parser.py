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

from efilter import ast
from efilter import errors

from efilter.parsers.experiments.dottysql import parser


class ParserTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected, params=None):
        p = parser.Parser(query, params=params)
        self.assertEqual(expected, p.parse())

    def assertQueryRaises(self, query, params=None):
        p = parser.Parser(query, params=params)
        self.assertRaises(errors.EfilterParseError, p.parse)

    def testParams(self):
        self.assertQueryMatches(
            "? == 1 and ? == 2",
            ast.Intersection(
                ast.Equivalence(
                    ast.Literal(1),
                    ast.Literal(1)),
                ast.Equivalence(
                    ast.Literal(2),
                    ast.Literal(2))),
            params=[1, 2])

        self.assertQueryMatches(
            "{1} == 1 and {0} == 2",
            ast.Intersection(
                ast.Equivalence(
                    ast.Literal(2),
                    ast.Literal(1)),
                ast.Equivalence(
                    ast.Literal(1),
                    ast.Literal(2))),
            params=[1, 2])

        self.assertQueryMatches(
            "{bar} == 1 and {foo} == 2",
            ast.Intersection(
                ast.Equivalence(
                    ast.Literal("foo"),
                    ast.Literal(1)),
                ast.Equivalence(
                    ast.Literal(1),
                    ast.Literal(2))),
            params=dict(bar="foo", foo=1))

    def testLiterals(self):
        # Numbers:
        self.assertQueryMatches("5", ast.Literal(5))
        self.assertQueryRaises("5)")

        # Strings:
        self.assertQueryMatches("'foo'", ast.Literal("foo"))

        # Booleans:
        self.assertQueryMatches("true", ast.Literal(True))
        self.assertQueryMatches("false", ast.Literal(False))
        self.assertQueryMatches("TRUE", ast.Literal(True))
        self.assertQueryMatches("TRU", ast.Var("TRU"))

    def testPrefix(self):
        self.assertQueryMatches(
            "-x",
            ast.Product(ast.Literal(-1), ast.Var("x")))

    def testVars(self):
        self.assertQueryMatches("x", ast.Var("x"))

    def testApplication(self):
        self.assertQueryMatches(
            "f(x, y)",
            ast.Apply(ast.Var("f"), ast.Var("x"), ast.Var("y")))

        self.assertQueryRaises("f(x, ,)")
        self.assertQueryRaises("f(x, y")
        self.assertQueryRaises("f (x, y)")

    def testSubscript(self):
        self.assertQueryMatches(
            "d['foo']",
            ast.Select(
                ast.Var("d"),
                ast.Literal("foo")))

        self.assertQueryMatches(
            "d['foo'] + 10",
            ast.Sum(
                ast.Select(
                    ast.Var("d"),
                    ast.Literal("foo")),
                ast.Literal(10)))

        self.assertQueryMatches(
            "obj.props[0]",
            ast.Select(
                ast.Map(
                    ast.Var("obj"),
                    ast.Var("props")),
                ast.Literal(0)))

        self.assertQueryMatches(
            "obj.props[0].foo",
            ast.Map(
                ast.Select(
                    ast.Map(
                        ast.Var("obj"),
                        ast.Var("props")),
                    ast.Literal(0)),
                ast.Var("foo")))

        self.assertQueryMatches(
            "obj.props[10 + 10].foo",
            ast.Map(
                ast.Select(
                    ast.Map(ast.Var("obj"), ast.Var("props")),
                    ast.Sum(
                        ast.Literal(10),
                        ast.Literal(10))),
                ast.Var("foo")))

        self.assertQueryMatches(
            "w['x'][y[5] + 5] * 10",
            ast.Product(
                ast.Select(
                    ast.Select(
                        ast.Var("w"),
                        ast.Literal("x")),
                    ast.Sum(
                        ast.Select(
                            ast.Var("y"),
                            ast.Literal(5)),
                        ast.Literal(5))),
                ast.Literal(10)))

    def testBuiltins(self):
        self.assertQueryMatches(
            "filter(pslist(), proc.pid == 1)",
            ast.Filter(
                ast.Apply(ast.Var("pslist")),
                ast.Equivalence(
                    ast.Map(
                        ast.Var("proc"),
                        ast.Var("pid")),
                    ast.Literal(1))))

        self.assertQueryMatches(
            "map(pslist(), [proc.pid, proc['command']])",
            ast.Map(
                ast.Apply(ast.Var("pslist")),
                ast.Tuple(
                    ast.Map(
                        ast.Var("proc"),
                        ast.Var("pid")),
                    ast.Select(
                        ast.Var("proc"),
                        ast.Literal("command")))))

        self.assertQueryMatches(
            "bind(x: 1, y: 2)",
            ast.Bind(
                ast.Pair(ast.Var("x"), ast.Literal(1)),
                ast.Pair(ast.Var("y"), ast.Literal(2))))

        self.assertQueryRaises("bind (x: 1, y: 2)")

    def testInfix(self):
        self.assertQueryMatches(
            "x + y",
            ast.Sum(ast.Var("x"), ast.Var("y")))

        self.assertQueryMatches(
            "w.x.y.z",
            ast.Map(
                ast.Map(
                    ast.Map(
                        ast.Var("w"),
                        ast.Var("x")),
                    ast.Var("y")),
                ast.Var("z")))

        # Operator precedence should work correctly.
        self.assertQueryMatches(
            "x + y * z",
            ast.Sum(ast.Var("x"),
                    ast.Product(ast.Var("y"),
                                ast.Var("z"))))

        self.assertQueryMatches(
            "x * y + z",
            ast.Sum(ast.Product(ast.Var("x"),
                                ast.Var("y")), ast.Var("z")))

    def testMultiWordOperators(self):
        self.assertQueryMatches(
            "x not in y",
            ast.Complement(
                ast.Membership(
                    ast.Var("x"),
                    ast.Var("y"))))

    def testOperatorPrecedence(self):
        # Prefix operator, like the unary minus sign, should respect operator
        # precedence order.
        self.assertQueryMatches(
            "-x + y",
            ast.Sum(ast.Product(ast.Literal(-1),
                                ast.Var("x")), ast.Var("y")))

        self.assertQueryMatches(
            "not x and y",
            ast.Intersection(
                ast.Complement(
                    ast.Var("x")),
                ast.Var("y")))

        self.assertQueryMatches(
            "x / -f(y) or not z(a, b)",
            ast.Union(
                ast.Quotient(
                    ast.Var("x"),
                    ast.Product(
                        ast.Literal(-1),
                        ast.Apply(
                            ast.Var("f"),
                            ast.Var("y")))),
                ast.Complement(
                    ast.Apply(
                        ast.Var("z"),
                        ast.Var("a"),
                        ast.Var("b")))))

    def testParens(self):
        # Base case.
        self.assertQueryMatches(
            "x + y * z",
            ast.Sum(ast.Var("x"),
                    ast.Product(ast.Var("y"),
                                ast.Var("z"))))

        # With parens.
        self.assertQueryMatches(
            "(x + y) * z",
            ast.Product(ast.Sum(ast.Var("x"),
                                ast.Var("y")), ast.Var("z")))

        # Missing rparen.
        self.assertQueryRaises("(x + y")

        # Empty expressions make no sense.
        self.assertQueryRaises("()")

    def testListLiterals(self):
        self.assertQueryMatches(
            "[1, 2, 3]",
            ast.Tuple(
                ast.Literal(1),
                ast.Literal(2),
                ast.Literal(3)))

        # Empty list literals should work.
        self.assertQueryMatches("[]", ast.Tuple())

        # Arbitrary AST should now be allowed in lists.
        self.assertQueryMatches(
            "[x, f(x)]",
            ast.Tuple(
                ast.Var("x"),
                ast.Apply(ast.Var("f"), ast.Var("x"))))

    def testKVPairs(self):
        self.assertQueryMatches(
            "x: y",
            ast.Pair(ast.Var("x"), ast.Var("y")))

        # KV pairs are used in named function arguments:
        self.assertQueryMatches(
            "f(10, 'strings': ['foo', 'bar'])",
            ast.Apply(
                ast.Var("f"),
                ast.Literal(10),
                ast.Pair(ast.Literal("strings"),
                         ast.Tuple(ast.Literal("foo"), ast.Literal("bar")))))

        # They can also appear in repeated values, forming a logical dictionary:
        self.assertQueryMatches(
            "('foo': foo, 'bar': bar)",
            ast.Repeat(
                ast.Pair(
                    ast.Literal("foo"),
                    ast.Var("foo")),
                ast.Pair(
                    ast.Literal("bar"),
                    ast.Var("bar"))))

    def testRepeatedExpressions(self):
        self.assertQueryMatches(
            "(1, 2, 3)",
            ast.Repeat(ast.Literal(1),
                       ast.Literal(2),
                       ast.Literal(3)))

    def testIfElse(self):
        self.assertQueryMatches(
            "if true then 'foo'",
            ast.IfElse(
                ast.Literal(True), ast.Literal("foo"), ast.Literal(None)))

        self.assertQueryMatches(
            "if true then 'foo' else 'bar'",
            ast.IfElse(
                ast.Literal(True), ast.Literal("foo"), ast.Literal("bar")))

        self.assertQueryMatches(
            "if true then 'foo' else if 5 + 5 then 'bar' else 'baz'",
            ast.IfElse(
                ast.Literal(True),
                ast.Literal("foo"),
                ast.Sum(
                    ast.Literal(5), ast.Literal(5)),
                ast.Literal("bar"),
                ast.Literal("baz")))

        # Missing then blows up:
        self.assertQueryRaises("if (true) bar")

        # Colon blows up:
        self.assertQueryRaises("if true: bar")

    def testBasicSelect(self):
        self.assertQueryMatches(
            "SELECT * FROM pslist()",
            ast.Apply(ast.Var("pslist")))

        # The dotty-like where doesn't exist. SQL keywords are not permitted
        # outside of a SELECT expression.
        self.assertQueryRaises("pslist where pid == 1")

    def testSelectOrder(self):
        # Order expressions.
        self.assertQueryMatches(
            "SELECT * FROM pslist() ORDER BY pid",
            ast.Sort(ast.Apply(ast.Var("pslist")),
                     ast.Var("pid")))

        self.assertQueryMatches(
            "SELECT * FROM pslist() ORDER BY pid DESC",
            ast.Reverse(ast.Sort(ast.Apply(ast.Var("pslist")),
                                 ast.Var("pid"))))

    def testSelectWhere(self):
        self.assertQueryMatches(
            "SELECT * FROM pslist() WHERE pid == 1",
            ast.Filter(ast.Apply(ast.Var("pslist")),
                       ast.Equivalence(ast.Var("pid"), ast.Literal(1))))

    def testSelectWhereOrder(self):
        self.assertQueryMatches(
            "SELECT * FROM pslist() WHERE pid == 1 ORDER BY command DESC",
            ast.Reverse(
                ast.Sort(
                    ast.Filter(
                        ast.Apply(ast.Var("pslist")),
                        ast.Equivalence(ast.Var("pid"), ast.Literal(1))),
                    ast.Var("command"))))

    def testSelectAny(self):
        self.assertQueryMatches(
            "SELECT ANY FROM pslist()",
            ast.Any(ast.Apply(ast.Var("pslist")), ast.Literal(True)))

        # Shorthands for any should work.
        self.assertQueryMatches(
            "SELECT ANY FROM pslist()",
            ast.Any(ast.Apply(ast.Var("pslist")), ast.Literal(True)))

        self.assertQueryMatches(
            "ANY pslist()",
            ast.Any(ast.Apply(ast.Var("pslist")), ast.Literal(True)))

        # Any doesn't allow ORDER BY.
        self.assertQueryRaises("SELECT ANY FROM pslist() ORDER BY pid")

    def testSelectAnyWhere(self):
        self.assertQueryMatches(
            "SELECT ANY FROM pslist() WHERE pid == 1",
            ast.Any(ast.Apply(ast.Var("pslist")),
                    ast.Equivalence(ast.Var("pid"), ast.Literal(1))))

    def testSelectWhat(self):
        self.assertQueryMatches(
            "SELECT proc.parent.pid AS ppid, proc.pid, 'foo' FROM pslist()",
            ast.Map(
                ast.Apply(
                    ast.Var("pslist")),
                ast.Bind(
                    ast.Pair(
                        ast.Literal("ppid"),
                        ast.Map(
                            ast.Map(
                                ast.Var("proc"),
                                ast.Var("parent")),
                            ast.Var("pid"))),
                    ast.Pair(
                        ast.Literal("pid"),
                        ast.Map(
                            ast.Var("proc"),
                            ast.Var("pid"))),
                    ast.Pair(
                        ast.Literal(2),
                        ast.Literal("foo")))))

    def testComplexSelect(self):
        query = ("(SELECT proc.parent.pid AS ppid, proc.pid FROM pslist(10) "
                 "WHERE COUNT(proc.open_files) > 10) and True")

        expected = ast.Intersection(
            ast.Map(
                ast.Filter(
                    ast.Apply(
                        ast.Var("pslist"),
                        ast.Literal(10)),
                    ast.StrictOrderedSet(
                        ast.Apply(
                            ast.Var("COUNT"),
                            ast.Map(
                                ast.Var("proc"),
                                ast.Var("open_files"))),
                        ast.Literal(10))),
                ast.Bind(
                    ast.Pair(
                        ast.Literal("ppid"),
                        ast.Map(
                            ast.Map(
                                ast.Var("proc"),
                                ast.Var("parent")),
                            ast.Var("pid"))),
                    ast.Pair(
                        ast.Literal("pid"),
                        ast.Map(
                            ast.Var("proc"),
                            ast.Var("pid"))))),
            ast.Literal(True))

        self.assertQueryMatches(query, expected)
