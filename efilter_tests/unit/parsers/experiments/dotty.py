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

from efilter.parsers.experiments import dotty


class TokenizerTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected):
        tokenizer = dotty.Tokenizer(query)
        actual = [(token.name, token.value) for token in tokenizer.parse()]
        self.assertEqual(expected, actual)

    def testLiterals(self):
        queries = [
            ("0xf", [15]),
            ("234.7  15\n ", [234.7, 15]),
            ("  15 0x15 '0x15' ' 52.6'", [15, 21, "0x15", " 52.6"])]

        for query, values in queries:
            expected = [("literal", val) for val in values]
            self.assertQueryMatches(query, expected)

    def testKeywords(self):
        query = "5 + 5 == 10 and 'foo' =~ 'foo'"
        expected = [
            ("literal", 5),
            ("infix", "+"),
            ("literal", 5),
            ("infix", "=="),
            ("literal", 10),
            ("infix", "and"),
            ("literal", "foo"),
            ("infix", "=~"),
            ("literal", "foo")]
        self.assertQueryMatches(query, expected)

    def testWhitespace(self):
        query = "20 not in 10"
        expected = [
            ("literal", 20),
            ("infix", "not in"),
            ("literal", 10)]
        self.assertQueryMatches(query, expected)

    def testLists(self):
        query = "'foo' in ('foo', 'bar')"
        expected = [
            ("literal", "foo"),
            ("infix", "in"),
            ("lparen", "("),
            ("literal", "foo"),
            ("comma", ","),
            ("literal", "bar"),
            ("rparen", ")")]
        self.assertQueryMatches(query, expected)

    def testPeeking(self):
        query = "1 in (5, 10) == ProcessPid"
        tokenizer = dotty.Tokenizer(query)
        tokenizer.next_token()
        self.assertEquals(tokenizer.peek(2).name, "lparen")
        self.assertEquals(tokenizer.current_token.value, 1)
        self.assertEquals(tokenizer.peek(20), None)
        self.assertEquals(tokenizer.current_token.value, 1)
        self.assertEquals(tokenizer.next_token().value, "in")
        self.assertEquals(tokenizer.current_token.value, "in")
        self.assertEquals(tokenizer.next_token().name, "lparen")
        self.assertEquals(tokenizer.next_token().value, 5)
        self.assertEquals(tokenizer.peek().name, "comma")
        self.assertEquals(tokenizer.next_token().name, "comma")
        self.assertEquals(tokenizer.next_token().value, 10)


class ParserTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected, params=None):
        parser = dotty.Parser(query, params=params)
        actual = parser.parse()
        self.assertEqual(expected, actual)

    def assertQueryRaises(self, query, params=None):
        parser = dotty.Parser(query, params=params)
        self.assertRaises(dotty.errors.EfilterParseError, parser.parse)

    def testLiterals(self):
        query = "0xff"
        expected = ast.Literal(255)
        self.assertQueryMatches(query, expected)

    def testDescendQuery(self):
        query = "Process where (name == 'init' and pid == 1)"
        expected = ast.Let(
            ast.Binding("Process"),
            ast.Intersection(
                ast.Equivalence(
                    ast.Binding("name"),
                    ast.Literal("init")
                ),
                ast.Equivalence(
                    ast.Binding("pid"),
                    ast.Literal(1))))
        self.assertQueryMatches(query, expected)

    def testDescendShorthand(self):
        query = "ProcessParent.ProcessParent.ProcessName"
        expected = ast.Let(
            ast.Binding("ProcessParent"),
            ast.Let(
                ast.Binding("ProcessParent"),
                ast.Binding("ProcessName")))
        self.assertQueryMatches(query, expected)

    def testEquivalence(self):
        query = "10 == 10"
        expected = ast.Equivalence(
            ast.Literal(10),
            ast.Literal(10))
        self.assertQueryMatches(query, expected)

    def testPrecedence(self):
        query = "5 == 1 * 5 and ProcessName == 'init'"
        expected = ast.Intersection(
            ast.Equivalence(
                ast.Literal(5),
                ast.Product(
                    ast.Literal(1),
                    ast.Literal(5))),
            ast.Equivalence(
                ast.Binding("ProcessName"),
                ast.Literal("init")))
        self.assertQueryMatches(query, expected)

    def testParensBaseline(self):
        query = "3 + 2 * 5"
        expected = ast.Sum(
            ast.Literal(3),
            ast.Product(
                ast.Literal(2),
                ast.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testParens(self):
        query = "(3 + 2) * 5"
        expected = ast.Product(
            ast.Sum(
                ast.Literal(3),
                ast.Literal(2)),
            ast.Literal(5))

        self.assertQueryMatches(query, expected)

    def testPrefixMinus(self):
        query = "-(5 + 5)"
        expected = ast.Product(
            ast.Literal(-1),
            ast.Sum(
                ast.Literal(5),
                ast.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testPrefixMinusHighPrecedence(self):
        query = "-5 + 5"
        expected = ast.Sum(
            ast.Product(
                ast.Literal(-1),
                ast.Literal(5)),
            ast.Literal(5))

        self.assertQueryMatches(query, expected)

    def testPrefixMinusLowPrecedence(self):
        query = "-5 * 5"
        expected = ast.Product(
            ast.Literal(-1),
            ast.Product(
                ast.Literal(5),
                ast.Literal(5)))

        self.assertQueryMatches(query, expected)

    def testLetSingle(self):
        query = "ProcessParent where ProcessCommand == 'init'"
        expected = ast.Let(
            ast.Binding("ProcessParent"),
            ast.Equivalence(
                ast.Binding("ProcessCommand"),
                ast.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexpr(self):
        query = ("ProcessParent where (ProcessCommand == 'init' and "
                 "ProcessPid == 1)")
        expected = ast.Let(
            ast.Binding("ProcessParent"),
            ast.Intersection(
                ast.Equivalence(
                    ast.Binding("ProcessCommand"),
                    ast.Literal("init")),
                ast.Equivalence(
                    ast.Binding("ProcessPid"),
                    ast.Literal(1))))

        self.assertQueryMatches(query, expected)

    def testLetSingleAny(self):
        query = "any Process.parent where name == 'init'"
        expected = ast.LetAny(
            ast.Let(
                ast.Binding("Process"),
                ast.Binding("parent")),
            ast.Equivalence(
                ast.Binding("name"),
                ast.Literal("init")))

        self.assertQueryMatches(query, expected)

    def testLetSubexprEach(self):
        query = "each ProcessChildren where ProcessCommand == 'foo'"
        expected = ast.LetEach(
            ast.Binding("ProcessChildren"),
            ast.Equivalence(
                ast.Binding("ProcessCommand"),
                ast.Literal("foo")))

        self.assertQueryMatches(query, expected)

    def testLists(self):
        query = "'foo' in ('foo', 'bar') and 1 not in (5, 2, 3,17)"
        expected = ast.Intersection(
            ast.Membership(
                ast.Literal("foo"),
                ast.Literal(("foo", "bar"))),
            ast.Complement(
                ast.Membership(
                    ast.Literal(1),
                    ast.Literal((5, 2, 3, 17)))))

        self.assertQueryMatches(query, expected)

    def testBigQuery(self):
        query = ("(ProcessPid == 1 and ProcessCommand in ('init', 'initd')) "
                 "or any ProcessChildren where (ProcessCommand not in "
                 "('launchd', 'foo'))")
        expected = ast.Union(
            ast.Intersection(
                ast.Equivalence(
                    ast.Binding("ProcessPid"),
                    ast.Literal(1)),
                ast.Membership(
                    ast.Binding("ProcessCommand"),
                    ast.Literal(("init", "initd")))),
            ast.LetAny(
                ast.Binding("ProcessChildren"),
                ast.Complement(
                    ast.Membership(
                        ast.Binding("ProcessCommand"),
                        ast.Literal(("launchd", "foo"))))))

        self.assertQueryMatches(query, expected)

    def testLooseAnyError(self):
        query = "any ProcessCommand == 'init'"
        self.assertQueryRaises(query)

    def testMissingClosingParens(self):
        query = "ProcessPid in (1,5"
        self.assertQueryRaises(query)

    def testNestedParens(self):
        query = "ProcessPid in ((1,2))"
        expected = ast.Membership(
            ast.Binding("ProcessPid"),
            ast.Literal((1, 2)))
        self.assertQueryMatches(query, expected)

    def testHasComponent(self):
        query = "has component Process"
        expected = ast.ComponentLiteral("Process")
        self.assertQueryMatches(query, expected)

    def testPositions(self):
        query = "Process.parent where (Process.pid + 10)"
        node = dotty.Parser(query).root
        # iterators = [iter(node.children)]
        iterators = []

        # Walk nodes (depth-first) and make sure they all have start/end.
        while isinstance(node, ast.Expression):
            iterators.append(iter(node.children))
            self.assertIsNotNone(
                node.start, "Node %r is missing 'start'." % node)
            self.assertIsNotNone(
                node.end, "Node %r is missing 'end'." % node)
            next_node = None
            while (iterators and not isinstance(next_node,
                                                ast.Expression)):
                try:
                    next_node = next(iterators[-1])
                except StopIteration:
                    iterators.pop()

            node = next_node

    def testIsa(self):
        query = "isa Process"
        expected = ast.IsInstance("Process")
        self.assertQueryMatches(query, expected)

        # What about let-forms?
        query = "parent isa Process"
        expected = ast.Let(
            ast.Binding("parent"),
            ast.IsInstance("Process"))

        # And nested let-forms?
        query = "Process.parent isa Process"
        expected = ast.Let(
            ast.Binding("Process"),
            ast.Let(
                ast.Binding("parent"),
                ast.IsInstance("Process")))

    def testTemplateReplacements(self):
        query = "ProcessPid == {}"
        params = [1]
        exptected = ast.Equivalence(
            ast.Binding("ProcessPid"),
            ast.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

        query = "ProcessPid == {pid}"
        params = {"pid": 1}
        exptected = ast.Equivalence(
            ast.Binding("ProcessPid"),
            ast.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParamFailures(self):
        query = "{foo} == 1"
        params = ["ProcessPid"]
        self.assertQueryRaises(query, params=params)

        # Even fixing the above, the left side should be a literal, not a
        # binding.
        query = "{foo} == 1"
        params = {"foo": "ProcessPid"}
        exptected = ast.Equivalence(
            ast.Literal("ProcessPid"),
            ast.Literal(1))
        self.assertQueryMatches(query, exptected, params=params)

    def testParenParsing(self):
        # This query should fail on the lose 'name' token:
        query = ("BufferPurpose == 'zones' and any BufferContext where"
                 " (AllocationZone name == {zone_name})")
        params = dict(zone_name="foo")
        parser = dotty.Parser(query, params=params)
        try:
            parser.parse()
        except dotty.errors.EfilterParseError as e:
            self.assertEqual(e.token.value, 'name')

    def testMultipleLiterals(self):
        query = "ProcessBinding foo foo bar 15"
        self.assertQueryRaises(query)
