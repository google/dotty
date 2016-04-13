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

from efilter import ast
from efilter import errors
from efilter import query as q

from efilter.parsers.common import ast_transforms
from efilter.parsers.common import grammar
from efilter.parsers.common import parser
from efilter.parsers.common import tokenizer


class ExpressionParserTest(testlib.EfilterTestCase):
    OPERATORS = [
        # Infix with precedence
        grammar.Operator(name="+", precedence=4, assoc="left", handler=ast.Sum,
                         docstring=None, prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "+")),
        grammar.Operator(name="eq", precedence=3, assoc="left",
                         handler=ast.Equivalence, docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "eq"), suffix=None),

        # Prefix
        grammar.Operator(name="unary -", precedence=5, assoc="right",
                         handler=ast_transforms.NegateValue,
                         docstring=None, infix=None, suffix=None,
                         prefix=grammar.Token("symbol", "-")),

        # Mixfix (infix + suffix)
        grammar.Operator(name="[]", precedence=12, assoc="left",
                         handler=ast.Select, docstring=None,
                         prefix=None, infix=grammar.Token("lbracket", "["),
                         suffix=grammar.Token("rbracket", "]")),

        # Circumfix with separator
        grammar.Operator(name="list builder", precedence=14, assoc="left",
                         handler=ast.Tuple, docstring=None,
                         prefix=grammar.Token("lbracket", "["),
                         infix=grammar.Token("comma", ","),
                         suffix=grammar.Token("rbracket", "]"))
    ]

    def parseQuery(self, query):
        t = tokenizer.LazyTokenizer(query)
        p = parser.ExpressionParser(self.OPERATORS, t)
        return p.parse()

    def assertQueryParses(self, query, expected):
        self.assertEqual(q.Query(expected), q.Query(self.parseQuery(query)))

    def testFailures(self):
        with self.assertRaises(errors.EfilterParseError):
            self.parseQuery("+ 5")

        with self.assertRaises(errors.EfilterParseError):
            self.parseQuery("5 +")

        with self.assertRaises(errors.EfilterParseError):
            self.parseQuery("")

        with self.assertRaises(errors.EfilterParseError):
            self.parseQuery("5 * 10")

    def testInfix(self):
        self.assertQueryParses(
            "5 + 5 eq 10",
            ast.Equivalence(
                ast.Sum(
                    ast.Literal(5), ast.Literal(5)),
                ast.Literal(10)))

    def testParens(self):
        self.assertQueryParses(
            "5 + (5 eq 10)",  # It doesn't have to make sense.
            ast.Sum(
                ast.Literal(5),
                ast.Equivalence(
                    ast.Literal(5), ast.Literal(10))))

    def testPrefix(self):
        self.assertQueryParses(
            "-5 + 5 eq - (10)",
            ast.Equivalence(
                ast.Sum(
                    ast.Product(
                        ast.Literal(-1),
                        ast.Literal(5)),
                    ast.Literal(5)),
                ast.Product(
                    ast.Literal(-1),
                    ast.Literal(10))))

    def testMixfix(self):
        self.assertQueryParses(
            "'foo'[0  ]",
            ast.Select(
                ast.Literal("foo"),
                ast.Literal(0)))

        self.assertQueryParses(
            # I refer you to my previous statement about making sense.
            " (5 +5) [ 'foo']",
            ast.Select(
                ast.Sum(ast.Literal(5), ast.Literal(5)),
                ast.Literal("foo")))

        self.assertQueryParses(
            "5 + 5['foo' + 10]",
            ast.Sum(
                ast.Literal(5),
                ast.Select(
                    ast.Literal(5),
                    ast.Sum(
                        ast.Literal("foo"), ast.Literal(10)))))

    def testCircumfix(self):
        self.assertQueryParses(
            "[1, 2, 3]",
            ast.Tuple(ast.Literal(1), ast.Literal(2), ast.Literal(3)))

        self.assertQueryParses(
            # Lists and selection are non-ambiguous.
            "10 + ['foo', 'bar'][1]",
            ast.Sum(
                ast.Literal(10),
                ast.Select(
                    ast.Tuple(ast.Literal("foo"), ast.Literal("bar")),
                    ast.Literal(1))))
