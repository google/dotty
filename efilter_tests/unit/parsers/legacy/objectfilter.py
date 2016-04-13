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

from efilter.parsers.legacy import objectfilter


class ObjectFilterTest(testlib.EfilterTestCase):
    def assertQueryMatches(self, query, expected):
        p = objectfilter.ObjectFilterSyntax(query)
        self.assertEqual(expected, p.root)

    def assertQueryRaises(self, query, f=None):
        p = objectfilter.ObjectFilterSyntax(query)

        try:
            p.root
        except errors.EfilterParseError as error:
            if callable(f) and not f(error):
                self.fail("Raised the wrong exception: %r." % error)

            return True

        self.fail("Didn't raise an exception.")

    def testInfix(self):
        self.assertQueryMatches(
            "x == 'foo' and y.z contains 'bar'",
            ast.Intersection(
                ast.Equivalence(ast.Var("x"), ast.Literal("foo")),
                ast.Membership(
                    ast.Literal("bar"),
                    ast.Resolve(ast.Var("y"), ast.Literal("z")))))

    def testLists(self):
        self.assertQueryMatches(
            "x inset [1, 2, 3]",
            ast.Membership(
                ast.Var("x"),
                ast.Tuple(ast.Literal(1), ast.Literal(2), ast.Literal(3))))

    def testEmpty(self):
        self.assertQueryRaises("")
        self.assertQueryRaises(" ")

    def testErrors(self):
        self.assertQueryRaises("x == ")
        self.assertQueryRaises(" == y")
