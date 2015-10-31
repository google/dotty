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
from efilter import query

from efilter.transforms import normalize

from efilter_tests import testlib


class NormalizeTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testExpression(self):
        """Nothing to test, really."""
        pass

    def testBinaryExpression(self):
        """Test that binary expressions can be eliminated.

        I can't actually think of a scenario where we'd ever get the below
        AST from any of the parsers, but we do have code to handle it so
        we should have a test for it.
        """
        self.assertEqual(
            query.Query(
                ast.Intersection(
                    ast.Membership(
                        None,
                        ast.Literal((1, 2)))),
                ast.Literal("5")),
            query.Query(
                ast.Literal("5")))

    def testEquivalence(self):
        self.assertEqual(
            query.Query("ProcessName == 'init'"),
            normalize.normalize(query.Query("ProcessName == 'init'")))

    def testVariadicExpression(self):
        self.assertEqual(
            query.Query(ast.Literal(True)),
            normalize.normalize(query.Query(("&", True))))

    def testWithin(self):
        original = query.Query(
            ("each",
             ("var", "parent"),
             ("var", "name")))

        self.assertEqual(
            original,
            normalize.normalize(original))

        original = query.Query(
            ("any",
             ("map", ("var", "Process"), ("var", "parent")),
             ("==", ("var", "name"), "init")))

        self.assertEqual(
            original,
            normalize.normalize(original))

    def testMap(self):
        original = ("&",
                    ("map",
                     ("map", ("var", "MemoryDescriptor"), ("var", "process")),
                     ("==",
                      ("map", ("var", "Process"), ("var", "command")),
                      "Adium")),
                    ("&",
                     ("in", "execute",
                      ("map",
                       ("var", "MemoryDescriptor"),
                       ("var", "permissions"))),
                     ("in", "write",
                      ("map",
                       ("var", "MemoryDescriptor"),
                       ("var", "permissions")))))

        # Two binary intersections become one variadic intersection and the
        # map-forms now have a Binding as their LHS whenever possible.
        expected = ("&",
                    ("map",
                     ("var", "MemoryDescriptor"),
                     ("map",
                      ("var", "process"),
                      ("==",
                       ("map", ("var", "Process"), ("var", "command")),
                       "Adium"))),
                    ("in", "execute",
                     ("map",
                      ("var", "MemoryDescriptor"),
                      ("var", "permissions"))),
                    ("in", "write",
                     ("map",
                      ("var", "MemoryDescriptor"),
                      ("var", "permissions"))))

        self.assertEqual(
            query.Query(expected),
            normalize.normalize(query.Query(original)))
