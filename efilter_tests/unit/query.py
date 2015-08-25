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
from efilter import query

from efilter.transforms import normalize
from efilter.transforms import hint


class QueryTest(unittest.TestCase):
    def testCreation(self):
        q = query.Query("foo == bar")
        self.assertEquals(
            q.root,
            ast.Equivalence(ast.Binding("foo"),
                            ast.Binding("bar")))

    def testFormatters(self):
        """Creating a query with raw AST should generate the source."""
        q = query.Query(
            ast.Complement(
                ast.Equivalence(
                    ast.Let(
                        ast.Binding("Process"),
                        ast.Binding("pid")),
                    ast.Literal(10))))
        self.assertEquals(q.source, "Process.pid != 10")

    def testSourceCache(self):
        """Creating the query with valid source should preserve it."""
        q = query.Query("Process.pid    != 10")  # Extra whitespace.
        self.assertEqual(q.source, "Process.pid    != 10")

        # Normalization shouldn't mess up the code (because it's 1:1).
        q = normalize.normalize(q)
        self.assertEqual(q.source, "Process.pid    != 10")

        # Bigger changes will trigger new source, though.
        q = hint.hint(q, selector="Process")
        self.assertEqual(q.source, "pid != 10")

    def testLisp(self):
        """Should be able to make lisp queries and preserve syntax."""
        original = ("==", ("var", "foo"), ("var", "bar"))
        q = query.Query(original)
        self.assertEqual(q.source, original)
