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
from efilter import query as q

from efilter.transforms import aslisp

# The nested tuples are way too real for poor old Pylint to handle.
# pylint: disable=bad-continuation


class AsLispTest(unittest.TestCase):
    def testQuery(self):
        query = q.Query("SELECT proc.pid, proc.parent.pid FROM pslist() "
                        "WHERE proc.command == 'init'",
                        syntax="dottysql")
        expected = \
            ("map",
                ("filter",
                    ("apply", ("var", "pslist")),
                    ("==",
                        (".", ("var", "proc"), "command"), "init")),
                ("bind",
                    ("pair", "pid", (".", ("var", "proc"), "pid")),
                    ("pair",
                        1, (".", (".", ("var", "proc"), "parent"), "pid"))))

        self.assertEqual(aslisp.aslisp(query), expected)

    def testExpression(self):
        query = ast.Map(ast.Var("x"), ast.Var("y"))
        expected = ("map", ("var", "x"), ("var", "y"))

        self.assertEqual(aslisp.aslisp(query), expected)

    def testLiteral(self):
        query = ast.Literal("foo")
        expected = "foo"

        self.assertEqual(aslisp.aslisp(query), expected)

    def testVar(self):
        query = ast.Var("x")
        expected = ("var", "x")

        self.assertEqual(aslisp.aslisp(query), expected)
