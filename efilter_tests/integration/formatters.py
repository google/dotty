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

This integration test makes sure that conversion and round-trips between
formatters and parsers of different syntaxes preserve the same AST.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import unittest

from efilter import syntax
from efilter import query


class FormatterIntegrationTest(unittest.TestCase):
    def testDottySQLRoundtrip(self):
        f = syntax.Syntax.get_formatter("dottysql")

        # Simple case:
        q = query.Query("(SELECT * FROM pslist WHERE pid == 1)",
                        syntax="dottysql")
        q2 = query.Query(f(q))
        self.assertEqual(q.root, q2.root)

        # ANY disambiguation:
        q = query.Query("(SELECT ANY pslist WHERE pid == 1) "
                        "AND (SELECT ANY netstat WHERE socket.last_pid == 1)",
                        syntax="dottysql")
        q2 = query.Query(f(q))
        self.assertEqual(q.root, q2.root)

    def testLispDottySQLRoundtrip(self):
        lisp = syntax.Syntax.get_formatter("lisp")
        dsql = syntax.Syntax.get_formatter("dottysql")

        q = query.Query("(SELECT proc.pid FROM pslist(pid: 1)"
                        "  WHERE proc.command in ['foo', 'bar'])"
                        "OR (SELECT proc.pid FROM psxview"
                        "  WHERE proc.alive ORDER BY proc.command DESC)")

        self.assertEqual(q.root, query.Query(lisp(q)).root)
        self.assertEqual(dsql(q.root),
                         dsql(query.Query(lisp(q)).root))
        self.assertEqual(lisp(q),
                         lisp(query.Query(dsql(query.Query(lisp(q))))))
