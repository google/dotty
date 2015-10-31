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

from efilter import query as q

from efilter.transforms import analyse


class AnalyseTest(unittest.TestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testEquivalence(self):
        analysis = analyse.analyse(q.Query("ProcessName == 'init'"))
        self.assertIn("ProcessName", analysis.symbols)

    def testMembership(self):
        analysis = analyse.analyse(
            q.Query("ProcessName in ('init', 'launchd')"))
        self.assertIn("ProcessName", analysis.symbols)
        self.assertIn("ProcessName", analysis.eq_indexables)

    def testWithin(self):
        analysis = analyse.analyse(q.Query("Process.name == 'foo'"))
        self.assertIn("Process", analysis.symbols)
        self.assertIn("Process.name", analysis.symbols)
        self.assertIn("Process.name", analysis.eq_indexables)

    def testMap(self):
        analysis = analyse.analyse(
            q.Query("Process.parent where (Process.name == 'init')"))
        self.assertIn("Process.parent", analysis.symbols)
        self.assertIn("Process.name", analysis.symbols)
        self.assertIn("Process", analysis.symbols)

    def testBinding(self):
        analysis = analyse.analyse(q.Query("Process"))
        self.assertSetEqual(set(analysis.symbols), {"Process"})

    def testComplement(self):
        analysis = analyse.analyse(q.Query("not Process.active"))
        self.assertSetEqual(set(analysis.symbols), {"Process", "active",
                                                    "Process.active"})

    def testLiteral(self):
        analysis = analyse.analyse(q.Query("42"))
        self.assertSetEqual(set(analysis.symbols), set())
        self.assertSetEqual(set(analysis.eq_indexables), set())

    def testIsInstance(self):
        analysis = analyse.analyse(q.Query("proc isa Process"))
        self.assertSetEqual(set(analysis.symbols), {"Process", "proc"})

    def testBinaryExpression(self):
        analysis = analyse.analyse(q.Query("Legion.name in Legion.many"))
        self.assertSetEqual(set(analysis.symbols),
                            {"Legion", "name", "many", "Legion.name",
                             "Legion.many"})

    def testVariadicExpression(self):
        analysis = analyse.analyse(q.Query("ready and able"))
        self.assertSetEqual(set(analysis.symbols), {"ready", "able"})
