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

from efilter.parsers.common import grammar


class GrammarTest(testlib.EfilterTestCase):
    def testComparingTokens(self):
        t1 = grammar.Token("lparen", "(", 1, 2)
        t2 = grammar.Token("lparen", "(", 20, 21)
        self.assertEqual(t1, t2)

        t3 = grammar.Token("lparen", "(", 0, 10)
        t4 = grammar.Token("lparen", ")", 0, 10)
        self.assertNotEqual(t3, t4)

    def testOperatorLookups(self):
        tl = grammar.TokenLookupTable()
        tl.set(grammar.Token("symbol", "func"), "function")
        tl.set((grammar.Token("symbol", "end"),), "end_st")

        self.assertEqual(
            tl.match([grammar.Token("symbol", "func", 1, 20)]),
            ("function", (grammar.Token("symbol", "func", 1, 20),)))

        self.assertEqual(
            tl.match([grammar.Token("symbol", "func_not", 0, None),
                      grammar.Token("symbol", "func", 1, 20)]),
            (None, None))

        # Multi-token matches
        tl.set(
            (grammar.Token("symbol", "not"), grammar.Token("symbol", "in")),
            "not in")

        self.assertEqual(
            tl.match([grammar.Token("symbol", "not"),
                      grammar.Token("symbol", "in"),
                      grammar.Token("blah", "blah")]),
            ("not in", (grammar.Token("symbol", "not"),
                        grammar.Token("symbol", "in"))))

        # Default match is the longest
        tl.set(grammar.Token("symbol", "not"), "not")
        self.assertEqual(
            tl.match([grammar.Token("symbol", "not"),
                      grammar.Token("symbol", "in"),
                      grammar.Token("blah", "blah")]),
            ("not in", (grammar.Token("symbol", "not"),
                        grammar.Token("symbol", "in"))))

        self.assertEqual(
            tl.match([grammar.Token("symbol", "not"),
                      grammar.Token("blah", "blah")]),
            ("not", (grammar.Token("symbol", "not"),)))
