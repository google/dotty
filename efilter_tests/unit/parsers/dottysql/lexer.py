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

from efilter.parsers.dottysql import lexer


class LexerTest(unittest.TestCase):
    def assertQueryMatches(self, query, expected):
        l = lexer.Lexer(query)
        actual = [(token.name, token.value) for token in l]
        self.assertEqual(expected, actual)

    def testLiterals(self):
        queries = [
            ("0xf 07 010", [15, 7, 8]),
            ("234.7  15\n ", [234.7, 15]),
            ("  15 0x15 '0x15' ' 52.6'", [15, 21, "0x15", " 52.6"])]

        for query, values in queries:
            expected = [("literal", val) for val in values]
            self.assertQueryMatches(query, expected)

    def testPrefix(self):
        self.assertQueryMatches("-5", [("symbol", "-"), ("literal", 5)])

    def testKeywords(self):
        query = "5 + 5 == 10 and 'foo' =~ 'bar'"
        expected = [
            ("literal", 5),
            ("symbol", "+"),
            ("literal", 5),
            ("symbol", "=="),
            ("literal", 10),
            ("symbol", "and"),
            ("literal", "foo"),
            ("symbol", "=~"),
            ("literal", "bar")]
        self.assertQueryMatches(query, expected)

    def testPeeking(self):
        query = "1 in (5, 10) == foo"
        l = lexer.Lexer(query)
        self.assertEquals(l.peek(0).value, 1)
        self.assertEquals(l.peek(2).name, "lparen", None)
        self.assertEquals(l.current_token.value, 1)
        self.assertEquals(l.peek(20), None)
        self.assertEquals(l.current_token.value, 1)
        self.assertEquals(l.next_token().value, "in")
        self.assertEquals(l.current_token.value, "in")
        self.assertEquals(l.next_token().name, "lparen")
        self.assertEquals(l.next_token().value, 5)
        self.assertEquals(l.peek().name, "comma")
        self.assertEquals(l.next_token().name, "comma")
        self.assertEquals(l.next_token().value, 10)
