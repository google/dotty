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

from efilter import query

from efilter.transforms import normalize

from efilter_tests import testlib

# Pylint is so broken... This is to stop it bitching about the nested tuples.
# pylint: disable=bad-continuation


class NormalizeTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testExpression(self):
        """Nothing to test, really."""
        pass

    def testReverse(self):
        """Make sure that reverse gets normalized."""
        original = query.Query(
            ("reverse",
                ("repeat",
                    ("var", "x"),
                    ("var", "y"),
                    ("|", 1, ("|", 2, 3)))))

        expected = query.Query(
            ("reverse",
                ("repeat",
                    ("var", "x"),
                    ("var", "y"),
                    ("|", 1, 2, 3))))

        self.assertEqual(normalize.normalize(original), expected)

    def testBinaryExpression(self):
        """Make sure binary expressions are normalized."""
        original = query.Query(
            ("pair",
                ("literal", "x"),
                ("|", ("var", "x"), ("|", ("var", "y"), ("var", "z")))))

        expected = query.Query(
            ("pair",
                ("literal", "x"),
                ("|", ("var", "x"), ("var", "y"), ("var", "z"))))

        self.assertEqual(normalize.normalize(original), expected)

    def testVariadicExpression(self):
        """Make sure variadic expressions are normalized."""
        original = query.Query(
            ("&",
                ("|", ("var", "x"), ("|", ("var", "y"), ("var", "z"))),
                ("var", "w")))

        expected = query.Query(
            ("&",
                ("|", ("var", "x"), ("var", "y"), ("var", "z")),
                ("var", "w")))

        self.assertEqual(normalize.normalize(original), expected)

    def testVariadicExpressionElimination(self):
        """Make sure variadic expressions are eliminated."""
        original = query.Query(("&", ("var", "w")))
        expected = query.Query(("var", "w"))

        self.assertEqual(normalize.normalize(original), expected)

    def testVariadicExpressionMerging(self):
        """Make sure variadic expressions are collapsed."""
        original = query.Query(
            ("|", ("var", "x"), ("|", ("var", "y"), ("var", "z"))))

        expected = query.Query(
            ("|", ("var", "x"), ("var", "y"), ("var", "z")))

        self.assertEqual(normalize.normalize(original), expected)

    def testApply(self):
        """Make sure arguments to functions are normalized."""
        original = query.Query(
            ("apply",
                ("var", "f"),
                ("|", ("var", "x"), ("|", ("var", "y"), ("var", "z"))),
                ("var", "w")))

        expected = query.Query(
            ("apply",
                ("var", "f"),
                ("|", ("var", "x"), ("var", "y"), ("var", "z")),
                ("var", "w")))

        self.assertEqual(normalize.normalize(original), expected)
