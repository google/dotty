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
EFILTER coverage tests for units
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.transforms import asdottysql
from efilter.transforms import aslisp
from efilter.transforms import normalize
from efilter.transforms import solve

from efilter_tests.unit.transforms import asdottysql as asdottysql_test
from efilter_tests.unit.transforms import aslisp as aslisp_test
from efilter_tests.unit.transforms import normalize as normalize_test
from efilter_tests.unit.transforms import solve as solve_test

from efilter_tests import testlib


class UnitCoverageTest(testlib.EfilterTestCase):
    def assertUnitCoverage(self, function, test_cls):
        """Assert that 'test_cls' has a test method for each implementation."""
        if not testlib.TEST_COVERAGE:
            return

        for t, _ in function.implementations:
            test_name = "test%s" % t.__name__
            test = getattr(test_cls, test_name, None)

            self.assertTrue(
                callable(test),
                "%r is missing a test for %r over type %r." %
                (test_cls.__name__, function.__name__, t.__name__))

    def testAsDottySQLCoverage(self):
        self.assertUnitCoverage(asdottysql.asdottysql,
                                asdottysql_test.AsDottySQLTest)

    def testAsLispCoverage(self):
        self.assertUnitCoverage(aslisp.aslisp, aslisp_test.AsLispTest)

    def testNormalizeCoverage(self):
        self.assertUnitCoverage(normalize.normalize,
                                normalize_test.NormalizeTest)

    def testSolveCoverage(self):
        self.assertUnitCoverage(solve.solve, solve_test.SolveTest)
