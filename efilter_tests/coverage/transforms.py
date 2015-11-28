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
EFILTER coverage tests for transforms.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import ast

from efilter.transforms import asdotty
from efilter.transforms import aslisp
from efilter.transforms import hint
from efilter.transforms import infer_type
from efilter.transforms import normalize
from efilter.transforms import solve
from efilter.transforms import validate

from efilter_tests import testlib


class TransformCoverageTest(testlib.EfilterTestCase):
    def assertASTCoverage(self, function):
        if not testlib.TEST_COVERAGE:
            return

        for name in dir(ast):
            cls = getattr(ast, name)
            if (isinstance(cls, type) and
                    issubclass(cls, ast.Expression) and
                    not getattr(cls, "_%s__abstract" % cls.__name__, None)):

                self.assertImplemented(function=function, for_type=cls)

    def testAsDottyCoverage(self):
        self.assertASTCoverage(asdotty.asdotty)

    def testAsLispCoverage(self):
        self.assertASTCoverage(aslisp.aslisp)

    def testHintCoverage(self):
        self.assertASTCoverage(hint.hint)  # Nudge, nudge.

    def testInferTypeCoverage(self):
        self.assertASTCoverage(infer_type.infer_type)

    def testNormalizeCoverage(self):
        self.assertASTCoverage(normalize.normalize)

    def testSolveCoverage(self):
        self.assertASTCoverage(solve.solve)

    def testValidateCoverage(self):
        self.assertASTCoverage(validate.validate)
