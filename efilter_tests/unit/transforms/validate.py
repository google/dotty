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

from efilter_tests import mocks
from efilter_tests import testlib

from efilter import errors
from efilter import query

from efilter.transforms import validate


class ValidateTest(testlib.EfilterTestCase):
    def testQuery(self):
        q = query.Query("5 + 'foo'")
        with self.assertRaises(errors.EfilterTypeError):
            validate.validate(q)

    def testValueExpression(self):
        q = query.Query("Process.pid + 5")
        self.assertTrue(validate.validate(q),
                        mocks.MockRootType)

    def testComplement(self):
        # Numbers implement IBoolean so this should work.
        q = query.Query("not 5")
        self.assertTrue(validate.validate(q),
                        mocks.MockRootType)

    def testBinaryExpression(self):
        q = query.Query("5.member")
        with self.assertRaises(errors.EfilterTypeError):
            validate.validate(q)

    def testVariadicExpression(self):
        # Variadic should check all children:
        q = query.Query("10 * 15 * 'foo' * 20")
        with self.assertRaises(errors.EfilterTypeError):
            validate.validate(q)
