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
from efilter.transforms import hint

from efilter_tests import testlib


class HintTest(testlib.EfilterTestCase):
    def testQuery(self):
        """Get coverage test to shut up."""
        pass

    def testRelation(self):
        original = query.Query("Process.name == 'init'")
        self.assertEqual(
            hint.hint(original, None),
            original)

    def testLet(self):
        self.assertEqual(
            hint.hint(query.Query("Process.name == 'init'"), "Process"),
            query.Query("name == 'init'"))

    def testMulti(self):
        self.assertEqual(
            hint.hint(query.Query("Process.parent.Process.name == 'init'"),
                      "Process.parent"),
            query.Query("Process.name == 'init'"))

    def testNested(self):
        self.assertEqual(
            hint.hint(query.Query("Process.parent.Process.name == 'init' "
                                  "and Process.pid > 10"),
                      "Process.parent"),
            query.Query("Process.name == 'init'"))

    def testIntersection(self):
        self.assertEqual(
            hint.hint(query.Query("Process.parent.Process.name == 'init' "
                                  "and Process.parent.Process.pid > 10"),
                      "Process.parent"),
            query.Query("Process.name == 'init' and Process.pid > 10"))

    def testComplement(self):
        self.assertEqual(
            hint.hint(query.Query("Process.parent.Process.name != 'init' "
                                  "and not Process.parent.Process.pid > 10"),
                      "Process.parent"),
            query.Query("Process.name != 'init' and not Process.pid > 10"))

    def testSubquery(self):
        self.assertEqual(
            hint.hint(query.Query("VAD.process where "
                                  "(Process.command == 'Adium') "
                                  "and 'execute' in VAD.permissions "
                                  "and 'write' in VAD.permissions"),
                      "VAD.process"),
            query.Query("Process.command == 'Adium'"))

    def testVariadicExpression(self):
        self.assertEqual(
            hint.hint(query.Query("Process.name + 10 + 10"), "Process"),
            query.Query("name + 10 + 10"))

    def testComponentLiteral(self):
        # TODO: 'has component' and 'isa' are currently weird, in that they are
        # unary expressions that apply to bindings, instead of a var in
        # bindings. Both are this way for historical reasons, and will chance
        # soon to be regular binary expressions applying to a var. Once that's
        # been done, the assertion below can be enabled.

        # self.assertEqual(
        #     hint.hint(
        #         query.Query("Process.parent has component Struct"),
        #         "Process.parent"),
        #     "has component Struct")
        pass

    def testIsInstance(self):
        # TODO: 'has component' and 'isa' are currently weird, in that they are
        # unary expressions that apply to bindings, instead of a var in
        # bindings. Both are this way for historical reasons, and will chance
        # soon to be regular binary expressions applying to a var. Once that's
        # been done, the assertion below can be enabled.

        # self.assertEqual(
        #     hint.hint(
        #         query.Query("Process.parent has component Struct"),
        #         "Process.parent"),
        #     "has component Struct")
        pass

    def testComplement(self):
        self.assertEqual(
            hint.hint(query.Query("not Process.awake"),
                      "Process"),
            query.Query("not awake"))

    def testBinaryExpression(self):
        self.assertEqual(
            hint.hint(query.Query("Process.parent in Process.parents"),
                      "Process"),
            query.Query("parent in parents"))

    def testLiteral(self):
        self.assertEqual(
            hint.hint(query.Query("10"), "foo"),
            query.Query("10"))

    def testBinding(self):
        self.assertEqual(
            hint.hint(query.Query("foo.bar"), "foo"),
            query.Query("bar"))
