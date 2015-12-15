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

from efilter import scope


class ScopeTest(unittest.TestCase):
    def testResolutionOrder(self):
        s = scope.ScopeStack({"x": 1}, {"x:": 2}, {"x": 3})
        self.assertEqual(s.locals, {"x": 3})
        self.assertEqual(s.globals, {"x": 1})
        self.assertEqual(s.resolve("x"), 3)

    def testStacking(self):
        s = scope.ScopeStack({"x": 1}, {"x:": 2})
        s = scope.ScopeStack(s, {"x": 3})

        # Stack remains flat.
        self.assertEqual(s.locals, {"x": 3})
        self.assertEqual(s.globals, {"x": 1})
