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

from efilter.stdlib import math as std_math


class MathTest(testlib.EfilterTestCase):
    def testLevenshteinDistance(self):
        self.assertEqual(std_math.LevenshteinDistance()("kitten", "kitten"), 0)
        self.assertEqual(std_math.LevenshteinDistance()("kitten", "Kitten"), 1)
        self.assertEqual(std_math.LevenshteinDistance()("kitten", "kittens"), 1)
        self.assertEqual(std_math.LevenshteinDistance()("Kitten", "kittens"), 2)
        self.assertEqual(std_math.LevenshteinDistance()("", "foo"), 3)
        self.assertEqual(std_math.LevenshteinDistance()("sitting", "kitten"), 3)
