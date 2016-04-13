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

from efilter import ast

from efilter_tests import testlib

from sample_projects.tagging import tag


class TagfileTest(testlib.EfilterTestCase):
    def testFullRun(self):
        tagfile = tag.TagFile(
            path=testlib.get_fixture_path("plaso_tagfile.txt"))

        # This is just a sanity check. Nuanced tests for the tagfile parser
        # are left as exercise to the reader.
        self.assertIsInstance(tagfile.root, ast.Repeat)
