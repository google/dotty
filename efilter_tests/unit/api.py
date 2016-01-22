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

from efilter import api


class QueryTest(testlib.EfilterTestCase):
    def testApply(self):
        self.assertValuesEqual(
            api.apply("select age from data where name == 'Peter'",
                      vars=dict(data=[dict(name="Peter", age=20),
                                      dict(name="Paul", age=30)])),
            dict(age=20))

        self.assertValuesEqual(
            api.apply("select * from data where name == 'Peter'",
                      vars=dict(data=[dict(name="Peter", age=20),
                                      dict(name="Paul", age=30)])),
            dict(age=20, name="Peter"))

        self.assertValuesEqual(
            api.apply("select * from data where name == ?",
                      vars=dict(data=[dict(name="Peter", age=20),
                                      dict(name="Paul", age=30)]),
                      replacements=["Peter"]),
            dict(age=20, name="Peter"))

    def testSearch(self):
        self.assertSequenceEqual(
            list(api.search(
                "name == 'Peter'",
                data=[dict(name="Peter", age=20),
                      dict(name="Paul", age=30)])),
            [dict(age=20, name="Peter")])
