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
from efilter import errors
from efilter import protocol


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

    def testInfer(self):
        self.assertIsa(int, api.infer("5 + 5"))

        # Test that IO needs to be explicit.
        self.assertEqual(protocol.AnyType,
                         api.infer("csv(path, decode_header:true)"))
        self.assertIsa(dict, api.infer("csv(path, decode_header:true)",
                                       allow_io=True))

    def testUserFunc(self):
        with self.assertRaises(errors.EfilterKeyError):
            api.apply("my_func(1, 5)")

        def my_func(x, y):
            return x + y

        with self.assertRaises(NotImplementedError):
            api.apply("my_func(1, 5)",
                      vars={"my_func": my_func})

        # Need to define it as a user_func!
        result = api.apply("my_func(1, 5)",
                           vars={"my_func": api.user_func(my_func)})
        self.assertEqual(result, 6)
