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

from efilter.protocols import number


class APITest(testlib.EfilterTestCase):
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

    def testLet(self):
        self.assertEqual(
            api.apply("let(x = 5, y = 10 * 2) x + y"),
            [25])

        self.assertEqual(
            api.apply("let(x = 5, y = 10 * x, z = (x + y)) z - y"),
            [5])

    def testSearch(self):
        self.assertSequenceEqual(
            list(api.search(
                "name == 'Peter'",
                data=[dict(name="Peter", age=20),
                      dict(name="Paul", age=30)])),
            [dict(age=20, name="Peter")])

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

    def testScalarFunc(self):
        # Define numeric addition.
        def my_func(x, y):
            return x + y

        # Two scalars.
        result = api.apply(
            "my_func(1, 5)",
            vars={"my_func": api.scalar_function(
                my_func, (number.INumber, number.INumber))})
        self.assertEqual(result, [6])

        # Scalar is repeated to length of vector.
        result = api.apply(
            "my_func(1, [1, 5])",
            vars={"my_func": api.scalar_function(
                my_func, (number.INumber, number.INumber))})
        self.assertEqual(result, [2, 6])

        # If a type is non numeric then skip calling the function.
        result = api.apply(
            "my_func(1, [1, 'a'])",
            vars={"my_func": api.scalar_function(
                my_func, (number.INumber, number.INumber))})
        self.assertEqual(result, [2, None])

        # Two vectors are added one element at a time.
        result = api.apply(
            "my_func([1, 2], [1, 5])",
            vars={"my_func": api.scalar_function(
                my_func, (number.INumber, number.INumber))})
        self.assertEqual(result, [2, 7])

        # Short vectors are padded to the longest vector.
        result = api.apply(
            "my_func([1, 2], [1, 5, 7])",
            vars={"my_func": api.scalar_function(
                my_func, (number.INumber, number.INumber))})
        self.assertEqual(result, [2, 7, 7])
