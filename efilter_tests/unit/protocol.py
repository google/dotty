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

from efilter import dispatch
from efilter import protocol


@dispatch.polymorphic
def say_moo(cow):
    _ = cow
    raise NotImplementedError()


@dispatch.polymorphic
def graze(cow):
    _ = cow
    raise NotImplementedError()


class IBovine(protocol.Protocol):
    _protocol_functions = (say_moo, graze)


class Kyr(object):
    def say_muu(self):
        return "Muu"


IBovine.implement(for_type=Kyr,
                  implementations={
                      graze: lambda c: "Om nom nom.",
                      say_moo: lambda c: c.say_muu()})


class BaseBovine(object):
    def say_moo(self):
        return NotImplemented

    def graze(self):
        return NotImplemented


class Krava(BaseBovine):
    def say_moo(self):
        return "Buu"

    def graze(self):
        "Ham ham"


IBovine.implicit_dynamic(for_type=BaseBovine)


class Vacka(object):
    def say_moo(self):
        return "Buu"

    def graze(self):
        "Ham ham"


IBovine.implicit_static(for_type=Vacka)


class TypesTest(unittest.TestCase):
    def testProtocol(self):
        self.assertTrue(isinstance(Kyr(), IBovine))
        self.assertEquals(say_moo(Kyr()), "Muu")
        self.assertEqual(graze(Kyr()), "Om nom nom.")

    def testImplicitImplementation(self):
        self.assertTrue(isinstance(Vacka(), IBovine))
        self.assertEquals(say_moo(Vacka()), "Buu")

    def testDynamicImplementation(self):
        self.assertTrue(isinstance(Krava(), IBovine))
        self.assertEquals(say_moo(Krava()), "Buu")
