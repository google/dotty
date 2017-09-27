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

from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"

import abc
import unittest

import six

from efilter import dispatch

# Type hierarchy to test over.


class Animal(object):
    pass


class Feline(six.with_metaclass(abc.ABCMeta)):
    pass


class Aquatic(six.with_metaclass(abc.ABCMeta)):
    pass


class Mammal(Animal):
    pass


class Cow(Mammal):
    def speak(self):
        return "Moo!"


class Pig(Mammal):
    def speak(self):
        return "Oink!"


class Fish(Animal):
    pass


Aquatic.register(Fish)


class Catfish(Fish):
    pass


Feline.register(Catfish)
Aquatic.register(Catfish)


class SeaCow(Cow):
    def speak(self):
        "Moosplash!"


Aquatic.register(SeaCow)


# Test functions

@dispatch.multimethod
def speak(animal):
    _ = animal
    raise NotImplementedError()


# Register the existing instance method:
speak.implement(for_type=Pig, implementation=Pig.speak)


# Abstract types should work.
@speak.implementation(for_type=Aquatic)
def speak(animal):
    _ = animal
    return "Splash!"


# Implementations have nothing to do with instance methods of the same name,
# and concrete types override abstract ones.
@speak.implementation(for_type=SeaCow)
def speak(animal):
    _ = animal
    return "Splash splash."


# More generic types will not override concrete ones (like Pig) but will work
# where implementations are missing, like Cow.
@speak.implementation(for_type=Mammal)
def speak(animal):
    _ = animal
    return "I am animated."


# Having two abstract types without an order of preference should blow up for
# Mr. Catfish.
@speak.implementation(for_type=Feline)
def speak(animal):
    _ = animal
    return "Meow!"


class TypesTest(unittest.TestCase):
    def testDispatch(self):
        self.assertEqual(speak(Cow()), "I am animated.")
        self.assertEqual(speak(Pig()), "Oink!")

        with self.assertRaises(TypeError):
            speak(Catfish())

        # Preferring one type should help with the above exception.
        speak.prefer_type(Feline, over=Aquatic)
        self.assertEqual(speak(Catfish()), "Meow!")

        self.assertEqual(speak(SeaCow()), "Splash splash.")
