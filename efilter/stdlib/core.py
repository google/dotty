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
EFILTER stdlib.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import itertools

from efilter import protocol

from efilter.protocols import applicative
from efilter.protocols import counted
from efilter.protocols import repeated


class TypedFunction(object):
    name = None

    def apply(self, args, kwargs):
        return self(*args, **kwargs)

    def __call__(self):
        raise NotImplementedError()

    @classmethod
    def reflect_static_args(cls):
        return itertools.repeat(protocol.AnyType)

    @classmethod
    def reflect_static_return(cls):
        return protocol.AnyType


applicative.IApplicative.implicit_dynamic(TypedFunction)


class Lower(TypedFunction):
    """Makes a string lowercase."""

    name = "lower"

    def __call__(self, x):
        return x.lower()

    @classmethod
    def reflect_static_args(cls):
        return (basestring,)

    @classmethod
    def reflect_static_return(cls):
        return basestring


class Count(TypedFunction):
    """Counts the number of elements in a tuple or of values in a repeated."""

    name = "count"

    def __call__(self, x):
        return counted.count(x)

    @classmethod
    def reflect_static_args(cls):
        return (repeated.IRepeated,)

    @classmethod
    def reflect_static_return(cls):
        return int


class Reverse(TypedFunction):
    """Reverses a tuple of a repeated and maintains the type."""

    name = "reverse"

    def __call__(self, x):
        if isinstance(x, tuple):
            return tuple(reversed(x))

        return repeated.meld(*reversed(repeated.getvalues(x)))

    @classmethod
    def reflect_static_args(cls):
        return (repeated.IRepeated,)

    @classmethod
    def reflect_static_return(cls):
        return repeated.IRepeated


FUNCTIONS = dict(count=Count(), reverse=Reverse(), lower=Lower())
