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
EFILTER stdlib - core module.

This module defines functions that are always included in every query, as well
as the base classes TypedFunction and LibraryModule, which are used to represent
stdlib functions and modules.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import itertools
import six
import threading

from efilter import protocol

from efilter.protocols import applicative
from efilter.protocols import counted
from efilter.protocols import reducer
from efilter.protocols import repeated
from efilter.protocols import structured


class TypedFunction(object):
    """Represents an EFILTER-callable function with reflection support.

    Each function in the standard library is an instance of a subclass of
    this class. Subclasses override __call__ and the reflection API.
    """
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


class TypedReducer(object):
    """Represents an EFILTER-callable reducer function.

    TypedReducer supports the IReducer protocol, but also works as a function
    (IApplicative), to allow it to reduce values inside rows in a query.
    """
    name = None

    # IApplicative

    def apply(self, args, kwargs):
        return self(*args, **kwargs)

    def __call__(self, data, chunk_size=None):
        return reducer.reduce(self, data, chunk_size)

    @classmethod
    def reflect_static_args(cls):
        return (repeated.IRepeated,)

    @classmethod
    def reflect_static_return(cls):
        return protocol.AnyType

    # IReducer

    def fold(self, chunk):
        raise NotImplementedError()

    def merge(self, left, right):
        raise NotImplementedError()

    def finalize(self, intermediate):
        raise NotImplementedError()


applicative.IApplicative.implicit_dynamic(TypedReducer)
reducer.IReducer.implicit_dynamic(TypedReducer)


class SingletonReducer(object):
    """Preserves a literal value and ensures it's a singleton."""

    name = "singleton"

    def fold(self, chunk):
        iterator = iter(chunk)
        first = next(iterator)
        for item in iterator:
            if item != first:
                raise ValueError("All values in a singleton reducer must be "
                                 "equal to each other. Got %r != %r." % (
                                     first, item))

        return first

    def merge(self, left, right):
        if left != right:
            raise ValueError("All values in a singleton reducer must be "
                             "equal to each other. Got %r != %r." % (
                                 left, right))

        return left

    def finalize(self, intermediate):
        return intermediate


class LibraryModule(object):
    """Represents a part of the standard library.

    Each library module consists of a collection of vars, which are mostly
    instances of TypedFunction. The stdcore module also contains basic types,
    such as 'str' or 'int', in addition to functions.
    """

    vars = None
    name = None

    # This is a class-level global storing all instances by their name.
    ALL_MODULES = {}
    _all_modules_lock = threading.Lock()

    def __init__(self, vars, name):
        self.vars = vars
        self.name = name

        self._all_modules_lock.acquire()
        try:
            if name in self.ALL_MODULES:
                raise ValueError("Duplicate module name %r." % name)

            self.ALL_MODULES[name] = self
        finally:
            self._all_modules_lock.release()

    def __del__(self):
        """If modules are being used properly this will only happen on exit."""
        self._all_modules_lock.acquire()
        try:
            del self.ALL_MODULES[self.name]
        finally:
            self._all_modules_lock.release()

    def __repr__(self):
        return "LibraryModule(name=%r, vars=%r)" % (self.name, self.vars)

    def getmembers_runtime(self):
        return self.vars.keys()

    def resolve(self, name):
        return self.vars[name]

    def reflect_runtime_member(self, name):
        return type(self.vars[name])


structured.IStructured.implicit_static(LibraryModule)


class First(TypedFunction):
    """Return the first value from an IRepeated."""

    name = "first"

    def __call__(self, x):
        for value in repeated.getvalues(x):
            return value

    @classmethod
    def reflect_static_args(cls):
        return (repeated.IRepeated,)

    @classmethod
    def reflect_static_return(cls):
        return protocol.AnyType


class Take(TypedFunction):
    """Take only the first 'count' elements from 'x' (tuple or IRepeated).

    This implementation is lazy.

    Example:
        take(2, (1, 2, 3, 4)) -> (1, 2)

    Arguments:
        count: How many elements to return.
        x: The tuple or IRepeated to take from.

    Returns:
        A lazy IRepeated.
    """

    name = "take"

    def __call__(self, count, x):
        def _generator():
            if isinstance(x, tuple):
                values = x
            else:
                values = repeated.getvalues(x)

            for idx, value in enumerate(values):
                if idx == count:
                    break

                yield value

        return repeated.lazy(_generator)

    @classmethod
    def reflect_static_args(cls):
        return (int, repeated.IRepeated)

    @classmethod
    def reflect_static_return(cls):
        return repeated.IRepeated


class Drop(TypedFunction):
    """Drop the first 'count' elements from 'x' (tuple or IRepeated).

    This implementation is lazy.

    Example:
        drop(2, (1, 2, 3, 4)) -> (3, 4)

    Arguments:
        count: How many elements to drop.
        x: The tuple or IRepeated to drop from.

    Returns:
        A lazy IRepeated.
    """

    name = "drop"

    def __call__(self, count, x):
        def _generator():
            if isinstance(x, tuple):
                values = x
            else:
                values = repeated.getvalues(x)

            for idx, value in enumerate(values):
                if idx < count:
                    continue

                yield value

        return repeated.lazy(_generator)

    @classmethod
    def reflect_static_args(cls):
        return (int, repeated.IRepeated)

    @classmethod
    def reflect_static_return(cls):
        return repeated.IRepeated


class Lower(TypedFunction):
    """Make a string lowercase."""

    name = "lower"

    def __call__(self, x):
        return x.lower()

    @classmethod
    def reflect_static_args(cls):
        return (six.string_types[0],)

    @classmethod
    def reflect_static_return(cls):
        return six.string_types[0]


class Find(TypedFunction):
    """Returns the position of 'needle' in 'string', or -1 if not found."""

    name = "find"

    def __call__(self, string, needle):
        return string.find(needle)

    @classmethod
    def reflect_static_args(cls):
        return (six.string_types[0], six.string_types[0])

    @classmethod
    def reflect_static_return(cls):
        return int


class Count(TypedReducer):
    """Counts the number of elements in a tuple or of values in a repeated."""

    name = "count"

    def fold(self, chunk):
        return counted.count(chunk)

    def merge(self, left, right):
        return left + right

    def finalize(self, intermediate):
        return intermediate

    @classmethod
    def reflect_static_return(cls):
        return int


class Reverse(TypedFunction):
    """Reverse a tuple of a repeated and maintains the type."""

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


MODULE = LibraryModule(name="stdcore",
                       vars={Take.name: Take(),
                             Drop.name: Drop(),
                             Count.name: Count(),
                             Reverse.name: Reverse(),
                             Lower.name: Lower(),
                             Find.name: Find(),
                             SingletonReducer.name: SingletonReducer(),
                             First.name: First(),
                             # Built-in types below:
                             "int": int,
                             "str": six.text_type,
                             "bytes": six.binary_type,
                             "float": float})
