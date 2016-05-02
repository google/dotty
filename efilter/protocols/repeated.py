# -*- coding: utf-8 -*-

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

"""EFILTER abstract type system.

The repeated protocol concerns itself with variables that have more than one
value, such as repeated fields on protocol buffers.
"""

from efilter import dispatch
from efilter import protocol

from efilter.protocols import counted
from efilter.protocols import eq
from efilter.protocols import ordered

# Declarations:
# pylint: disable=unused-argument


@dispatch.multimethod
def repeated(first_value, *values):
    """Build a repeated variable from values, all of which are the same type.

    Repeated values usually [1] preserve order and always allow a single value
    to appear more than once. Order of repeated values is NOT significant even
    when it is preserved.

    Any repeated values passed to this function will be flattened (repeated
    values do not nest). If you pass a repeated value in the arguments
    its value type (as determined by IRepeated.value_type) must be the same
    as the type of the other arguments.

    1: Order is always preserved for repetead values created with 'repeated' or
    'meld' but not for repeated values created with other functions.
    """
    raise NotImplementedError()


def meld(*values):
    """Return the repeated value, or the first value if there's only one.

    This is a convenience function, equivalent to calling
    getvalue(repeated(x)) to get x.

    This function skips over instances of None in values (None is not allowed
    in repeated variables).

    Examples:
        meld("foo", "bar") # => ListRepetition("foo", "bar")
        meld("foo", "foo") # => ListRepetition("foo", "foo")
        meld("foo", None) # => "foo"
        meld(None) # => None
    """
    values = [x for x in values if x is not None]
    if not values:
        return None

    result = repeated(*values)
    if isrepeating(result):
        return result

    return getvalue(result)


@dispatch.multimethod
def lazy(generator_func):
    """Return a lazy repeated value of 'generator_func', which must be stable.

    For large datasets, it's useful to use lazy repeated values, because they
    avoid storing all the values of the repetition in memory.

    EFILTER ships a default implementation of this multimethod, found in
    efilter.ext.lazy_repetition.

    Arguments:
        generator_func: A function that returns a generator of the values that
            constitute this repeated value.

            IMPORTANT: This function MUST be stable, meaning the values in the
            generator MUST be the same each time the function is called.
    """
    raise NotImplementedError()


@dispatch.multimethod
def lines(fd):
    """Return a lazy repeated value of lines in 'fd' which is a File object.

    EFILTER ships a default implementation of this multimethod, found in
    efilter.ext.line_reader.

    Argument:
        fd: A File object that represents a text file.
    """
    raise NotImplementedError()


@dispatch.multimethod
def getvalues(x):
    """Return a collection of the values of x."""
    raise NotImplementedError()


def getvalue(x):
    """Return the single value of x or raise TypError if more than one value."""
    if isrepeating(x):
        raise TypeError(
            "Ambiguous call to getvalue for %r which has more than one value."
            % x)

    for value in getvalues(x):
        return value


@dispatch.multimethod
def value_type(x):
    """Return the type (class) of the values of x."""
    raise NotImplementedError()


@dispatch.multimethod
def value_eq(x, y):
    """Sorted comparison between the values in x and y."""
    raise NotImplementedError()


@dispatch.multimethod
def value_apply(x, f):
    """Apply f to each value of x and return a new repeated var of results."""
    raise NotImplementedError()


@dispatch.multimethod
def isrepeating(x):
    """Optional: Is x a repeated var AND does it have more than one value?"""
    return isinstance(x, IRepeated) and counted.count(x) > 1


class IRepeated(protocol.Protocol):
    _required_functions = (getvalues, value_type, value_eq, value_apply)
    _optional_functions = (isrepeating,)


def _scalar_value_eq(x, y):
    if isrepeating(y):
        return False

    return eq.eq(x, getvalue(y))


# If you're repeated, you automatically implement ICounted.
counted.ICounted.implement(
    for_type=IRepeated,
    implementations={
        counted.count: lambda r: len(getvalues(r))
    }
)


# Repeated values should sort as a tuple of themselves.
ordered.IOrdered.implement(
    for_type=IRepeated,
    implementations={
        ordered.assortkey: getvalues
    }
)


# Implementation for scalars:
# pylint: disable=unnecessary-lambda
IRepeated.implement(
    for_type=protocol.AnyType,
    implementations={
        getvalues: lambda x: (x,) if x is not None else (),
        value_type: lambda x: type(x),
        value_eq: _scalar_value_eq,
        value_apply: lambda x, f: f(x)
    }
)
