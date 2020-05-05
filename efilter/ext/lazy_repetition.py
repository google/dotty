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
Implements IRepeated using a restartable generator.
"""

from builtins import next
from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.protocols import applicative
from efilter.protocols import counted
from efilter.protocols import eq
from efilter.protocols import ordered
from efilter.protocols import repeated


class LazyRepetition(object):
    """Repeated variable backed by a restartable generator.

    Arguments:
        generator_func: A function that returns a generator.
    """
    _generator_func = None

    def __init__(self, generator_func):
        if not callable(generator_func):
            raise TypeError("Generator function must be callable.")

        self._generator_func = generator_func

    def __iter__(self):
        return self._generator_func()

    def __repr__(self):
        return "LazyRepetition(generator_func=%r)" % (
            self._generator_func)

    # IRepeated protocol implementation (see IRepeated for behavior docs).

    def getvalues(self):
        """Yields all the values from 'generator_func' and type-checks.

        Yields:
            Whatever 'generator_func' yields.

        Raises:
            TypeError: if subsequent values are of a different type than first
                value.

            ValueError: if subsequent iteration returns a different number of
                values than the first iteration over the generator. (This would
                mean 'generator_func' is not stable.)
        """
        for value in self._generator_func():
            yield value

    # ICounted implementation:
    def count(self):
        count = 0
        for _ in self:
            count += 1
        return count


repeated.IRepeated.implicit_static(LazyRepetition)

# We really mean the toplevel object whatever this is (due to futurize
# this might be futurize.builtins.newobject)
repeated.lazy.implement(for_type=object.__mro__[-1],
                        implementation=LazyRepetition)

counted.ICounted.implicit_static(LazyRepetition)


def eq_implementation(self, other):
    if not repeated.isrepeating(other):
        return False
    for my_item, other_item in zip(self, other):
        if my_item  != other_item:
            return False
    return True


eq.IEq.implement(
    for_type=LazyRepetition,
    implementations={
        eq.eq: eq_implementation,
        eq.ne: lambda x, y: not (x == y)
    }
)
