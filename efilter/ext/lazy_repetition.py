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

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.protocols import counted
from efilter.protocols import ordered
from efilter.protocols import repeated


class LazyRepetition(object):
    """Repeated variable backed by a restartable generator.

    Arguments:
        generator_func: A stable function that returns a generator. Stable
            means that the generator must be the same every time the function
            is called (for the express purpose of reseting iteration).
    """

    _generator_func = None
    _value_type = None  # Just a cache for value_type.
    _watermark = 0  # Highest idx reached so far.

    # The count of values. After first complete iteration this will be one
    # higher than watermark.
    _count = None

    def __init__(self, generator_func):
        if not callable(generator_func):
            raise TypeError("Generator function must be callable.")

        self._generator_func = generator_func

    def __eq__(self, other):
        if not isinstance(other, repeated.IRepeated):
            return False

        return self.value_eq(other)

    def __iter__(self):
        return self._generator_func()

    def __repr__(self):
        return "LazyRepetition(generator_func=%r, value_type=%r)" % (
            self._generator_func, self.value_type())

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
        idx = 0
        generator = self._generator_func()
        first_value = next(generator)
        self._value_type = type(first_value)
        yield first_value

        for idx, value in enumerate(generator):
            if not isinstance(value, self._value_type):
                raise TypeError(
                    "All values of a repeated var must be of the same type."
                    " First argument was of type %r, but argument %r is of"
                    " type %r." %
                    (self._value_type, value, repeated.value_type(value)))

            self._watermark = max(self._watermark, idx + 1)
            yield value

        # Iteration stopped - check if we're at the previous watermark and raise
        # if not.
        if idx + 1 < self._watermark:
            raise ValueError(
                "LazyRepetition %r was previously able to iterate its"
                " generator up to idx %d, but this time iteration stopped after"
                " idx %d! Generator function %r is not stable." %
                (self, self._watermark, idx + 1, self._generator_func))

        # Watermark is higher than previous count! Generator function returned
        # more values this time than last time.
        if self._count is not None and self._watermark >= self._count:
            raise ValueError(
                "LazyRepetition %r previously iterated only up to idx %d but"
                " was now able to reach idx %d! Generator function %r is not"
                " stable." %
                (self, self._count - 1, idx + 1, self._generator_func))

        # We've finished iteration - cache count. After this the count will be
        # watermark + 1 forever.
        self._count = self._watermark + 1

    def value_type(self):
        if self._value_type is None:
            for value in self.getvalues():
                self._value_type = type(value)
                break

        return self._value_type

    def value_eq(self, other):
        """Sorted comparison of values."""
        self_sorted = ordered.ordered(self.getvalues())
        other_sorted = ordered.ordered(repeated.getvalues(other))
        return self_sorted == other_sorted

    def value_apply(self, f):
        def _generator():
            for value in self.getvalues():
                yield f(value)

        return LazyRepetition(_generator)

    # ICounted implementation:

    def count(self):
        if not self._count:
            # Do a complete pass over the generator to cause _count to be set.
            for _ in self.getvalues():
                pass

        return self._count


repeated.IRepeated.implicit_static(LazyRepetition)
repeated.lazy.implement(for_type=object, implementation=LazyRepetition)
counted.ICounted.implicit_static(LazyRepetition)
