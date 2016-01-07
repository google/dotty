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
    _watermark = 0

    def __init__(self, generator_func):
        if not callable(generator_func):
            raise TypeError("Generator function must be callable.")

        self._generator_func = generator_func

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

    def value_type(self):
        if self._value_type is None:
            for value in self.getvalues():
                self._value_type = type(value)
                break

        return self._value_type

    def value_eq(self, other):
        return sorted(self.getvalues()) == sorted(repeated.getvalues(other))

    def __eq__(self, other):
        if not isinstance(other, repeated.IRepeated):
            return False

        return self.value_eq(other)

    def value_apply(self, f):
        def _generator():
            for value in self.getvalues():
                yield f(value)

        return LazyRepetition(_generator)


repeated.IRepeated.implicit_static(LazyRepetition)
repeated.lazy.implement(for_type=object, implementation=LazyRepetition)
