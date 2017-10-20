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
Implements IRepeated using a list container.
"""

from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.protocols import repeated
from efilter.protocols import eq


class ListRepetition(object):
    """Repeated variable backed by a list."""

    _delegate = None

    def __init__(self, *values):
        self._delegate = []

        for value in values:
            self.add_value(value)

    def __iter__(self):
        return iter(self._delegate)

    def add_value(self, value):
        """Add a value to this repeated var.

        WARNING: this mutates the object (it's NOT copy on write). Unless
        you're absolutely certain of what you're doing, you most likely want
        to call repeated.meld(x, y) instead.
        """
        self._delegate.extend(repeated.getvalues(value))

    def add_single_value(self, value):
        """Same as 'add_value' but even more dangerous.

        Same caveats apply as with 'add_value' but also, the caller is
        responsible for ensuring 'value' is a scalar (not another repetition).
        """
        self._delegate.append(value)

    def __eq__(self, other):
        return eq.eq(self, other)

    def getvalues(self):
        # Return a copy because delegate is mutable and we don't want things
        # to blow up.
        return self._delegate[:]

    def value_apply(self, f):
        return repeated.repeated(*[f(x) for x in self.getvalues()])

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__,
                           ", ".join([repr(x) for x in self.getvalues()]))


repeated.IRepeated.implicit_static(ListRepetition)
repeated.repeated.implement(for_type=object.__mro__[-1],
                            implementation=ListRepetition)


def eq_impl(self, other):
    if not repeated.isrepeating(other):
        return False

    for x, y in zip(self, other):
        if eq.ne(x, y):
            return False

    return True


eq.IEq.implement(
    for_type=ListRepetition,
    implementations={
        eq.eq: eq_impl,
        eq.ne: lambda x, y: not eq_impl(x, y)
    }
)
