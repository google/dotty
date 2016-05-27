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
Implements IStructured with a RowTuple to represent rows of output from SELECTS.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import collections
import six

from efilter.protocols import associative
from efilter.protocols import counted
from efilter.protocols import structured


class RowTuple(object):
    """Represents a row of output where column names are significant.

    The Bind expression, which is how DottySQL represents "SELECT AS" queries,
    assigns variable names to columns in output of the SELECT statement. This
    is the type we use to represent that row. It has several functions:

     - Preserves the order of columns in the output.
     - Implements a way to get values by either their index or by their name.
     - Implements IStructured, so the resulting row can be used as lexical
       scope for subexpressions.
     - Makes it possible to select a single column from a subselect and use it
       as a scalar value, while still retaining the column name, for example,
       "SELECT proc.pid AS pid FROM pslist" will return a RowTuple() with
       members set to ['pid'] and _vars set to {'pid': some_value}, which can
       be accessed as row_tuple["pid"], row_tuple[0] or row_tuple.get_singleton.

    The RowTuple can be treated as both a structured container and a tuple.

    Using the  IStructured protocol, values at named columns can be obtained
    with the 'resolve' function; 'getmembers' is also supported.

    Using IAssociative, values at numerical indices in the conceptual tuple
    can be obtained. The number of columns can be obtained using ICounted.

    The python __getitem__ magic method supports both numeric indices and column
    names. Iterating the RowTuple yields the values in order of columns.
    """
    ordered_dict = None

    class __UnsetSentinel(object):
        """This is a sentinel value for columns that haven't been initialized.

        Because order of columns is significant, we want to always initialize
        the ordered_dict container with the final list of columns in the
        constructor. If values of those columns are not yet available, we can
        set them to a sentinel value (this class) that signifies a KeyError
        should be raised if someone attempts to access the column before it's
        been set.
        """
        pass

    def __init__(self, values=None, ordered_columns=None):
        if ordered_columns is not None and values is not None:
            if sorted(values.keys()) != sorted(ordered_columns):
                raise ValueError(
                    "Bad arguments to RowTuple: ordered_columns were %r but "
                    "values had keys for %r."
                    % (ordered_columns, list(values.keys())))

            self.ordered_dict = collections.OrderedDict(
                [(c, values[c]) for c in ordered_columns])
        elif ordered_columns is not None:
            self.ordered_dict = collections.OrderedDict(
                [(c, self.__UnsetSentinel) for c in ordered_columns])
        elif values is not None:
            self.ordered_dict = collections.OrderedDict(
                sorted(values.items(), key=lambda t: t[1]))
        else:
            raise ValueError(
                "RowTuple must be instantiated with values, columns or both.")

    def get_singleton(self):
        """If the row only has one column, return that value; otherwise raise.

        Raises:
            ValueError, if count of columns is not 1.
        """
        only_value = None
        for value in six.itervalues(self.ordered_dict):
            # This loop will raise if it runs more than once.
            if only_value is not None:
                raise ValueError("%r is not a singleton." % self)

            only_value = value

        if only_value is self.__UnsetSentinel or only_value is None:
            raise ValueError("%r is empty." % self)

        return only_value

    @property
    def ordered_values(self):
        """Return a tuple of values in the order columns were specified."""
        return tuple(iter(self))

    # Implementing IAssociative:

    def select(self, idx):
        try:
            key = tuple(self.ordered_dict.keys())[idx]
        except TypeError:
            # Select should only raise KeyError or AttributeError.
            raise KeyError(idx)

        return self.resolve(key)

    # Implementing ICounted:

    def count(self):
        return len(self)

    # Implementing IStructured:

    def resolve(self, name):
        value = self.ordered_dict[name]
        if value is self.__UnsetSentinel:
            # Resolve should raise, not return None.
            raise KeyError(name)

        return value

    def getmembers_runtime(self):
        return tuple(self.ordered_dict.keys())

    # Magic methods:

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def __getitem__(self, key):
        if isinstance(key, six.integer_types):
            try:
                return self.select(key)
            except KeyError:
                # By convention, [] with numeric key should raise an IndexError.
                raise IndexError(key)

        return self.resolve(key)

    def __setitem__(self, key, value):
        if isinstance(key, six.integer_types):
            if key >= len(self):
                raise IndexError(key)

            key = tuple(self.ordered_dict.keys())[key]

        if not key in self.ordered_dict:
            raise KeyError("%r doesn't contain var %r." % (self, key))

        self.ordered_dict[key] = value

    def __repr__(self):
        return "RowTuple(%r)" % (self.ordered_dict)

    def __iter__(self):
        for value in six.itervalues(self.ordered_dict):
            if value is self.__UnsetSentinel:
                yield None
            else:
                yield value

    def __len__(self):
        return len(self.ordered_dict)

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.ordered_dict == other.ordered_dict
        elif isinstance(other, structured.IStructured):
            try:
                other_members = structured.getmembers(other)
            except NotImplementedError:
                return None

            members = sorted(self.ordered_dict.keys())
            if members != sorted(other_members):
                return False

            vals = tuple([self.get(m) for m in members])
            other_vals = tuple([structured.resolve(other, m) for m in members])
            return vals == other_vals
        elif isinstance(other, (tuple, list)):
            return list(self) == list(other)
        else:
            return None

    def __ne__(self, other):
        return not self.__eq__(other)

associative.IAssociative.implicit_static(RowTuple)
counted.ICounted.implicit_static(RowTuple)
structured.IStructured.implicit_static(RowTuple)
