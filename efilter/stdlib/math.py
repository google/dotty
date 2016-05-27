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
(EXPERIMENTAL) EFILTER stdlib - math module.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import six
from six.moves import xrange

from efilter.protocols import counted
from efilter.protocols import number
from efilter.stdlib import core


# Analytical functions:


class LevenshteinDistance(core.TypedFunction):
    """Compute Levenshtein distance between 'x' and 'y'.

    Levenshtein distance is, informally, the number of insert/delete/substitute
    operations needed to transform 'x' to 'y'. Computing the distance takes
    O(N * M) steps using the bottom-up dynamic programming approach below.

    See: https://en.wikipedia.org/wiki/Levenshtein_distance.
    """

    name = "levenshtein"

    def __call__(self, x, y):
        lx = len(x)
        ly = len(y)

        # Base cases:
        if not lx:
            return ly

        if not ly:
            return lx

        if lx > ly:
            # This saves space, because the rows are shorter.
            return self(y, x)

        # Conceptually, this is a matrix of edit distances between prefixes of
        # x and y, arranged so that every coordinate pair into the matrix is
        # the levenshtein distance between the first 'i' characters of 'x' and
        # first 'j' characters of 'y'. To compute the distance from x to y we
        # need all intermediate results, but only the last two rows at a time.

        # The first row of edit distances: an empty string can be transformed
        # into a string of length N in N steps.
        current_row = list(xrange(lx))

        for i in xrange(1, ly):
            previous_row = current_row
            current_row = [0] * lx
            current_row[0] = i

            for j in xrange(1, lx):
                if x[j - 1] == y[i - 1]:
                    substitution_cost = 0
                else:
                    substitution_cost = 1

                # One of three operations will have to lowest cost. They are,
                # in order, substitution (or nop), deletion and insertion.
                current_row[j] = min(
                    previous_row[j - 1] + substitution_cost,
                    previous_row[j] + 1,
                    current_row[j - 1] + 1)

        return current_row[-1]

    @classmethod
    def reflect_static_args(cls):
        return (six.string_types[0], six.string_types[0])

    @classmethod
    def reflect_static_return(cls):
        return int


# Aggregate functions (reducers):

class Mean(core.TypedReducer):
    """(EXPERIMENTAL) Computes the mean."""

    name = "mean"

    def fold(self, chunk):
        return (sum(chunk), counted.count(chunk))

    def merge(self, left, right):
        return (left[0] + right[0], left[1] + right[1])

    def finalize(self, intermediate):
        total, count = intermediate
        return float(total) / count

    @classmethod
    def reflect_static_return(cls):
        return int


class Sum(core.TypedReducer):
    """(EXPERIMENTAL) Computes a sum of numbers."""

    name = "sum"

    def fold(self, chunk):
        return sum(chunk)

    def merge(self, left, right):
        return left + right

    def finalize(self, intermediate):
        return intermediate

    @classmethod
    def reflect_static_return(cls):
        return number.INumber


class VectorSum(core.TypedReducer):
    """(EXPERIMENTAL) Computes a sum of vectors of numbers of constant size."""

    name = "vector_sum"

    def fold(self, chunk):
        iterator = iter(chunk)
        running_sum = list(next(chunk))
        expected_len = len(running_sum)
        for row in iterator:
            if len(row) != expected_len:
                raise ValueError(
                    "vector_sum can only add up vectors of same size.")

            for idx, col in enumerate(row):
                running_sum[idx] += col

    def merge(self, left, right):
        return self.fold([left, right])

    def finalize(self, intermediate):
        return intermediate

    @classmethod
    def reflect_static_return(cls):
        return list


MODULE = core.LibraryModule(
    name="stdmath",
    vars={
        Mean.name: Mean(),
        Sum.name: Sum(),
        LevenshteinDistance.name: LevenshteinDistance()
    }
)
