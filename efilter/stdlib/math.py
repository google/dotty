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


from efilter.protocols import counted
from efilter.protocols import number
from efilter.stdlib import core


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


MODULE = core.LibraryModule(name="stdmath",
                            vars={Mean.name: Mean(),
                                  Sum.name: Sum()})
