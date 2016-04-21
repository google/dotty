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

"""(EXPERIMENTAL) EFILTER abstract type system."""

import itertools

from efilter import dispatch
from efilter import protocol

from efilter.protocols import repeated

# Declarations:
# pylint: disable=unused-argument

# Determined as good trade-off between memory usage and speed based on the
# hygdata_v3 benchmark.
DEFAULT_CHUNK_SIZE = 4096


@dispatch.multimethod
def fold(reducer, chunk):
    """Reduce 'chunk' into an intermediate value."""
    raise NotImplementedError()


@dispatch.multimethod
def merge(reducer, left, right):
    """Merge two intermediate values (from 'merge' or 'fold').

    Returns:
        Intermediate value merged from 'left' and 'right'.
    """
    raise NotImplementedError()


@dispatch.multimethod
def finalize(reducer, intermediate):
    """Convert the 'intermediate' to the final result of the reducer."""
    raise NotImplementedError()


def generate_chunks(data, chunk_size=DEFAULT_CHUNK_SIZE):
    """Yield 'chunk_size' items from 'data' at a time."""
    iterator = iter(repeated.getvalues(data))

    while True:
        chunk = list(itertools.islice(iterator, chunk_size))
        if not chunk:
            return

        yield chunk


def reduce(reducer, data, chunk_size=DEFAULT_CHUNK_SIZE):
    """Repeatedly call fold and merge on data and then finalize.

    Arguments:
        data: Input for the fold function.
        reducer: The IReducer to use.
        chunk_size: How many items should be passed to fold at a time?

    Returns:
        Return value of finalize.
    """
    if not chunk_size:
        return finalize(reducer, fold(reducer, data))

    # Splitting the work up into chunks allows us to, e.g. reduce a large file
    # without loading everything into memory, while still being significantly
    # faster than repeatedly calling the fold function for every element.
    chunks = generate_chunks(data, chunk_size)
    intermediate = fold(reducer, next(chunks))
    for chunk in chunks:
        intermediate = merge(reducer, intermediate, fold(reducer, chunk))

    return finalize(reducer, intermediate)


class IReducer(protocol.Protocol):
    _required_functions = (fold, finalize, merge)


class Compose(object):
    """Reducer that runs multiple other reducers on the same input."""
    reducers = None

    def __init__(self, *reducers):
        self.reducers = reducers

    def fold(self, chunk):
        return [fold(r, chunk) for r in self.reducers]

    def merge(self, left, right):
        result = []
        for idx, r in enumerate(self.reducers):
            result.append(merge(r, left[idx], right[idx]))

        return result

    def finalize(self, intermediate):
        result = []
        for idx, r in enumerate(self.reducers):
            result.append(finalize(r, intermediate[idx]))

        return result


IReducer.implicit_static(Compose)


class Map(object):
    """Reducer that converts the input before calling the delegate."""
    delegate = None
    mapper = None

    def __init__(self, delegate, mapper):
        if not callable(mapper):
            raise TypeError("Mapper must be callable.")

        self.mapper = mapper
        self.delegate = delegate

    def fold(self, chunk):
        return self.delegate.fold(tuple(self.mapper(chunk)))

    def merge(self, left, right):
        return self.delegate.merge(left, right)

    def finalize(self, intermediate):
        return self.delegate.finalize(intermediate)


IReducer.implicit_static(Map)
