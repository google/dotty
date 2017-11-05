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

"""EFILTER abstract type system."""

from efilter import dispatch
from efilter import protocol

# Declarations:
# pylint: disable=unused-argument


@dispatch.multimethod
def eq(x, y):
    """The default simply refers back to python's own comparator."""
    try:
        return x == y
    except TypeError:
        # If the python comparator fails the values are not equal.
        return False


@dispatch.multimethod
def ne(x, y):
    return not eq(x, y)


class IEq(protocol.Protocol):
    _required_functions = (eq, )
    _optional_functions = (ne, )


# Default implementations:
def _robust_cb(cb, *args, **kwargs):
    try:
        cb(*args, **kwargs)
    except TypeError:
        return False


# Lists are compared sorted so we dont care about their order.
IEq.implement(
    for_types=(list, tuple),
    implementations={
        eq: _robust_cb(lambda x, y: sorted(x) == sorted(y)),
    }
)
