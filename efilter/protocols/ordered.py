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

import six

from efilter import dispatch
from efilter import protocol

# Declarations:
# pylint: disable=unused-argument


def ordered(collection, key_func=None):
    if callable(key_func):
        def key_for_sorted(x):
            return assortkey(key_func(x))

    else:
        key_for_sorted = assortkey

    return sorted(collection, key=key_for_sorted)


@dispatch.multimethod
def assortkey(x):
    raise NotImplementedError()


class IOrdered(protocol.Protocol):
    _required_functions = (assortkey,)


# Default implementations:

IOrdered.implement(
    for_type=protocol.AnyType,
    implementations={
        assortkey: lambda x: x
    }
)


IOrdered.implement(
    for_type=dict,
    implementations={
        assortkey: lambda x: ordered(six.iteritems(x))
    }
)


IOrdered.implement(
    for_type=type(None),
    implementations={
        assortkey: lambda _: 0
    }
)
