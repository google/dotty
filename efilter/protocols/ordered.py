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

if six.PY3:
    long = int


# Declarations:
# pylint: disable=unused-argument

@dispatch.multimethod
def lt(lhs, rhs):
    raise NotImplementedError()


class IOrdered(protocol.Protocol):
    _required_functions = (lt, )


def isordered(element):
    return isinstance(element, IOrdered)


# Default implementations:
IOrdered.implement(
    for_type=type(None),
    implementations={
        lt: lambda x, y: False
    }
)

IOrdered.implement(
    for_types=(int, long, float,),
    implementations={
        lt: lambda x, y: x < y
    }
)
