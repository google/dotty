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


@dispatch.multimethod
def sum(x, y):
    raise NotImplementedError()


@dispatch.multimethod
def product(x, y):
    raise NotImplementedError()


@dispatch.multimethod
def difference(x, y):
    raise NotImplementedError()


@dispatch.multimethod
def quotient(x, y):
    raise NotImplementedError()


class INumber(protocol.Protocol):
    _required_functions = (sum, product, difference, quotient)


# Default implementations:

INumber.implement(
    for_types=(float, complex) + six.integer_types,
    implementations={
        sum: lambda x, y: x + y,
        product: lambda x, y: x * y,
        difference: lambda x, y: x - y,
        quotient: lambda x, y: x / y
    }
)
