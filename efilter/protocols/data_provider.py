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

"""EFILTER abstract type system.

The data provider is intended to be similar to a collector in Rekall. Using the
protocol, an application can expose generators of objects selected based on
different criteria, such as desired types and hinted queries.

This module is experimental and subject to frequent change.
"""

from efilter import dispatch
from efilter import protocol


# pylint: disable=unused-argument


@dispatch.multimethod
def provide(provider, query=None, params=None):
    raise NotImplementedError()


@dispatch.multimethod
def declare_output(provider, query=None):
    raise NotImplementedError()


@dispatch.multimethod
def declare_input(provider, query=None):
    raise NotImplementedError()


class IDataProvider(protocol.Protocol):
    _protocol_functions = (provide, declare_input, declare_output)
