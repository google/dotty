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

from efilter.protocols import counted

# Declarations:
# pylint: disable=unused-argument


@dispatch.multimethod
def select(associative, key):
    raise NotImplementedError()


def getkeys(associative):
    if isinstance(associative, type):
        return getkeys_static(associative)

    return getkeys_runtime(associative)


@dispatch.class_multimethod
def getkeys_static(associative_cls):
    raise NotImplementedError()


@dispatch.multimethod
def getkeys_runtime(associative):
    return getkeys_static(type(associative))


def reflect(associative, key):
    if isinstance(associative, type):
        return reflect_static_key(associative, key)

    return reflect_runtime_key(associative, key)


@dispatch.class_multimethod
def reflect_static_key(associative_cls, key):
    """Provide the type of 'key' which is a member of 'associative_cls'.

    Arguments:
        associative_cls: The type of the associative object (like a dict).
        key: The name to be reflected. Must be a member of  'associative_cls'.

    Returns:
        The type of 'name' or None. Invalid names should return None,
        whereas valid names with unknown type should return AnyType.
    """
    raise NotImplementedError()


@dispatch.multimethod
def reflect_runtime_key(associative, key):
    return reflect_static_key(type(associative), key)


class IAssociative(protocol.Protocol):
    _required_functions = (select,)
    _optional_functions = (reflect_runtime_key, reflect_static_key,
                           getkeys_runtime, getkeys_static)


IAssociative.implement(for_type=dict,
                       implementations={
                           select: lambda d, key: d[key],
                           getkeys_runtime: lambda d: d.keys()})


IAssociative.implement(
    for_types=(list, tuple),
    implementations={
        select: lambda c, idx: c[idx],
        getkeys_runtime: lambda c: six.moves.range(counted.count(c))})
