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
def resolve(structured, key):
    raise NotImplementedError()


def getmembers(structured):
    if isinstance(structured, type):
        return getmembers_static(structured)

    return getmembers_runtime(structured)


@dispatch.class_multimethod
def getmembers_static(structured_cls):
    raise NotImplementedError()


@dispatch.multimethod
def getmembers_runtime(structured):
    return getmembers_static(type(structured))


def reflect(structured, name):
    if isinstance(structured, type):
        return reflect_static_member(structured, name)

    return reflect_runtime_member(structured, name)


@dispatch.class_multimethod
def reflect_static_member(structured_cls, name):
    """Provide the type of 'name' which is a member of 'structured_cls'.

    Arguments:
        associative_cls: The type of the structured object (like a dict).
        name: The name to be reflected. Must be a member of  'structured_cls'.

    Returns:
        The type of 'name' or None. Invalid names should return None,
        whereas valid names with unknown type should return AnyType.
    """
    raise NotImplementedError()


@dispatch.multimethod
def reflect_runtime_member(structured, name):
    return reflect_static_member(type(structured), name)


class IStructured(protocol.Protocol):
    _required_functions = (resolve,)
    _optional_functions = (reflect_runtime_member, reflect_static_member,
                           getmembers_static, getmembers_runtime)


# Lets us pretend that dicts are objects, which makes it easy for users to
# declare variables.
IStructured.implement(for_type=dict,
                      implementations={
                          resolve: lambda d, m: d[m],
                          getmembers_runtime: lambda d: d.keys()})
