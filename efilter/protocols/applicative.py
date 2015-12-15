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
def apply(applicative, args, kwargs):
    """Return the result of calling 'applicative' with 'args'.

    Host program should implement function whitelisting in this function!
    """
    raise NotImplementedError()


def reflect_return(applicative):
    if isinstance(applicative, type):
        return reflect_static_return(applicative)

    return reflect_runtime_return(applicative)


def reflect_args(applicative):
    if isinstance(applicative, type):
        return reflect_static_args(applicative)

    return reflect_runtime_args(applicative)


@dispatch.class_multimethod
def reflect_static_args(applicative_cls):
    raise NotImplementedError()


@dispatch.multimethod
def reflect_runtime_args(applicative):
    return reflect_static_args(type(applicative))


@dispatch.class_multimethod
def reflect_static_return(applicative_cls):
    raise NotImplementedError()


@dispatch.multimethod
def reflect_runtime_return(applicative):
    return reflect_static_return(type(applicative))


class IApplicative(protocol.Protocol):
    _required_functions = (apply,)
    _optional_functions = (reflect_static_return, reflect_runtime_return,
                           reflect_static_args, reflect_runtime_args)
