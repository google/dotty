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

import abc
import itertools

from efilter import dispatch
from efilter import protocol

# Declarations:
# pylint: disable=unused-argument


class AbstractPythonCallable(object):
    """Abstract base class for anything that implements __call__."""

    __metaclass__ = abc.ABCMeta

    @classmethod
    def __subclasshook__(cls, C):
        # Let's not create an inheritance cycle.
        if C is IApplicative:
            return NotImplemented

        if callable(C):
            return True

        return NotImplemented


@dispatch.multimethod
def apply(applicative, args, kwargs):
    """Return the result of calling 'applicative' with 'args'.

    Host program should implement function whitelisting in this function!
    """
    raise NotImplementedError()


@dispatch.class_multimethod
def reflect_args(applicative):
    """Return an iterable with types of arguments that 'applicative' takes."""
    raise NotImplementedError()


@dispatch.class_multimethod
def reflect_return(applicative):
    """Return the return type of 'applicative'."""
    raise NotImplementedError()


class IApplicative(protocol.Protocol):
    _protocol_functions = (apply, reflect_args, reflect_return)


IApplicative.implement(
    for_type=AbstractPythonCallable,
    implementations={
        apply: lambda a, args, kwargs: a(*args, **kwargs),

        # I thought about what the default implementation should look like for
        # Python functions and I realized this is actually literally as much
        # guarantee as the language provides.
        reflect_args: lambda _: itertools.repeat(protocol.AnyType),
        reflect_return: lambda _: protocol.AnyType
    })
