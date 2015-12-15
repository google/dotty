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

This special protocol defines functions for an application/service level
delegate object, intended to provide type information and a global name service
to EFILTER. Implementing this protocol will enable EFILTER expressions to
reference globals and provide stronger type protections and hints in the
query analyzer.
"""

from efilter import dispatch
from efilter import protocol


# pylint: disable=unused-argument


def reflect(reflective_type, name):
    """Provide the type of 'name' which is a member of 'reflective_type'.

    Arguments:
        reflective_type: The application delegate.
        name: The name to be reflected. Either a global (from getnames) or
            a member of 'scope', which is a type or a container.

    Returns:
        The type of 'name' or None. Invalid names should return None,
        whereas valid names with unknown type should return AnyType.

    Examples:
        # What's a process?
        reflect(delegate, "Process") #=> Process

        # What's pslist?
        reflect(delegate, "pslist") #=> <Plugin pslist>

        # What's the pid column's type?
        reflect(
            reflect(delegate, "pslist"),
            "pid") #=> int
    """
    raise NotImplementedError()


def _liberal_dispatch(args, kwargs):
    """This makes the multimethod accept both classes and their instances.

    You may be wondering why. It's a fair question. Most other protocols in
    efilter use the default multimethod dispatch, which decides which overload
    to call based on the type of the first argument. The first version of the
    reflective protocol used a dispatch that worked on the types themselves,
    instead of instances: you would pass the multimethods the actual type as
    first argument, instead of an object, and this worked well with class
    methods and all was well.

    Enter Rekall. Rekall, because it simulates the type systems of a large
    number of different operating system versions, doesn't know what type a
    particular object will be until runtime, when it can determine the correct
    types based on debug symbols from the OS being analyzed. There was no
    reasonable way for Rekall to use this protocol! Simultaneously, the vast
    majority of other projects will be perfectly well served by class-level
    implementations, and a runtime reflection system would be burdensome.

    The most practical solution is what I here refer to as liberal dispatch -
    if you pass a multimethod with liberal dispatch a type, it will use it. If
    not, it will dispatch on the type of the instance. Everyone wins.

    Direct your hate mail (or better ideas) to adamsh@google.com.
    """

    if not args:
        raise ValueError(
            "Multimethods must be passed at least one positional arg.")

    if isinstance(args[0], type):
        return args[0]
    else:
        return type(args[0])


reflect = dispatch.multimethod(reflect,
                               dispatch_function=_liberal_dispatch)


def getkeys(reflective_type):
    """Provide a list of keys that can be reflected or selected/resolved."""
    raise NotImplementedError()


getkeys = dispatch.multimethod(getkeys,
                               dispatch_function=_liberal_dispatch)


class IReflective(protocol.Protocol):
    _required_functions = (reflect, getkeys)


IReflective.implement(for_type=dict,
                      implementations={
                          reflect: lambda _, __: protocol.AnyType,
                          getkeys: lambda d: d.keys()})


IReflective.implement(for_type=protocol.AnyType,
                      implementations={
                          reflect: lambda _, __: protocol.AnyType,
                          getkeys: lambda _: ()})
