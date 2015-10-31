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

"""
EFILTER abstract type system.

The type protocols defined under efilter.protocols.* provide a very thin layer
over Python's builtin types, defined as collections of related functions with
defined semantics. Each type protocol is intended to uniformly support a
specific behavior across any type that participates in the protocol.

To participate in a protocol, two things are required:
1) Implementations of each of the member functions must be provided.
2) The type must be formally added to the protocol.

In this manner, we are able to declare strict compositional types on atoms and
expressions in the EFILTER AST and allow type hierarchies external to EFILTER
(Plaso Events, Rekall Entities) to be passed to the EFILTER transforms without
casting or wrapping.

The compositional, flat nature of the type protocols makes it simple to support
basic type inference, by annotating each expression type with sets of
protocols it requires on its children and guarantees on its return type.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import abc


class AnyType(object):
    """Sentinel used to provide a default implementation of a protocol.

    If you need to provide a default implementation of functions in a
    protocol (for example, providing fall-through behavior for objects that
    don't participate in the protocol) you may pass this type in place of
    'object'. This will cause the multimethod functions to fall through to
    this default implementation, but won't cause 'object' to be a subclass
    of the protocol.

    Example:
        MyProtocol.implement(for_type=AnyType,
                             implementations={foo=lambda x: "foo"})

        foo(5)  # => "foo"
        isinstance(5, MyProtocol)  # => False
        implements(5, MyProtocol)  # => True
    """


BUILTIN_TYPES = (int, float, long, complex, basestring, tuple, list, dict, set,
                 frozenset, type(None), AnyType)


def implements(obj, protocol):
    """Does the object 'obj' implement the 'prococol'?"""
    if isinstance(obj, type):
        raise TypeError("First argument to implements must be an instance. "
                        "Got %r." % obj)
    return isinstance(obj, protocol) or issubclass(AnyType, protocol)


def isa(cls, protocol):
    """Does the type 'cls' participate in the 'protocol'?"""
    if not isinstance(cls, type):
        raise TypeError("First argument to isa must be a type. Got %r." % cls)

    if not isinstance(protocol, type):
        raise TypeError(("Second argument to isa must be a type or a Protocol. "
                         "Got an instance of %r.") % type(protocol))
    return issubclass(cls, protocol) or issubclass(AnyType, protocol)


class Protocol(object):
    """Collection of related functions that operate on a type (interface)."""
    __metaclass__ = abc.ABCMeta

    _protocol_functions = set()

    @classmethod
    def functions(cls):
        result = set(cls._protocol_functions)

        for scls in cls.mro():
            protocol_functions = getattr(scls, "_protocol_functions", None)
            if protocol_functions:
                result.update(protocol_functions)

        return result

    @classmethod
    def implemented(cls, for_type):
        for function in cls.functions():
            if not function.implemented_for_type(for_type):
                raise TypeError(
                    "%r doesn't implement %r so it cannot participate in "
                    "the protocol %r." %
                    (for_type, function.func.func_name, cls))

        cls.register(for_type)

    @classmethod
    def _implement_for_type(cls, for_type, implementations):
        # AnyType is a sentinel that means the multimethod function should
        # just dispatch on 'object'.
        dispatch_type = object if for_type is AnyType else for_type
        protocol_functions = cls.functions()
        remaining = set(protocol_functions)

        for func, impl in implementations.iteritems():
            if func not in protocol_functions:
                func_name = getattr(func, "func_name", repr(func))
                raise TypeError("Function %s is not part of the protocol %r." %
                                (func_name, cls))

            func.implement(for_type=dispatch_type,
                           implementation=impl)
            remaining.remove(func)

        if remaining:
            raise TypeError(
                "%s.implement invokation must provide implementations of "
                "%r" % (cls.__name__, remaining))

        cls.implemented(for_type=for_type)

    @classmethod
    def implicit_static(cls, for_type):
        """Automatically generate implementations for a type.

        Implement the protocol for the 'for_type' type by dispatching each
        member function of the protocol to an instance method of the same name
        declared on the type 'for_type'.

        Arguments:
            for_type: The type to implictly implement the protocol with.

        Raises:
            TypeError if not all implementations are provided by 'for_type'.
        """
        implementations = {}
        for function in cls.functions():
            method = getattr(for_type, function.func_name, None)
            if not callable(method):
                raise TypeError(
                    "%s.implicit invokation on type %r is missing instance "
                    "method %r." % (cls.__name__, for_type, function.func_name))

            implementations[function] = method

        return cls.implement(for_type=for_type, implementations=implementations)

    @staticmethod
    def _build_late_dispatcher(func_name):
        """Return a function that calls method 'func_name' on objects.

        This is useful for building late-bound dynamic dispatch.

        Arguments:
            func_name: The name of the instance method that should be called.

        Returns:
            A function that takes an 'obj' parameter, followed by *args and
            returns the result of calling the instance method with the same
            name as the contents of 'func_name' on the 'obj' object with the
            arguments from *args.
        """
        def _late_dynamic_dispatcher(obj, *args):
            method = getattr(obj, func_name, None)
            if not callable(method):
                raise NotImplementedError(
                    "Instance method %r is not implemented by %r." % (
                        func_name, obj))

            return method(*args)

        return _late_dynamic_dispatcher

    @classmethod
    def implicit_dynamic(cls, for_type):
        """Automatically generate late dynamic dispatchers to type.

        This is similar to 'implicit_static', except instead of binding the
        instance methods, it generates a dispatcher that will call whatever
        instance method of the same name happens to be available at time of
        dispatch.

        This has the obvious advantage of supporting arbitrary subclasses, but
        can do no verification at bind time.

        Arguments:
            for_type: The type to implictly implement the protocol with.
        """
        implementations = {}
        for function in cls.functions():
            implementations[function] = cls._build_late_dispatcher(
                func_name=function.func_name)

        return cls.implement(for_type=for_type, implementations=implementations)

    @classmethod
    def implement(cls, implementations, for_type=None, for_types=None):
        """Provide protocol implementation for a type.

        Register all implementations of multimethod functions in this
        protocol and add the type into the abstract base class of the
        protocol.

        Arguments:
            implementations: A dict of (function, implementation), where each
                function is multimethod and each implementation is a callable.
            for_type: The concrete type implementations apply to.
            for_types: Same as for_type, but takes a tuple of types.

            You may not supply both for_type and for_types for obvious reasons.

        Raises:
            ValueError for arguments.
            TypeError if not all implementations are provided or if there
                are issues related to polymorphism (e.g. attempting to
                implement a non-multimethod function.
        """
        if for_type:
            if for_types:
                raise ValueError("Cannot pass both for_type and for_types.")
            for_types = (for_type,)
        elif for_types:
            if not isinstance(for_types, tuple):
                raise TypeError("for_types must be passed as a tuple of "
                                "types (classes).")
        else:
            raise ValueError("Must pass either for_type or for_types.")

        for type_ in for_types:
            cls._implement_for_type(for_type=type_,
                                    implementations=implementations)
