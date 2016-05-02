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
EFILTER lexical scope container.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import protocol

from efilter.protocols import structured


class ScopeStack(object):
    """Stack of IStructured scopes from global to local.

    Arguments:
        scopes: A flat list of scopes from local (idx -1) to global (idx 0).
            Note that ScopeStackStack instances passed to the constructor are
            flattened.

            Each scope is either a subclass of IStructured or an instance of
            such subclass. When the ScopeStack is used in type inference
            the individual scopes are usually instances of type, or whatever
            objects the host application uses to emulate types. When used at
            runtime, they are, of course, instances.
    """

    scopes = ()

    @property
    def globals(self):
        return self.scopes[0]

    @property
    def locals(self):
        return self.scopes[-1]

    def __repr__(self):
        return "ScopeStack(%s)" % ", ".join((repr(s) for s in self.scopes))

    def __init__(self, *scopes):
        flattened_scopes = []
        for scope in scopes:
            if isinstance(scope, type(self)):
                flattened_scopes.extend(scope.scopes)
            elif isinstance(scope, type):
                flattened_scopes.append(scope)
            elif protocol.implements(scope, structured.IStructured):
                flattened_scopes.append(scope)
            else:
                raise TypeError("Scopes must be instances or subclasses of "
                                "IStructured; got %r." % (scope,))

        self.scopes = flattened_scopes

    # IStructured implementation.

    def resolve(self, name):
        """Call IStructured.resolve across all scopes and return first hit."""
        for scope in reversed(self.scopes):
            try:
                return structured.resolve(scope, name)
            except (KeyError, AttributeError):
                continue

        raise AttributeError(name)

    def getmembers(self):
        """Gets members (vars) from all scopes, using both runtime and static.

        This method will attempt both static and runtime getmembers. This is the
        recommended way of getting available members.

        Returns:
            Set of available vars.

        Raises:
            NotImplementedError if any scope fails to implement 'getmembers'.
        """
        names = set()
        for scope in self.scopes:
            if isinstance(scope, type):
                names.update(structured.getmembers_static(scope))
            else:
                names.update(structured.getmembers_runtime(scope))

        return names

    def getmembers_runtime(self):
        """Gets members (vars) from all scopes using ONLY runtime information.

        You most likely want to use ScopeStack.getmembers instead.

        Returns:
            Set of available vars.

        Raises:
            NotImplementedError if any scope fails to implement 'getmembers'.
        """
        names = set()
        for scope in self.scopes:
            names.update(structured.getmembers_runtime(scope))

        return names

    @classmethod
    def getmembers_static(cls):
        """Gets members (vars) from all scopes using ONLY static information.

        You most likely want to use ScopeStack.getmembers instead.

        Returns:
            Set of available vars.

        Raises:
            NotImplementedError if any scope fails to implement 'getmembers'.
        """
        names = set()
        for scope in cls.scopes:
            names.update(structured.getmembers_static(scope))

        return names

    def reflect(self, name):
        """Reflect 'name' starting with local scope all the way up to global.

        This method will attempt both static and runtime reflection. This is the
        recommended way of using reflection.

        Returns:
            Type of 'name', or protocol.AnyType.

        Caveat:
            The type of 'name' does not necessarily have to be an instance of
            Python's type - it depends on what the host application returns
            through the reflection API. For example, Rekall uses objects
            generated at runtime to simulate a native (C/C++) type system.
        """
        # Return whatever the most local scope defines this as, or bubble all
        # the way to the top.
        result = None
        for scope in reversed(self.scopes):
            try:
                if isinstance(scope, type):
                    result = structured.reflect_static_member(scope, name)
                else:
                    result = structured.reflect_runtime_member(scope, name)

                if result is not None:
                    return result

            except (NotImplementedError, KeyError, AttributeError):
                continue

        return protocol.AnyType

    def reflect_runtime_member(self, name):
        """Reflect 'name' using ONLY runtime reflection.

        You most likely want to use ScopeStack.reflect instead.

        Returns:
            Type of 'name', or protocol.AnyType.
        """
        for scope in reversed(self.scopes):
            try:
                return structured.reflect_runtime_member(scope, name)
            except (NotImplementedError, KeyError, AttributeError):
                continue

        return protocol.AnyType

    @classmethod
    def reflect_static_member(cls, name):
        """Reflect 'name' using ONLY static reflection.

        You most likely want to use ScopeStack.reflect instead.

        Returns:
            Type of 'name', or protocol.AnyType.
        """
        for scope in reversed(cls.scopes):
            try:
                return structured.reflect_static_member(scope, name)
            except (NotImplementedError, KeyError, AttributeError):
                continue

        return protocol.AnyType


structured.IStructured.implicit_static(ScopeStack)
