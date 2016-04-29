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
EFILTER type system.

This module implements multimethod function dispatch.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import functools
import six
import threading


def memoize(func):
    # Declare the class in this lexical scope so 'func' is bound to the
    # decorated callable.
    class memdict(dict):
        """Calls 'func' for missing keys in this dict subclass."""

        def __missing__(self, args):
            result = func(*args)
            self[args] = result
            return result

    cache = memdict()

    def memoized(*args):
        return cache[args]

    return memoized


def call_audit(func):
    """Print a detailed audit of all calls to this function."""
    def audited_func(*args, **kwargs):
        import traceback
        stack = traceback.extract_stack()
        r = func(*args, **kwargs)
        func_name = func.__name__

        print("@depth %d, trace %s -> %s(*%r, **%r) => %r" % (
            len(stack),
            " -> ".join("%s:%d:%s" % x[0:3] for x in stack[-5:-2]),
            func_name,
            args,
            kwargs,
            r))
        return r

    return audited_func


def _class_dispatch(args, kwargs):
    """See 'class_multimethod'."""
    _ = kwargs
    if not args:
        raise ValueError(
            "Multimethods must be passed at least one positional arg.")

    if not isinstance(args[0], type):
        raise TypeError(
            "class_multimethod must be called with a type, not instance.")

    return args[0]


def class_multimethod(func):
    """Declare a multimethod that dispatches on the first arg.

    If you think of 'multimethod' as working on the instances of classes then
    this would work on the classes.
    """
    return multimethod(func, dispatch_function=_class_dispatch)


class multimethod(object):
    """Multimethod that dispatches on the type of the first arg.

    This function decorator can be used on instance methods as well as regular
    functions. It allows the function to dispatch on the type of its first
    argument, much like standard python instance methods dispatch on the type
    of self (conceptually, not in actuality).

    This enables us to define arbitrary interfaces and have already existing
    types participate in those interfaces, without having to actually alter
    the existing type hierarchy or monkey-patch additional functions into their
    namespaces.

    This approach is used in EFILTER to enable it to be easily added to
    existing codebases, which may already overload many operators and have
    their own conventions about how members of objects are accessed and types
    interact.

    Arguments:
        func: The original function passed to the decorator. Usually 'func'
            should just raise NotImplementedError, but if not, it can be used
            as sort of a default behavior.
        dispatch_function: Optional. Can override the dispatch type derivation
            function, which takes the type of the first arg by default.

    Examples:
        @multimethod
        def say_moo(bovine):
            raise NotImplementedError()

        class Cow():
            pass

        say_moo.implement(for_type=Cow, implementation=lambda x: "Moo!")

        class Sheep():
            pass

        say_moo.implement(for_type=Sheep, implementation=lambda x: "Baah!")

        shaun = Sheep()
        bessy = Cow()

        say_moo(shaun)  # => "Baah!"
        say_moo(bessy)  # => "Moo!"
    """

    # Locks _dispatch_table and implementations.
    _write_lock = None

    # Cache of type -> implementation.
    _dispatch_table = None

    # Table of which dispatch type is preferred over which other type in
    # cases that benefit from disambiguation.
    _prefer_table = None

    implementations = None
    func = None

    is_multimethod = True

    # Can override behavior of default_dispatch to derive the dispatch type
    # some other way. For example, using types of more than just the first
    # argument, or by using the argument itself, in case of functions that
    # take classes as parameters.
    dispatch_function = None

    def __init__(self, func, dispatch_function=None):
        self._write_lock = threading.Lock()
        self.func = func
        self._dispatch_table = {}
        self._prefer_table = {}
        self.implementations = []
        self.dispatch_function = dispatch_function or self.default_dispatch
        functools.update_wrapper(self, func)

    @staticmethod
    def default_dispatch(args, kwargs):
        """Returns the type of the first argument as dispatch key."""
        _ = kwargs
        if not args:
            raise ValueError(
                "Multimethods must be passed at least one positional arg.")

        return type(args[0])

    @property
    def func_name(self):
        return self.func.__name__

    def __repr__(self):
        return "multimethod(%s)" % self.func_name

    def __call__(self, *args, **kwargs):
        """Pick the appropriate overload based on args and call it."""
        dispatch_type = self.dispatch_function(args, kwargs)
        implementation = self._find_and_cache_best_function(dispatch_type)
        if implementation:
            return implementation(*args, **kwargs)

        # Fall-through to calling default implementation. By convention, the
        # default will usually raise a NotImplemented exception, but there
        # may be times when it will actually do something useful (good example
        # are convenience type checking functions, such as isrepeated).
        try:
            return self.func(*args, **kwargs)
        except NotImplementedError:
            # Throw a better exception.
            if isinstance(None, dispatch_type):
                raise TypeError(
                    "%r was passed None for first argument, which was "
                    "unexpected." % self.func_name)

            implemented_types = [t for t, _ in self.implementations]
            raise NotImplementedError(
                "Multimethod %r is not implemented for type %r and has no "
                "default behavior. Overloads are defined for %r."
                % (self.func_name, dispatch_type, implemented_types))

    def implemented_for_type(self, dispatch_type):
        candidate = self._find_and_cache_best_function(dispatch_type)
        return candidate is not None

    def _preferred(self, preferred, over):
        prefs = self._prefer_table.get(preferred)
        if prefs and over in prefs:
            return True

        return False

    def prefer_type(self, prefer, over):
        """Prefer one type over another type, all else being equivalent.

        With abstract base classes (Python's abc module) it is possible for
        a type to appear to be a subclass of another type without the supertype
        appearing in the subtype's MRO. As such, the supertype has no order
        with respect to other supertypes, and this may lead to amguity if two
        implementations are provided for unrelated abstract types.

        In such cases, it is possible to disambiguate by explictly telling the
        function to prefer one type over the other.

        Arguments:
            prefer: Preferred type (class).
            over: The type we don't like (class).

        Raises:
            ValueError: In case of logical conflicts.
        """
        self._write_lock.acquire()
        try:
            if self._preferred(preferred=over, over=prefer):
                raise ValueError(
                    "Type %r is already preferred over %r." % (over, prefer))
            prefs = self._prefer_table.setdefault(prefer, set())
            prefs.add(over)
        finally:
            self._write_lock.release()

    def _find_and_cache_best_function(self, dispatch_type):
        """Finds the best implementation of this function given a type.

        This function caches the result, and uses locking for thread safety.

        Returns:
            Implementing function, in below order of preference:
            1. Explicitly registered implementations (through
               multimethod.implement) for types that 'dispatch_type' either is
               or inherits from directly.
            2. Explicitly registered implementations accepting an abstract type
               (interface) in which dispatch_type participates (through
               abstract_type.register() or the convenience methods).
            3. Default behavior of the multimethod function. This will usually
               raise a NotImplementedError, by convention.

        Raises:
            TypeError: If two implementing functions are registered for
                different abstract types, and 'dispatch_type' participates in
                both, and no order of preference was specified using
                prefer_type.
        """
        result = self._dispatch_table.get(dispatch_type)
        if result:
            return result

        # The outer try ensures the lock is always released.
        with self._write_lock:
            try:
                dispatch_mro = dispatch_type.mro()
            except TypeError:
                # Not every type has an MRO.
                dispatch_mro = ()

            best_match = None
            result_type = None

            for candidate_type, candidate_func in self.implementations:
                if not issubclass(dispatch_type, candidate_type):
                    # Skip implementations that are obviously unrelated.
                    continue

                try:
                    # The candidate implementation may be for a type that's
                    # actually in the MRO, or it may be for an abstract type.
                    match = dispatch_mro.index(candidate_type)
                except ValueError:
                    # This means we have an implementation for an abstract
                    # type, which ranks below all concrete types.
                    match = None

                if best_match is None:
                    if result and match is None:
                        # Already have a result, and no order of preference.
                        # This is probably because the type is a member of two
                        # abstract types and we have separate implementations
                        # for those two abstract types.

                        if self._preferred(candidate_type, over=result_type):
                            result = candidate_func
                            result_type = candidate_type
                        elif self._preferred(result_type, over=candidate_type):
                            # No need to update anything.
                            pass
                        else:
                            raise TypeError(
                                "Two candidate implementations found for "
                                "multimethod function %s (dispatch type %s) "
                                "and neither is preferred." %
                                (self.func_name, dispatch_type))
                    else:
                        result = candidate_func
                        result_type = candidate_type
                        best_match = match

                if (match or 0) < (best_match or 0):
                    result = candidate_func
                    result_type = candidate_type
                    best_match = match

            self._dispatch_table[dispatch_type] = result
            return result

    @staticmethod
    def __get_types(for_type=None, for_types=None):
        """Parse the arguments and return a tuple of types to implement for.

        Raises:
            ValueError or TypeError as appropriate.
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

        return for_types

    def implementation(self, for_type=None, for_types=None):
        """Return a decorator that will register the implementation.

        Example:
            @multimethod
            def add(x, y):
                pass

            @add.implementation(for_type=int)
            def add(x, y):
                return x + y

            @add.implementation(for_type=SomeType)
            def add(x, y):
                return int(x) + int(y)
        """
        for_types = self.__get_types(for_type, for_types)

        def _decorator(implementation):
            self.implement(implementation, for_types=for_types)
            return self

        return _decorator

    @staticmethod
    def __get_unbound_function(method):
        try:
            return six.get_method_function(method)
        except AttributeError:
            return method

    def implement(self, implementation, for_type=None, for_types=None):
        """Registers an implementing function for for_type.

        Arguments:
            implementation: Callable implementation for this type.
            for_type: The type this implementation applies to.
            for_types: Same as for_type, but takes a tuple of types.

            for_type and for_types cannot both be passed (for obvious reasons.)

        Raises:
            ValueError
        """
        unbound_implementation = self.__get_unbound_function(implementation)
        for_types = self.__get_types(for_type, for_types)

        for t in for_types:
            self._write_lock.acquire()
            try:
                self.implementations.append((t, unbound_implementation))
            finally:
                self._write_lock.release()
