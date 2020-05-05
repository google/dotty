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
EFILTER convenience API.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import query as q
from efilter import scope

from efilter.protocols import repeated
from efilter.protocols import string

from efilter.transforms import solve

from efilter.stdlib import core as std_core


def apply(query, replacements=None, vars=None, allow_io=False,
          libs=("stdcore", "stdmath")):
    """Run 'query' on 'vars' and return the result(s).

    Arguments:
        query: A query object or string with the query.
        replacements: Built-time parameters to the query, either as dict or
            as an array (for positional interpolation).
        vars: The variables to be supplied to the query solver.
        allow_io: (Default: False) Include 'stdio' and allow IO functions.
        libs: Iterable of library modules to include, given as strings.
            Default: ('stdcore', 'stdmath')
            For full list of bundled libraries, see efilter.stdlib.

            Note: 'stdcore' must always be included.

            WARNING: Including 'stdio' must be done in conjunction with
                'allow_io'. This is to make enabling IO explicit. 'allow_io'
                implies that 'stdio' should be included and so adding it to
                libs is actually not required.

    Notes on IO: If allow_io is set to True then 'stdio' will be included and
    the EFILTER query will be allowed to read files from disk. Use this with
    caution.

        If the query returns a lazily-evaluated result that depends on reading
        from a file (for example, filtering a CSV file) then the file
        descriptor will remain open until the returned result is deallocated.
        The caller is responsible for releasing the result when it's no longer
        needed.

    Returns:
        The result of evaluating the query. The type of the output will depend
        on the query, and can be predicted using 'infer' (provided reflection
        callbacks are implemented). In the common case of a SELECT query the
        return value will be an iterable of filtered data (actually an object
        implementing IRepeated, as well as __iter__.)

    A word on cardinality of the return value:
        Types in EFILTER always refer to a scalar. If apply returns more than
        one value, the type returned by 'infer' will refer to the type of
        the value inside the returned container.

        If you're unsure whether your query returns one or more values (rows),
        use the 'getvalues' function.

    Raises:
        efilter.errors.EfilterError if there are issues with the query.

    Examples:
        apply("5 + 5") # -> 10

        apply("SELECT * FROM people WHERE age > 10",
              vars={"people":({"age": 10, "name": "Bob"},
                              {"age": 20, "name": "Alice"},
                              {"age": 30, "name": "Eve"}))

        # This will replace the question mark (?) with the string "Bob" in a
        # safe manner, preventing SQL injection.
        apply("SELECT * FROM people WHERE name = ?", replacements=["Bob"], ...)
    """
    if vars is None:
        vars = {}

    if allow_io:
        libs = list(libs)
        libs.append("stdio")

    query = q.Query(query, params=replacements)

    stdcore_included = False
    for lib in libs:
        if lib == "stdcore":
            stdcore_included = True
            # 'solve' always includes this automatically - we don't have a say
            # in the matter.
            continue

        if lib == "stdio" and not allow_io:
            raise ValueError("Attempting to include 'stdio' but IO not "
                             "enabled. Pass allow_io=True.")

        module = std_core.LibraryModule.ALL_MODULES.get(lib)
        if not lib:
            raise ValueError("There is no standard library module %r." % lib)
        vars = scope.ScopeStack(module, vars)

    if not stdcore_included:
        raise ValueError("EFILTER cannot work without standard lib 'stdcore'.")

    results = solve.solve(query, vars).value

    return results


def getvalues(result):
    """Return an iterator of results of 'apply'.

    The 'apply' function can return one or more values, depending on the query.
    If you are unsure whether your query evaluates to a scalar or a collection
    of scalars, 'getvalues' will always return an iterator with one or more
    elements.

    Arguments:
        result: Anything. If it's an instance of IRepeated, all values will be
            returned.

    Returns:
        An iterator of at least one element.
    """
    return repeated.getvalues(result)


def user_func(func, arg_types=None, return_type=None):
    """Create an EFILTER-callable version of function 'func'.

    As a security precaution, EFILTER will not execute Python callables
    unless they implement the IApplicative protocol. There is a perfectly good
    implementation of this protocol in the standard library and user functions
    can inherit from it.

    This will declare a subclass of the standard library TypedFunction and
    return an instance of it that EFILTER will happily call.

    Arguments:
        func: A Python callable that will serve as the implementation.
        arg_types (optional): A tuple of argument types. If the function takes
            keyword arguments, they must still have a defined order.
        return_type (optional): The type the function returns.

    Returns:
        An instance of a custom subclass of efilter.stdlib.core.TypedFunction.

    Examples:
        def my_callback(tag):
            print("I got %r" % tag)

        api.apply("if True then my_callback('Hello World!')",
                  vars={
                    "my_callback": api.user_func(my_callback)
                  })

        # This should print "I got 'Hello World!'".
    """
    class UserFunction(std_core.TypedFunction):
        name = func.__name__

        def __call__(self, *args, **kwargs):
            return func(*args, **kwargs)

        @classmethod
        def reflect_static_args(cls):
            return arg_types

        @classmethod
        def reflect_static_return(cls):
            return return_type

    return UserFunction()


def scalar_function(func, arg_types=(string.IString,), pad=0):
    """Defines a function which operates on a scalar.

    If a repeated value is provided, then this will be called once on
    each arg and the result will be packaged in a list. This allows
    users to define a single function which works both on repeated and
    non repeated values.

    The arg_types tuple should specify the protocols the args must
    support. If the arg does not support this protocol, the wrapper
    returns None without calling the func.
    """
    class UserFunction(std_core.TypedFunction):
        name = func.__name__

        def __call__(self, *args, **kwargs):
            result = []
            expanded_args = []
            max_length = 1
            for expanded_arg in args:
                if repeated.isrepeating(expanded_arg):
                    # Materialize it.
                    expanded_arg = list(expanded_arg)
                    max_length = max(max_length, len(expanded_arg))
                expanded_args.append(expanded_arg)

            # Second pass pad or expand to the correct length.
            padded_args = []
            for expanded_arg in expanded_args:
                if isinstance(expanded_arg, list):
                    expanded_arg.extend([pad] * (max_length-len(expanded_arg)))
                else:
                    expanded_arg = [expanded_arg] * max_length
                padded_args.append(expanded_arg)

            for args in zip(*padded_args):
                result.append(self._call_on_scalar(args, kwargs))

            return result

        def _call_on_scalar(self, args, kwargs):
            # Type check args
            for arg, arg_type in zip(args, arg_types):
                if arg_type is not None and not isinstance(arg, arg_type):
                    return None

            return func(*args, **kwargs)

        @classmethod
        def reflect_static_args(cls):
            return arg_types

        @classmethod
        def reflect_static_return(cls):
            return return_type

    return UserFunction()


def search(query, data, replacements=None):

    """Yield objects from 'data' that match the 'query'."""
    query = q.Query(query, params=replacements)
    for entry in data:
        if solve.solve(query, entry).value:
            yield entry
