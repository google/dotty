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

from efilter.transforms import solve
from efilter.transforms import infer_type

from efilter.stdlib import io as std_io


def apply(query, replacements=None, vars=None, allow_io=False):
    """Run 'query' on 'vars' and return the result(s).

    Arguments:
        query: A query object or string with the query.
        replacements: Built-time parameters to the query, either as dict or
            as an array (for positional interpolation).
        vars: The variables to be supplied to the query solver.
        allow_io: If True then functions from stdlib.io will be included and
            allowed to read from the filesystem. Use with caution!
            (default: False)

            WARNING: If the query returns a lazily-evaluated result that depends
            on reading from a file (for example, filtering a CSV file) then the
            file descriptor will remain open until the returned result is
            deallocated. The caller is responsible for releasing the result when
            it's no longer needed.

    Returns:
        The result of evaluating the query. The type of the output will depend
        on the query, and can be predicted using 'infer' (provided reflection
        callbacks are implemented). In the common case of a SELECT query the
        return value will be an iterable of filtered data (actually an object
        implementing IRepeated, as well as __iter__.)

    Raises:
        efilter.errors.EfilterError if there are issues with the query.

    Examples:
        apply("5 + 5") # -> 10

        apply("SELECT * FROM people WHERE age > 10",
              people=({"age": 10, "name": "Bob"},
                      {"age": 20, "name": "Alice"},
                      {"age": 30, "name": "Eve"})) # -> LazyRepetition(...)

        # This will replace the question mark (?) with the string "Bob" in a
        # safe manner, preventing SQL injection.
        apply("SELECT * FROM people WHERE name = ?", replacements=["Bob"], ...)
    """
    if vars is None:
        vars = {}

    query = q.Query(query, params=replacements)
    if allow_io:
        vars = scope.ScopeStack(std_io.FUNCTIONS, vars)

    results = solve.solve(query, vars).value

    return results


def infer(query, replacements=None, root_type=None):
    """Determine the type of the query's output without actually running it.

    Arguments:
        query: A query object or string with the query.
        replacements: Built-time parameters to the query, either as dict or as
            an array (for positional interpolation).
        root_type: The types of variables to be supplied to the query inference.

    Returns:
        The type of the query's output, if it can be determined. If undecidable,
        returns efilter.protocol.AnyType.

        NOTE: The inference returns the type of a row in the results, not of the
        actual Python object returned by 'apply'. For example, if a query
        returns multiple rows, each one of which is an integer, the type of the
        output is considered to be int, not a collection of rows.

    Examples:
        infer("5 + 5") # -> INumber

        infer("SELECT * FROM people WHERE age > 10") # -> AnyType

        # If root_type implements the IStructured reflection API:
        infer("SELECT * FROM people WHERE age > 10", root_type=...) # -> dict
    """
    query = q.Query(query, params=replacements)
    return infer_type.infer_type(query, root_type)


def search(query, data, replacements=None):
    """Yield objects from 'data' that match the 'query'."""
    query = q.Query(query, params=replacements)
    for entry in data:
        if solve.solve(query, entry).value:
            yield entry
