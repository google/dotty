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
EFILTER individual object filter and matcher.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


# pylint: disable=function-redefined

import collections
import re

from efilter import ast
from efilter import dispatch
from efilter import errors
from efilter import protocol
from efilter import query as q


from efilter.protocols import associative
from efilter.protocols import iset
from efilter.protocols import reflective
from efilter.protocols import repeated


Result = collections.namedtuple("Result", ["value", "branch", "sort_key"])


@dispatch.multimethod
def solve(query, bindings):
    """Evaluate the 'query' using variables in 'bindings'.

    Canonical implementation of the EFILTER AST's actual behavior. This may
    not be the most optimal way of executing the query, but it is guaranteed
    to have full coverage without falling through to some other implementation.

    Arguments:
        query: The instance of Query to evaluate against data in bindings.
        bindings: An object implementing IAssociative (like a dict) containing
            pairs of variable -> value.

    Returns:
        Instance of Result, with members set as follows:

            value: The result of evaluation. The type of the result can be
                determined by calling infer_type on 'query'.

            branch: An instance of Expression, representing a subtree of 'query'
                that was that last branch evaluated before a match was produced.
                This only applies to simple queries using AND/OR and NOT
                operators, which evaluate to booleans and can terminate early.
                For other queries this will be set to None.

            sort_key: A key by which the 'bindings' should be sorted with
                respect to other groups of bindings of the same type. Not
                currently implemented.
    """
    _ = query, bindings
    raise NotImplementedError()


@solve.implementation(for_type=q.Query)
def solve(query, bindings):
    try:
        return solve(query.root, bindings)
    except errors.EfilterError as error:
        if not error.query:
            error.query = query.source
        raise


@solve.implementation(for_type=ast.Literal)
def solve(expr, bindings):
    """Returns just the value of literal."""
    _ = bindings
    return Result(expr.value, (), ())


@solve.implementation(for_type=ast.Binding)
def solve(expr, bindings):
    """Returns the value of the binding (var) named in the expression."""
    try:
        return Result(associative.resolve(bindings, expr.value), (), ())
    except (KeyError, AttributeError) as e:
        # Raise a better exception for accessing a non-existent member.
        raise errors.EfilterKeyError(root=expr, key=expr.value, message=e)
    except (TypeError, ValueError) as e:
        # Raise a better exception for what is probably a null pointer error.
        if isinstance(bindings, type(None)):
            raise errors.EfilterNoneError(
                root=expr,
                message="Trying to access member %r of a null." % expr.value)
        else:
            raise
    except NotImplementedError as e:
        raise errors.EfilterError(
            root=expr,
            message="Trying to access member %r of an instance of %r." %
            (expr.value, type(bindings)))


@solve.implementation(for_type=ast.Map)
def solve(expr, bindings):
    """Solves the map-form, by recursively calling its RHS with new bindings.

    let-forms are binary expressions. The LHS should evaluate to an IAssociative
    that can be used as new bindings with which to solve a new query, of which
    the RHS is the root. In most cases, the LHS will be a Binding (var).

    Typically, map-forms result from the dotty "dot" (.) operator. For example,
    the query "User.name" will translate to a map-form with the binding "User"
    on LHS and a binding to "name" on the RHS. With top-level bindings being
    something like {"User": {"name": "Bob"}}, the Binding on the LHS will
    evaluate to {"name": "Bob"}, which subdict will then be used on the RHS as
    new bindings, and that whole form will evaluate to "Bob".
    """
    lhs = solve(expr.lhs, bindings)

    try:
        values = []
        for value in repeated.getvalues(lhs.value):
            value_ = solve(expr.rhs, value)
            values.append(value_.value)
    except errors.EfilterNoneError as error:
        error.root = expr
        raise

    return Result(repeated.meld(*values), (), ())


@solve.implementation(for_type=ast.Filter)
def solve(expr, bindings):
    """Filter values on the LHS by evaluating RHS with each value.

    Returns any LHS values for which RHS evaluates to a true value.
    """
    lhs = solve(expr.lhs, bindings)

    results = []
    for value in repeated.getvalues(lhs.value):
        if solve(expr.rhs, value).value:
            results.append(value)

    return Result(repeated.meld(*results), (), ())


@solve.implementation(for_type=ast.Sort)
def sort(expr, bindings):
    """Sort values on the LHS by the value they yield when passed to RHS."""
    values = repeated.getvalues(solve(expr.lhs, bindings).value)
    values = sorted(values, key=lambda val: solve(expr.rhs, val))
    return Result(repeated.meld(*values), (), ())


@solve.implementation(for_type=ast.Each)
def solve(expr, bindings):
    """Return True if RHS evaluates to a true value with each state of LHS.

    If LHS evaluates to a normal IAssociative object then this is the same as
    a regular let-form, except the return value is always a boolean. If LHS
    evaluates to a repeared var (see efilter.protocols.repeated) of
    IAssociative objects then RHS will be evaluated with each state and True
    will be returned only if each result is true.
    """
    branch_bindings = solve(expr.lhs, bindings).value
    for state in repeated.getvalues(branch_bindings):
        result = solve(expr.rhs, state)
        if not result.value:
            return result

    return Result(True, (), ())


@solve.implementation(for_type=ast.Any)
def solve(expr, bindings):
    """Same as Each, except returning True on first true result at LHS."""
    branch_bindings = solve(expr.lhs, bindings).value
    result = Result(False, (), ())
    for state in repeated.getvalues(branch_bindings):
        result = solve(expr.rhs, state)
        if result.value:
            return result

    return result


@solve.implementation(for_type=ast.IsInstance)
def solve(expr, bindings):
    """Typecheck whether LHS is type on the RHS."""
    lhs = solve(expr.lhs, bindings)
    t = reflective.reflect(type(bindings), expr.rhs)
    return Result(protocol.implements(lhs.value, t), (), ())


@solve.implementation(for_type=ast.Complement)
def solve(expr, bindings):
    result = solve(expr.value, bindings)
    return result._replace(value=not result.value)


@solve.implementation(for_type=ast.Intersection)
def solve(expr, bindings):
    result = Result(False, (), ())
    for child in expr.children:
        result = solve(child, bindings)
        if not result.value:
            return result

    return result


@solve.implementation(for_type=ast.Union)
def solve(expr, bindings):
    for child in expr.children:
        result = solve(child, bindings)
        if result.value:
            return result._replace(branch=child)

    return Result(False, (), ())


@solve.implementation(for_type=ast.Sum)
def solve(expr, bindings):
    total = 0
    for child in expr.children:
        total += solve(child, bindings).value

    return Result(total, (), ())


@solve.implementation(for_type=ast.Difference)
def solve(expr, bindings):
    children = iter(expr.children)
    difference = solve(next(children), bindings).value
    for child in children:
        difference -= solve(child, bindings).value

    return Result(difference, (), ())


@solve.implementation(for_type=ast.Product)
def solve(expr, bindings):
    product = 1
    for child in expr.children:
        product *= solve(child, bindings).value

    return Result(product, (), ())


@solve.implementation(for_type=ast.Quotient)
def solve(expr, bindings):
    children = iter(expr.children)
    quotient = solve(next(children), bindings).value
    for child in children:
        quotient /= solve(child, bindings).value

    return Result(quotient, (), ())


@solve.implementation(for_type=ast.Equivalence)
def solve(expr, bindings):
    children = iter(expr.children)
    first_value = solve(next(children), bindings).value
    for child in children:
        if solve(child, bindings).value != first_value:
            return Result(False, (), ())

    return Result(True, (), ())


@solve.implementation(for_type=ast.Membership)
def solve(expr, bindings):
    element = solve(expr.element, bindings).value
    values = solve(expr.set, bindings).value
    return Result(element in values, (), ())


@solve.implementation(for_type=ast.RegexFilter)
def solve(expr, bindings):
    string = solve(expr.string, bindings).value
    pattern = solve(expr.regex, bindings).value

    return Result(re.compile(pattern).match(str(string)), (), ())


@solve.implementation(for_type=ast.ContainmentOrder)
def solve(expr, bindings):
    _ = bindings
    iterator = iter(expr.children)
    x = solve(next(iterator), bindings).value
    for y in iterator:
        y = solve(y, bindings).value
        if not iset.issubset(x, y):
            return Result(False, (), ())
        x = y

    return Result(True, (), ())


@solve.implementation(for_type=ast.StrictOrderedSet)
def solve(expr, bindings):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), bindings).value

    if min_ is None:
        return Result(False, (), ())

    for child in iterator:
        val = solve(child, bindings).value

        if not min_ > val or val is None:
            return Result(False, (), ())

        min_ = val

    return Result(True, (), ())


@solve.implementation(for_type=ast.PartialOrderedSet)
def solve(expr, bindings):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), bindings).value

    if min_ is None:
        return Result(False, (), ())

    for child in iterator:
        val = solve(child, bindings).value

        if min_ < val or val is None:
            return Result(False, (), ())

        min_ = val

    return Result(True, (), ())
