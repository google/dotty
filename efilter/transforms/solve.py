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

from efilter import dispatch
from efilter import query as q
from efilter import ast
from efilter import protocol

from efilter.protocols import associative
from efilter.protocols import iset
from efilter.protocols import name_delegate
from efilter.protocols import superposition


Result = collections.namedtuple("Result", ["value", "branch", "sort_key"])


@dispatch.polymorphic
def solve(query, bindings, app_delegate):
    """Evaluate the 'query' using variables in 'bindings'.

    Canonical implementation of the EFILTER AST's actual behavior. This may
    not be the most optimal way of executing the query, but it is guaranteed
    to have full coverage without falling through to some other implementation.

    Arguments:
        query: The instance of Query to evaluate against data in bindings.
        bindings: An object implementing IAssociative (like a dict) containing
            pairs of variable -> value.
        app_delegate: An object implementing INameDelegate which will be asked
            for types and values of global names.

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
    _ = query, bindings, app_delegate
    raise NotImplementedError()


@solve.implementation(for_type=q.Query)
def solve(query, bindings, app_delegate):
    return solve(query.root, bindings, app_delegate)


@solve.implementation(for_type=ast.Literal)
def solve(expr, bindings, app_delegate):
    """Returns just the value of literal."""
    _ = app_delegate, bindings
    return Result(expr.value, (), ())


@solve.implementation(for_type=ast.Binding)
def solve(expr, bindings, app_delegate):
    """Returns the value of the binding (var) named in the expression."""
    _ = app_delegate
    return Result(associative.resolve(bindings, expr.value), (), ())


@solve.implementation(for_type=ast.Let)
def solve(expr, bindings, app_delegate):
    """Solves the let-form, by recursively calling its RHS with new bindings.

    let-forms are binary expressions. The LHS should evaluate to an IAssociative
    that can be used as new bindings with which to solve a new query, of which
    the RHS is the root. In most cases, the LHS will be a Binding (var).

    Typically, let-forms result from the dotty "dot" (.) operator. For example,
    the query "User.name" will translate to a let-form with the binding "User"
    on LHS and a binding to "name" on the RHS. With top-level bindings being
    something like {"User": {"name": "Bob"}}, the Binding on the LHS will
    evaluate to {"name": "Bob"}, which subdict will then be used on the RHS as
    new bindings, and that whole form will evaluate to "Bob".
    """
    return solve(expr.rhs,
                 solve(expr.lhs, bindings, app_delegate).value,
                 app_delegate)


@solve.implementation(for_type=ast.LetEach)
def solve(expr, bindings, app_delegate):
    """Return True if RHS evaluates to a true value with each state of LHS.

    If LHS evaluates to a normal IAssociative object then this is the same as
    a regular let-form, except the return value is always a boolean. If LHS
    evaluates to a superposition (see efilter.protocols.superposition) of
    IAssociative objects then RHS will be evaluated with each state and True
    will be returned only if each result is true.
    """
    branch_bindings = solve(expr.lhs, bindings, app_delegate).value
    for state in superposition.getstates(branch_bindings):
        result = solve(expr.rhs, state, app_delegate)
        if not result.value:
            return result

    return Result(True, (), ())


@solve.implementation(for_type=ast.LetAny)
def solve(expr, bindings, app_delegate):
    """Same as LetEach, except returning True on first true result at LHS."""
    branch_bindings = solve(expr.lhs, bindings, app_delegate).value
    result = Result(False, (), ())
    for state in superposition.getstates(branch_bindings):
        result = solve(expr.rhs, state, app_delegate)
        if result.value:
            return result

    return result


@solve.implementation(for_type=ast.ComponentLiteral)
def solve(expr, bindings, app_delegate):
    _ = app_delegate
    return Result(getattr(bindings.components, expr.value), (), ())


@solve.implementation(for_type=ast.IsInstance)
def solve(expr, bindings, app_delegate):
    """Use 'app_delegate' to determine type of the var and typecheck it."""
    cls = name_delegate.reflect(app_delegate, expr.value)
    return Result(protocol.isa(cls, type(bindings)), (), ())


@solve.implementation(for_type=ast.Complement)
def solve(expr, bindings, app_delegate):
    result = solve(expr.value, bindings, app_delegate)
    return result._replace(value=not result.value)


@solve.implementation(for_type=ast.Intersection)
def solve(expr, bindings, app_delegate):
    result = Result(False, (), ())
    for child in expr.children:
        result = solve(child, bindings, app_delegate)
        if not result.value:
            return result

    return result


@solve.implementation(for_type=ast.Union)
def solve(expr, bindings, app_delegate):
    for child in expr.children:
        result = solve(child, bindings, app_delegate)
        if result.value:
            return result._replace(branch=child)

    return Result(False, (), ())


@solve.implementation(for_type=ast.Sum)
def solve(expr, bindings, app_delegate):
    total = 0
    for child in expr.children:
        total += solve(child, bindings, app_delegate).value

    return Result(total, (), ())


@solve.implementation(for_type=ast.Difference)
def solve(expr, bindings, app_delegate):
    children = iter(expr.children)
    difference = solve(next(children), bindings, app_delegate).value
    for child in children:
        difference -= solve(child, bindings, app_delegate).value

    return Result(difference, (), ())


@solve.implementation(for_type=ast.Product)
def solve(expr, bindings, app_delegate):
    product = 1
    for child in expr.children:
        product *= solve(child, bindings, app_delegate).value

    return Result(product, (), ())


@solve.implementation(for_type=ast.Quotient)
def solve(expr, bindings, app_delegate):
    children = iter(expr.children)
    quotient = solve(next(children), bindings, app_delegate).value
    for child in children:
        quotient /= solve(child, bindings, app_delegate).value

    return Result(quotient, (), ())


@solve.implementation(for_type=ast.Equivalence)
def solve(expr, bindings, app_delegate):
    children = iter(expr.children)
    first_value = solve(next(children), bindings, app_delegate).value
    for child in children:
        if solve(child, bindings, app_delegate).value != first_value:
            return Result(False, (), ())

    return Result(True, (), ())


@solve.implementation(for_type=ast.Membership)
def solve(expr, bindings, app_delegate):
    element = solve(expr.element, bindings, app_delegate).value
    values = solve(expr.set, bindings, app_delegate).value
    return Result(element in values, (), ())


@solve.implementation(for_type=ast.RegexFilter)
def solve(expr, bindings, app_delegate):
    string = solve(expr.string, bindings, app_delegate).value
    pattern = solve(expr.regex, bindings, app_delegate).value

    return Result(re.compile(pattern).match(str(string)), (), ())


@solve.implementation(for_type=ast.ContainmentOrder)
def solve(expr, bindings, app_delegate):
    _ = bindings, app_delegate
    iterator = iter(expr.children)
    x = solve(next(iterator), bindings, app_delegate).value
    for y in iterator:
        y = solve(y, bindings, app_delegate).value
        if not iset.issubset(x, y):
            return Result(False, (), ())
        x = y

    return Result(True, (), ())


@solve.implementation(for_type=ast.StrictOrderedSet)
def solve(expr, bindings, app_delegate):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), bindings, app_delegate).value

    if min_ is None:
        return Result(False, (), ())

    for child in iterator:
        val = solve(child, bindings, app_delegate).value

        if not min_ > val or val is None:
            return Result(False, (), ())

        min_ = val

    return Result(True, (), ())


@solve.implementation(for_type=ast.PartialOrderedSet)
def solve(expr, bindings, app_delegate):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), bindings, app_delegate).value

    if min_ is None:
        return Result(False, (), ())

    for child in iterator:
        val = solve(child, bindings, app_delegate).value

        if min_ < val or val is None:
            return Result(False, (), ())

        min_ = val

    return Result(True, (), ())
