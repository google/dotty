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
import itertools
import re

from efilter import ast
from efilter import dispatch
from efilter import errors
from efilter import protocol
from efilter import query as q
from efilter import scope

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import boolean
from efilter.protocols import iset
from efilter.protocols import number
from efilter.protocols import ordered
from efilter.protocols import reflective
from efilter.protocols import repeated
from efilter.protocols import structured

from efilter.stdlib import core as std_core

Result = collections.namedtuple("Result", ["value", "branch"])


@dispatch.multimethod
def solve(query, vars):
    """Evaluate the 'query' using variables in 'vars'.

    Canonical implementation of the EFILTER AST's actual behavior. This may
    not be the most optimal way of executing the query, but it is guaranteed
    to have full coverage without falling through to some other implementation.

    Arguments:
        query: The instance of Query to evaluate against data in vars.
        vars: An object implementing IAssociative (like a dict) containing
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
    """
    _ = query, vars
    raise NotImplementedError()


@solve.implementation(for_type=q.Query)
def solve(query, vars):
    # Always include the standard library for now. We will revisit this later,
    # and probably add something to the AST for explicit imports.
    vars = scope.ScopeStack(std_core.FUNCTIONS, vars)

    try:
        return solve(query.root, vars)
    except errors.EfilterError as error:
        if not error.query:
            error.query = query.source
        raise


@solve.implementation(for_type=ast.Literal)
def solve(expr, vars):
    """Returns just the value of literal."""
    _ = vars
    return Result(expr.value, ())


@solve.implementation(for_type=ast.Var)
def solve(expr, vars):
    """Returns the value of the var (var) named in the expression."""
    try:
        return Result(structured.resolve(vars, expr.value), ())
    except (KeyError, AttributeError) as e:
        # Raise a better exception for accessing a non-existent member.
        raise errors.EfilterKeyError(root=expr, key=expr.value, message=e)
    except (TypeError, ValueError) as e:
        # Raise a better exception for what is probably a null pointer error.
        if vars is None:
            raise errors.EfilterNoneError(
                root=expr,
                message="Trying to access member %r of a null." % expr.value)
        else:
            raise errors.EfilterTypeError(
                root=expr,
                message="%r (vars: %r)" % (e, vars))
    except NotImplementedError as e:
        raise errors.EfilterError(
            root=expr,
            message="Trying to access member %r of an instance of %r." %
            (expr.value, type(vars)))


@solve.implementation(for_type=ast.Select)
def solve(expr, vars):
    """Use IAssociative.select to get key (rhs) from the data (lhs)."""
    data = __within_lhs_as_repeated(expr.lhs, vars)
    key = solve(expr.rhs, vars).value

    try:
        results = [associative.select(d, key) for d in repeated.getvalues(data)]
    except (KeyError, AttributeError):
        # Raise a better exception for accessing a non-existent key.
        raise errors.EfilterKeyError(root=expr, key=key)
    except (TypeError, ValueError):
        # Raise a better exception for what is probably a null pointer error.
        if vars is None:
            raise errors.EfilterNoneError(
                root=expr,
                message="Cannot select key %r from a null." % key)
        else:
            raise
    except NotImplementedError:
        raise errors.EfilterError(
            root=expr,
            message="Cannot select keys from a non-associative value.")

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Resolve)
def solve(expr, vars):
    """Use IStructured.resolve to get member (rhs) from the object (lhs)."""
    objs = __within_lhs_as_repeated(expr.lhs, vars)
    member = solve(expr.rhs, vars).value

    try:
        results = [structured.resolve(o, member)
                   for o in repeated.getvalues(objs)]
    except (KeyError, AttributeError):
        # Raise a better exception for the non-existent member.
        raise errors.EfilterKeyError(root=expr.rhs, key=member)
    except (TypeError, ValueError):
        # Is this a null object error?
        if vars is None:
            raise errors.EfilterNoneError(
                root=expr,
                message="Cannot resolve member %r from a null." % member)
        else:
            raise
    except NotImplementedError:
        raise errors.EfilterError(
            root=expr,
            message="Cannot resolve members from a non-structured value.")

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Apply)
def solve(expr, vars):
    """Returns the result of applying function (lhs) to its arguments (rest).

    We use IApplicative to apply the function, because that gives the host
    application an opportunity to compare the function being called against
    a whitelist. EFILTER will never directly call a function that wasn't
    provided through a protocol implementation.
    """
    func = solve(expr.func, vars).value
    args = []
    kwargs = {}
    for arg in expr.args:
        if isinstance(arg, ast.Pair):
            if not isinstance(arg.lhs, ast.Var):
                raise errors.EfilterError(
                    root=arg.lhs,
                    message="Invalid argument name.")

            kwargs[arg.key.value] = solve(arg.value, vars).value
        else:
            args.append(solve(arg, vars).value)

    result = applicative.apply(func, args, kwargs)

    return Result(result, ())


@solve.implementation(for_type=ast.Bind)
def solve(expr, vars):
    """Build a dict from key/value pairs under the bind."""
    result = {}
    for pair in expr.children:
        if not isinstance(pair, ast.Pair):
            raise errors.EfilterError(
                root=pair,
                message="Bind expression must consist of key/value pairs.")

        key = solve(pair.key, vars).value
        value = solve(pair.value, vars).value
        result[key] = value

    return Result(result, ())


@solve.implementation(for_type=ast.Repeat)
def solve(expr, vars):
    """Build a repeated value from subexpressions."""
    try:
        result = repeated.meld(*[solve(x, vars).value for x in expr.children])
        return Result(result, ())
    except TypeError:
        raise errors.EfilterTypeError(
            root=expr,
            message="All values in a repeated value must be of the same type.")


@solve.implementation(for_type=ast.Tuple)
def solve(expr, vars):
    """Build a tuple from subexpressions."""
    result = tuple(solve(x, vars).value for x in expr.children)
    return Result(result, ())


@solve.implementation(for_type=ast.IfElse)
def solve(expr, vars):
    """Evaluate conditions and return the one that matches."""
    for condition, result in expr.conditions():
        if boolean.asbool(solve(condition, vars).value):
            return solve(result, vars)

    return solve(expr.default(), vars)


def __within_lhs_as_repeated(lhs_expr, vars):
    """Map/Filter/others support lists and IRepeated on the LHS.

    If the value of 'lhs_expr' is a list or tuple of IAssociative objects then
    treat it as an IRepeated of IAssociative objects because that is what the
    caller meant to do. This is a convenience so that users don't have to
    create IRepeated objects.
    """
    var = solve(lhs_expr, vars).value
    if (var and isinstance(var, (tuple, list))
            and protocol.implements(var[0], associative.IAssociative)):
        return repeated.meld(*var)

    return var


@solve.implementation(for_type=ast.Map)
def solve(expr, vars):
    """Solves the map-form, by recursively calling its RHS with new vars.

    let-forms are binary expressions. The LHS should evaluate to an IAssociative
    that can be used as new vars with which to solve a new query, of which
    the RHS is the root. In most cases, the LHS will be a Var (var).

    Typically, map-forms result from the dotty "dot" (.) operator. For example,
    the query "User.name" will translate to a map-form with the var "User"
    on LHS and a var to "name" on the RHS. With top-level vars being
    something like {"User": {"name": "Bob"}}, the Var on the LHS will
    evaluate to {"name": "Bob"}, which subdict will then be used on the RHS as
    new vars, and that whole form will evaluate to "Bob".
    """
    lhs_values = __within_lhs_as_repeated(expr.lhs, vars)

    try:
        results = []
        for lhs_value in repeated.getvalues(lhs_values):
            nested_scope = scope.ScopeStack(vars, lhs_value)
            results.append(solve(expr.rhs, nested_scope).value)
    except errors.EfilterNoneError as error:
        error.root = expr
        raise

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Filter)
def solve(expr, vars):
    """Filter values on the LHS by evaluating RHS with each value.

    Returns any LHS values for which RHS evaluates to a true value.
    """
    lhs_values = __within_lhs_as_repeated(expr.lhs, vars)

    results = []
    for lhs_value in repeated.getvalues(lhs_values):
        nested_scope = scope.ScopeStack(vars, lhs_value)
        if solve(expr.rhs, nested_scope).value:
            results.append(lhs_value)

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Sort)
def sort(expr, vars):
    """Sort values on the LHS by the value they yield when passed to RHS."""
    lhs_values = repeated.getvalues(__within_lhs_as_repeated(expr.lhs, vars))

    sort_expression = expr.rhs

    def _key_func(x):
        sort_value = solve(sort_expression, scope.ScopeStack(vars, x))
        return ordered.assortkey(sort_value)

    results = sorted(lhs_values, key=_key_func)

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Each)
def solve(expr, vars):
    """Return True if RHS evaluates to a true value with each state of LHS.

    If LHS evaluates to a normal IAssociative object then this is the same as
    a regular let-form, except the return value is always a boolean. If LHS
    evaluates to a repeared var (see efilter.protocols.repeated) of
    IAssociative objects then RHS will be evaluated with each state and True
    will be returned only if each result is true.
    """
    lhs_values = __within_lhs_as_repeated(expr.lhs, vars)

    for lhs_value in repeated.getvalues(lhs_values):
        result = solve(expr.rhs, scope.ScopeStack(vars, lhs_value))
        if not result.value:
            # Each is required to return an actual boolean.
            return result._replace(value=False)

    return Result(True, ())


@solve.implementation(for_type=ast.Any)
def solve(expr, vars):
    """Same as Each, except returning True on first true result at LHS."""
    lhs_values = __within_lhs_as_repeated(expr.lhs, vars)

    try:
        rhs = expr.rhs
    except IndexError:
        # Child 1 is out of range. There is no condition on the RHS.
        # Just see if we have anything on the LHS.
        return Result(len(repeated.getvalues(lhs_values)) > 0, ())

    result = Result(False, ())
    for lhs_value in repeated.getvalues(lhs_values):
        result = solve(rhs, scope.ScopeStack(vars, lhs_value))
        if result.value:
            # Any is required to return an actual boolean.
            return result._replace(value=True)

    return result


@solve.implementation(for_type=ast.IsInstance)
def solve(expr, vars):
    """Typecheck whether LHS is type on the RHS."""
    lhs = solve(expr.lhs, vars)
    t = reflective.reflect(type(vars), expr.rhs)
    return Result(protocol.implements(lhs.value, t), ())


@solve.implementation(for_type=ast.Complement)
def solve(expr, vars):
    result = solve(expr.value, vars)
    return result._replace(value=not result.value)


@solve.implementation(for_type=ast.Intersection)
def solve(expr, vars):
    result = Result(False, ())
    for child in expr.children:
        result = solve(child, vars)
        if not result.value:
            # Intersections don't preserve the last value the way Unions do.
            return result._replace(value=False)

    return result


@solve.implementation(for_type=ast.Union)
def solve(expr, vars):
    for child in expr.children:
        result = solve(child, vars)
        if result.value:
            # Don't replace a matched child branch. Also, preserve the actual
            # value of the last subexpression (as opposed to just returning a
            # boolean).
            if result.branch:
                return result
            return result._replace(branch=child)

    return Result(False, ())


@solve.implementation(for_type=ast.Pair)
def solve(expr, vars):
    return Result((solve(expr.lhs, vars).value, solve(expr.rhs, vars).value),
                  ())


@solve.implementation(for_type=ast.Sum)
def solve(expr, vars):
    total = 0

    for child in expr.children:
        val = solve(child, vars).value
        try:
            total += val
        except TypeError:
            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=type(val),
                                          root=child)

    return Result(total, ())


@solve.implementation(for_type=ast.Difference)
def solve(expr, vars):
    children = enumerate(expr.children)
    _, first_child = next(children)
    difference = solve(first_child, vars).value

    for idx, child in children:
        val = solve(child, vars).value
        try:
            difference -= val
        except TypeError:
            # The type what caused that there error.
            if idx == 1:
                actual_t = type(difference)
            else:
                actual_t = type(val)

            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=actual_t,
                                          root=expr.children[idx - 1])

    return Result(difference, ())


@solve.implementation(for_type=ast.Product)
def solve(expr, vars):
    product = 1

    for child in expr.children:
        val = solve(child, vars).value
        try:
            product *= val
        except TypeError:
            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=type(val),
                                          root=child)

    return Result(product, ())


@solve.implementation(for_type=ast.Quotient)
def solve(expr, vars):
    children = enumerate(expr.children)
    _, first_child = next(children)
    quotient = solve(first_child, vars).value

    for idx, child in children:
        val = solve(child, vars).value
        try:
            quotient /= val
        except TypeError:
            # The type what caused that there error.
            if idx == 1:
                actual_t = type(quotient)
            else:
                actual_t = type(val)
            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=actual_t,
                                          root=expr.children[idx - 1])

    return Result(quotient, ())


@solve.implementation(for_type=ast.Equivalence)
def solve(expr, vars):
    children = iter(expr.children)
    first_value = solve(next(children), vars).value
    for child in children:
        if solve(child, vars).value != first_value:
            return Result(False, ())

    return Result(True, ())


@solve.implementation(for_type=ast.Membership)
def solve(expr, vars):
    element = solve(expr.element, vars).value
    values = solve(expr.set, vars).value

    if isinstance(values, repeated.IRepeated):
        return Result(element in repeated.getvalues(values), ())

    return Result(element in values, ())


@solve.implementation(for_type=ast.RegexFilter)
def solve(expr, vars):
    string = solve(expr.string, vars).value
    pattern = solve(expr.regex, vars).value

    return Result(re.compile(pattern).match(str(string)), ())


@solve.implementation(for_type=ast.StrictOrderedSet)
def solve(expr, vars):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), vars).value

    if min_ is None:
        return Result(False, ())

    for child in iterator:
        val = solve(child, vars).value

        if not min_ > val or val is None:
            return Result(False, ())

        min_ = val

    return Result(True, ())


@solve.implementation(for_type=ast.PartialOrderedSet)
def solve(expr, vars):
    iterator = iter(expr.children)
    min_ = solve(next(iterator), vars).value

    if min_ is None:
        return Result(False, ())

    for child in iterator:
        val = solve(child, vars).value

        if min_ < val or val is None:
            return Result(False, ())

        min_ = val

    return Result(True, ())
