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
import six

from efilter import ast
from efilter import dispatch
from efilter import errors
from efilter import protocol
from efilter import query as q
from efilter import scope

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import boolean
from efilter.protocols import number
from efilter.protocols import ordered
from efilter.protocols import reducer
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
        vars: An object implementing IStructured (like a dict) containing
            pairs of variable -> value. Best thing to pass is an instance of
            efilter.scope.ScopeStack, which is what the solver will convert
            'vars' to anyway, eventually.

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


def __solve_for_repeated(expr, vars):
    """Helper: solve 'expr' always returning an IRepeated.

    If the result of solving 'expr' is a list or a tuple of IAssociative objects
    then treat is as a repeated value of IAssociative objects because that's
    what the called meant to do. This is a convenience helper so users of the
    API don't have to create IRepeated objects.

    If the result of solving 'expr' is a scalar then return it as a repeated
    value of one element.

    Arguments:
        expr: Expression to solve.
        vars: The scope.

    Returns:
        IRepeated result of solving 'expr'.
    """
    var = solve(expr, vars).value
    if (var and isinstance(var, (tuple, list))
            and protocol.implements(var[0], associative.IAssociative)):
        return repeated.meld(*var)

    return var


def __solve_for_scalar(expr, vars):
    """Helper: solve 'expr' always returning a scalar (not IRepeated).

    If the output of 'expr' is a single value or a single dict with a single
    value then return that value. Otherwise raise an EfilterTypeError.

    Arguments:
        expr: Expression to solve.
        varS: The scope.

    Returns:
        A scalar value (not an IRepeated).

    Raises:
        EfilterTypeError if it cannot get a scalar.
    """
    var = solve(expr, vars).value
    try:
        scalar = repeated.getvalue(var)
    except TypeError:
        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="Wasn't expecting more than one value here. Got %r."
            % (var,))

    if isinstance(scalar, associative.IAssociative):
        keys = associative.getkeys(scalar)
        if len(keys) == 1:
            return associative.select(scalar, list(keys)[0])
        else:
            raise errors.EfilterTypeError(
                root=expr, query=expr.source,
                message="Was expecting a scalar value here. Got %r."
                % (scalar,))
    else:
        return scalar


def __solve_and_destructure_repeated(expr, vars):
    """Helper: solve 'expr' always returning a list of scalars.

    If the output of 'expr' is one or more dicts (IAssociative) of a single
    element then return a repeated value of those single elements. If the dicts
    have more than one element each then raise.

    This returns a list because there's no point in wrapping the scalars in
    a repeated value for use internal to the implementing solver.

    Returns:
        A list (not an IRepeated!) of scalars.

    Raises:
        EfilterTypeError if the values don't conform.
    """
    values = iter(__solve_for_repeated(expr, vars))

    try:
        first_value = next(values)
    except StopIteration:
        return []

    if not isinstance(first_value, associative.IAssociative):
        results = [first_value]
        # We skip type checking the remaining values because it'd be slow.
        results.extend(values)
        return results

    keys = associative.getkeys(first_value)
    if len(keys) == 1:
        key = list(keys)[0]
    else:
        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="Was expecting at most one key in %r." % (first_value,))

    results = [associative.select(first_value, key)]
    for value in values:
        results.append(associative.select(value, key))

    return results


def __nest_scope(expr, outer, inner):
    try:
        return scope.ScopeStack(outer, inner)
    except TypeError:
        if protocol.implements(inner, applicative.IApplicative):
            raise errors.EfilterTypeError(
                root=expr, query=expr.source,
                message="Attempting to use a function %r as an object." % inner)

        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="Attempting to use %r as an object (IStructured)." % inner)


@solve.implementation(for_type=q.Query)
def solve_query(query, vars):
    # Standard library must always be included. Others are optional, and the
    # caller can add them to vars using ScopeStack.
    vars = scope.ScopeStack(std_core.MODULE, vars)

    try:
        return solve(query.root, vars)
    except errors.EfilterError as error:
        if not error.query:
            error.query = query.source
        raise


@solve.implementation(for_type=ast.Literal)
def solve_literal(expr, vars):
    """Returns just the value of literal."""
    _ = vars
    return Result(expr.value, ())


@solve.implementation(for_type=ast.Var)
def solve_var(expr, vars):
    """Returns the value of the var named in the expression."""
    try:
        return Result(structured.resolve(vars, expr.value), ())
    except (KeyError, AttributeError) as e:
        # Raise a better exception for accessing a non-existent member.
        raise errors.EfilterKeyError(root=expr, key=expr.value, message=e,
                                     query=expr.source)
    except (TypeError, ValueError) as e:
        # Raise a better exception for what is probably a null pointer error.
        if vars.locals is None:
            raise errors.EfilterNoneError(
                root=expr, query=expr.source,
                message="Trying to access member %r of a null." % expr.value)
        else:
            raise errors.EfilterTypeError(
                root=expr, query=expr.source,
                message="%r (vars: %r)" % (e, vars))
    except NotImplementedError as e:
        raise errors.EfilterError(
            root=expr, query=expr.source,
            message="Trying to access member %r of an instance of %r." %
            (expr.value, type(vars)))


@solve.implementation(for_type=ast.Select)
def solve_select(expr, vars):
    """Use IAssociative.select to get key (rhs) from the data (lhs).

    This operation supports both scalars and repeated values on the LHS -
    selecting from a repeated value implies a map-like operation and returns a
    new repeated value.
    """
    data = __solve_for_repeated(expr.lhs, vars)
    key = solve(expr.rhs, vars).value

    try:
        results = [associative.select(d, key) for d in repeated.getvalues(data)]
    except (KeyError, AttributeError):
        # Raise a better exception for accessing a non-existent key.
        raise errors.EfilterKeyError(root=expr, key=key, query=expr.source)
    except (TypeError, ValueError):
        # Raise a better exception for what is probably a null pointer error.
        if vars.locals is None:
            raise errors.EfilterNoneError(
                root=expr, query=expr.source,
                message="Cannot select key %r from a null." % key)
        else:
            raise
    except NotImplementedError:
        raise errors.EfilterError(
            root=expr, query=expr.source,
            message="Cannot select keys from a non-associative value.")

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Resolve)
def solve_resolve(expr, vars):
    """Use IStructured.resolve to get member (rhs) from the object (lhs).

    This operation supports both scalars and repeated values on the LHS -
    resolving from a repeated value implies a map-like operation and returns a
    new repeated values.
    """
    objs = __solve_for_repeated(expr.lhs, vars)
    member = solve(expr.rhs, vars).value

    try:
        results = [structured.resolve(o, member)
                   for o in repeated.getvalues(objs)]
    except (KeyError, AttributeError):
        # Raise a better exception for the non-existent member.
        raise errors.EfilterKeyError(root=expr.rhs, key=member,
                                     query=expr.source)
    except (TypeError, ValueError):
        # Is this a null object error?
        if vars.locals is None:
            raise errors.EfilterNoneError(
                root=expr, query=expr.source,
                message="Cannot resolve member %r from a null." % member)
        else:
            raise
    except NotImplementedError:
        raise errors.EfilterError(
            root=expr, query=expr.source,
            message="Cannot resolve members from a non-structured value.")

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Apply)
def solve_apply(expr, vars):
    """Returns the result of applying function (lhs) to its arguments (rest).

    We use IApplicative to apply the function, because that gives the host
    application an opportunity to compare the function being called against
    a whitelist. EFILTER will never directly call a function that wasn't
    provided through a protocol implementation.
    """
    func = __solve_for_scalar(expr.func, vars)
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
def solve_bind(expr, vars):
    """Build a dict from key/value pairs under the bind.

    The Bind subtree is arranged as follows:

    Bind
    | First KV Pair
    | | First Key Expression
    | | First Value Expression
    | Second KV Pair
    | | Second Key Expression
    | | Second Value Expression
    Etc...

    As we evaluate the subtree, each subsequent KV pair is evaluated with
    the all previous bingings already in scope. For example:

    bind(x: 5, y: x + 5)  # Will bind y = 10 because x is already available.
    """
    result = {}
    intermediate_scope = scope.ScopeStack(vars, result)

    for pair in expr.children:
        if not isinstance(pair, ast.Pair):
            raise errors.EfilterError(
                root=pair, query=expr.source,
                message="Bind expression must consist of key/value pairs.")

        key = solve(pair.key, intermediate_scope).value
        value = solve(pair.value, intermediate_scope).value

        # Update the intermediate bindings so as to make earlier bindings
        # already available to the next child-expression.
        result[key] = value

    return Result(result, ())


@solve.implementation(for_type=ast.Repeat)
def solve_repeat(expr, vars):
    """Build a repeated value from subexpressions."""
    try:
        result = repeated.meld(*[solve(x, vars).value for x in expr.children])
        return Result(result, ())
    except TypeError:
        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="All values in a repeated value must be of the same type.")


@solve.implementation(for_type=ast.Tuple)
def solve_tuple(expr, vars):
    """Build a tuple from subexpressions."""
    result = tuple(solve(x, vars).value for x in expr.children)
    return Result(result, ())


@solve.implementation(for_type=ast.IfElse)
def solve_ifelse(expr, vars):
    """Evaluate conditions and return the one that matches."""
    for condition, result in expr.conditions():
        if boolean.asbool(solve(condition, vars).value):
            return solve(result, vars)

    return solve(expr.default(), vars)


@solve.implementation(for_type=ast.Map)
def solve_map(expr, vars):
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
    lhs_values = __solve_for_repeated(expr.lhs, vars)

    def lazy_map():
        try:
            for lhs_value in repeated.getvalues(lhs_values):
                yield solve(expr.rhs,
                            __nest_scope(expr.lhs, vars, lhs_value)).value
        except errors.EfilterNoneError as error:
            error.root = expr
            raise

    return Result(repeated.lazy(lazy_map), ())


@solve.implementation(for_type=ast.Let)
def solve_let(expr, vars):
    """Solves a let-form by calling RHS with nested scope."""
    lhs_value = solve(expr.lhs, vars).value
    if not isinstance(lhs_value, structured.IStructured):
        raise errors.EfilterTypeError(
            root=expr.lhs, query=expr.original,
            message="The LHS of 'let' must evaluate to an IStructured. Got %r."
            % (lhs_value,))

    return solve(expr.rhs, __nest_scope(expr.lhs, vars, lhs_value))


@solve.implementation(for_type=ast.Filter)
def solve_filter(expr, vars):
    """Filter values on the LHS by evaluating RHS with each value.

    Returns any LHS values for which RHS evaluates to a true value.
    """
    lhs_values = __solve_for_repeated(expr.lhs, vars)

    def lazy_filter():
        for lhs_value in repeated.getvalues(lhs_values):
            if solve(expr.rhs, __nest_scope(expr.lhs, vars, lhs_value)).value:
                yield lhs_value

    return Result(repeated.lazy(lazy_filter), ())


@solve.implementation(for_type=ast.Reducer)
def solve_reducer(expr, vars):
    def _mapper(rows):
        mapper = expr.mapper
        for row in rows:
            yield solve(mapper, __nest_scope(expr.lhs, vars, row)).value

    delegate = solve(expr.reducer, vars).value

    return Result(reducer.Map(delegate=delegate, mapper=_mapper), ())


@solve.implementation(for_type=ast.Group)
def solve_group(expr, vars):
    rows = __solve_for_repeated(expr.lhs, vars)
    reducers = [solve(child, vars).value for child in expr.reducers]
    r = reducer.Compose(*reducers)
    intermediates = {}

    # To avoid loading too much data into memory we segment the input rows.
    for chunk in reducer.generate_chunks(rows, reducer.DEFAULT_CHUNK_SIZE):
        # Group rows based on the output of the grouper expression.
        groups = {}
        for value in chunk:
            key = solve(expr.grouper, __nest_scope(expr.lhs, vars, value)).value
            grouped_values = groups.setdefault(key, [])
            grouped_values.append(value)

        # Fold each group in this chunk, merge with previous intermediate, if
        # any.
        for key, group in six.iteritems(groups):
            intermediate = reducer.fold(r, group)
            previous = intermediates.get(key)
            if previous:
                intermediate = reducer.merge(r, intermediate, previous)

            intermediates[key] = intermediate

    # This could equally well return a lazy repeated value to avoid finalizing
    # right away. The assumption here is that finalize is cheap, at least
    # compared to fold and merge, which already have to run eagerly. Using a
    # lazy value here would keep the intermediates around in memory, and just
    # doesn't seem worth it.
    results = [reducer.finalize(r, intermediate)
               for intermediate in six.itervalues(intermediates)]

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Sort)
def solve_sort(expr, vars):
    """Sort values on the LHS by the value they yield when passed to RHS."""
    lhs_values = repeated.getvalues(__solve_for_repeated(expr.lhs, vars))

    sort_expression = expr.rhs

    def _key_func(x):
        return solve(sort_expression, __nest_scope(expr.lhs, vars, x)).value

    results = ordered.ordered(lhs_values, key_func=_key_func)

    return Result(repeated.meld(*results), ())


@solve.implementation(for_type=ast.Each)
def solve_each(expr, vars):
    """Return True if RHS evaluates to a true value with each state of LHS.

    If LHS evaluates to a normal IAssociative object then this is the same as
    a regular let-form, except the return value is always a boolean. If LHS
    evaluates to a repeared var (see efilter.protocols.repeated) of
    IAssociative objects then RHS will be evaluated with each state and True
    will be returned only if each result is true.
    """
    lhs_values = __solve_for_repeated(expr.lhs, vars)

    for lhs_value in repeated.getvalues(lhs_values):
        result = solve(expr.rhs, __nest_scope(expr.lhs, vars, lhs_value))
        if not result.value:
            # Each is required to return an actual boolean.
            return result._replace(value=False)

    return Result(True, ())


@solve.implementation(for_type=ast.Any)
def solve_any(expr, vars):
    """Same as Each, except returning True on first true result at LHS."""
    lhs_values = __solve_for_repeated(expr.lhs, vars)

    try:
        rhs = expr.rhs
    except IndexError:
        # Child 1 is out of range. There is no condition on the RHS.
        # Just see if we have anything on the LHS.
        return Result(len(repeated.getvalues(lhs_values)) > 0, ())

    result = Result(False, ())
    for lhs_value in repeated.getvalues(lhs_values):
        result = solve(rhs, __nest_scope(expr.lhs, vars, lhs_value))
        if result.value:
            # Any is required to return an actual boolean.
            return result._replace(value=True)

    return result


@solve.implementation(for_type=ast.Cast)
def solve_cast(expr, vars):
    """Get cast LHS to RHS."""
    lhs = solve(expr.lhs, vars).value
    t = solve(expr.rhs, vars).value

    if t is None:
        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="Cannot find type named %r." % expr.rhs.value)

    if not isinstance(t, type):
        raise errors.EfilterTypeError(
            root=expr.rhs, query=expr.source,
            message="%r is not a type and cannot be used with 'cast'." % (t,))

    try:
        cast_value = t(lhs)
    except TypeError:
        raise errors.EfilterTypeError(
            root=expr, query=expr.source,
            message="Invalid cast %s -> %s." % (type(lhs), t))

    return Result(cast_value, ())


@solve.implementation(for_type=ast.IsInstance)
def solve_isinstance(expr, vars):
    """Typecheck whether LHS is type on the RHS."""
    lhs = solve(expr.lhs, vars)

    try:
        t = solve(expr.rhs, vars).value
    except errors.EfilterKeyError:
        t = None

    if t is None:
        raise errors.EfilterTypeError(
            root=expr.rhs, query=expr.source,
            message="Cannot find type named %r." % expr.rhs.value)

    if not isinstance(t, type):
        raise errors.EfilterTypeError(
            root=expr.rhs, query=expr.source,
            message="%r is not a type and cannot be used with 'isa'." % (t,))

    return Result(protocol.implements(lhs.value, t), ())


@solve.implementation(for_type=ast.Complement)
def solve_complement(expr, vars):
    result = solve(expr.value, vars)
    return result._replace(value=not result.value)


@solve.implementation(for_type=ast.Intersection)
def solve_intersection(expr, vars):
    result = Result(False, ())
    for child in expr.children:
        result = solve(child, vars)
        if not result.value:
            # Intersections don't preserve the last value the way Unions do.
            return result._replace(value=False)

    return result


@solve.implementation(for_type=ast.Union)
def solve_union(expr, vars):
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
def solve_pair(expr, vars):
    return Result((solve(expr.lhs, vars).value, solve(expr.rhs, vars).value),
                  ())


@solve.implementation(for_type=ast.Sum)
def solve_sum(expr, vars):
    total = 0

    for child in expr.children:
        val = __solve_for_scalar(child, vars)
        try:
            total += val
        except TypeError:
            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=type(val),
                                          root=child, query=expr.source)

    return Result(total, ())


@solve.implementation(for_type=ast.Difference)
def solve_difference(expr, vars):
    children = enumerate(expr.children)
    _, first_child = next(children)
    difference = __solve_for_scalar(first_child, vars)

    for idx, child in children:
        val = __solve_for_scalar(child, vars)
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
                                          root=expr.children[idx - 1],
                                          query=expr.source)

    return Result(difference, ())


@solve.implementation(for_type=ast.Product)
def solve_product(expr, vars):
    product = 1

    for child in expr.children:
        val = __solve_for_scalar(child, vars)
        try:
            product *= val
        except TypeError:
            raise errors.EfilterTypeError(expected=number.INumber,
                                          actual=type(val),
                                          root=child,
                                          query=expr.source)

    return Result(product, ())


@solve.implementation(for_type=ast.Quotient)
def solve_quotient(expr, vars):
    children = enumerate(expr.children)
    _, first_child = next(children)
    quotient = __solve_for_scalar(first_child, vars)

    for idx, child in children:
        val = __solve_for_scalar(child, vars)
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
                                          root=expr.children[idx - 1],
                                          query=expr.source)

    return Result(quotient, ())


@solve.implementation(for_type=ast.Equivalence)
def solve_equivalence(expr, vars):
    children = iter(expr.children)
    first_value = __solve_for_scalar(next(children), vars)
    for child in children:
        value = __solve_for_scalar(child, vars)
        if not value == first_value:
            return Result(False, ())

    return Result(True, ())


@solve.implementation(for_type=ast.Membership)
def solve_membership(expr, vars):
    needle = solve(expr.element, vars).value

    # There is an expectation that "foo" in "foobar" will be true, while at
    # the same time that "foo" in ["foobar", "fuzz"] will be false. The
    # expectation probably comes down to the fact that this is how the 'in'
    # operator behaves in other languages, such as Python. To meet the
    # expectation, we treat as special the case where the RHS is a literal
    # string value.
    if (isinstance(expr.set, ast.Literal)
            and isinstance(expr.set.value, six.string_types)):
        return Result(needle in expr.set.value, ())

    values = __solve_and_destructure_repeated(expr.set, vars)
    return Result(needle in values, ())


@solve.implementation(for_type=ast.RegexFilter)
def solve_regexfilter(expr, vars):
    string = __solve_for_scalar(expr.string, vars)
    pattern = __solve_for_scalar(expr.regex, vars)

    return Result(re.compile(pattern).match(str(string)), ())


@solve.implementation(for_type=ast.StrictOrderedSet)
def solve_strictorderedset(expr, vars):
    iterator = iter(expr.children)
    min_ = __solve_for_scalar(next(iterator), vars)

    if min_ is None:
        return Result(False, ())

    for child in iterator:
        val = __solve_for_scalar(child, vars)

        try:
            if not min_ > val or val is None:
                return Result(False, ())
        except TypeError:
            raise errors.EfilterTypeError(expected=type(min_),
                                          actual=type(val),
                                          root=child,
                                          query=expr.source,)

        min_ = val

    return Result(True, ())


@solve.implementation(for_type=ast.PartialOrderedSet)
def solve_partialorderedset(expr, vars):
    iterator = iter(expr.children)
    min_ = __solve_for_scalar(next(iterator), vars)

    if min_ is None:
        return Result(False, ())

    for child in iterator:
        val = __solve_for_scalar(child, vars)

        try:
            if min_ < val or val is None:
                return Result(False, ())
        except TypeError:
            raise errors.EfilterTypeError(expected=type(min_),
                                          actual=type(val),
                                          root=child,
                                          query=expr.source)

        min_ = val

    return Result(True, ())
