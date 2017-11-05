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

from builtins import next
from builtins import zip
__author__ = "Adam Sindelar <adamsh@google.com>"

# pylint: disable=function-redefined

import collections
import functools
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
from efilter.protocols import eq
from efilter.protocols import number
from efilter.protocols import ordered
from efilter.protocols import reducer
from efilter.protocols import repeated
from efilter.protocols import string
from efilter.protocols import structured

from efilter.stdlib import core as std_core

Result = collections.namedtuple("Result", ["value", "branch"])

if six.PY3:
    unicode = str


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

            value: The result of evaluation.

            branch: An instance of Expression, representing a subtree of 'query'
                that was that last branch evaluated before a match was produced.
                This only applies to simple queries using AND/OR and NOT
                operators, which evaluate to booleans and can terminate early.
                For other queries this will be set to None.
    """
    _ = query, vars
    raise NotImplementedError()


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
    data = solve(expr.lhs, vars).value
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
    objs = solve(expr.lhs, vars).value
    member = solve(expr.rhs, vars).value
    results = []

    if repeated.isrepeating(objs):
        for o in repeated.getvalues(objs):
            results.append(structured.resolve(o, member))

        return Result(results, ())

    return Result(structured.resolve(objs, member), ())


def parse_apply_args(args_ast, scope_):
    args = []
    kwargs = {}
    for arg in args_ast:
        if isinstance(arg, ast.Pair):
            if not isinstance(arg.lhs, ast.Var):
                raise errors.EfilterError(
                    root=arg.lhs,
                    message="Invalid argument name.")

            kwargs[arg.key.value] = solve(arg.value, scope_).value
        else:
            args.append(solve(arg, scope_).value)

    return args, kwargs


@solve.implementation(for_type=ast.Apply)
def solve_apply(expr, vars):
    """Returns the result of applying function (lhs) to its arguments (rest).

    We use IApplicative to apply the function, because that gives the host
    application an opportunity to compare the function being called against
    a whitelist. EFILTER will never directly call a function that wasn't
    provided through a protocol implementation.
    """
    func = solve(expr.func, vars).value
    args, kwargs = parse_apply_args(expr.args, vars)
    result = applicative.apply(func, args, kwargs)

    return Result(result, ())


@solve.implementation(for_type=ast.Bind)
def solve_bind(expr, vars):
    """Build a RowTuple from key/value pairs under the bind.

    The Bind subtree is arranged as follows:

    Bind
    | First KV Pair
    | | First Key Expression
    | | First Value Expression
    | Second KV Pair
    | | Second Key Expression
    | | Second Value Expression
    Etc...
    """
    local_scope = vars
    values = []
    keys = []
    for pair in expr.children:
        key = solve(pair.key, local_scope).value
        keys.append(key)
        value = solve(pair.value, local_scope).value
        values.append(value)
        local_scope = scope.ScopeStack(local_scope, {key: value})

    result = {}
    for k, v in zip(keys, values):
        result[k] = v

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
    lhs_values = solve(expr.lhs, vars).value

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
    lhs_values = solve(expr.lhs, vars).value

    def lazy_filter():
        for lhs_value in repeated.getvalues(lhs_values):
            filter_result = solve(expr.rhs, __nest_scope(
                expr.lhs, vars, lhs_value)).value
            # Repeating values are chosen if any of the values returns
            # true.
            if repeated.isrepeating(filter_result):
                if any(filter_result):
                    yield lhs_value

            else:
                # Todo: Implement a bool protocol - for now we use the
                # python bool.  Scalar values must evaluate to true.
                if bool(filter_result):
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
    rows = solve(expr.lhs, vars).value
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


def _cmp(x, y):
    if eq.eq(x, y) or eq.eq(y, x):
        return 0

    if _lt(x, y):
        return -1

    return 1


@solve.implementation(for_type=ast.Sort)
def solve_sort(expr, vars):
    """Sort values on the LHS by the value they yield when passed to RHS."""
    lhs_values = repeated.getvalues(solve(expr.lhs, vars)[0])
    sort_expression = expr.rhs

    def _key_func(x):
        return solve(sort_expression, __nest_scope(expr.lhs, vars, x)).value

    # In order to sort we must expand the list into memory and apply
    # the sort expression to each element. We then use the ordered and
    # eq protocols to compare any two items until the list is sorted.
    sorted_list = [(x, _key_func(x)) for x in lhs_values]
    key_func = functools.cmp_to_key(_cmp)
    sorted_list.sort(key=lambda x: key_func(x[1]))

    return Result([x[0] for x in sorted_list], ())


@solve.implementation(for_type=ast.Each)
def solve_each(expr, vars):
    """Return True if RHS evaluates to a true value with each state of LHS.

    If LHS evaluates to a normal IAssociative object then this is the same as
    a regular let-form, except the return value is always a boolean. If LHS
    evaluates to a repeared var (see efilter.protocols.repeated) of
    IAssociative objects then RHS will be evaluated with each state and True
    will be returned only if each result is true.
    """
    lhs_values = solve(expr.lhs, vars).value

    for lhs_value in repeated.getvalues(lhs_values):
        result = solve(expr.rhs, __nest_scope(expr.lhs, vars, lhs_value))
        if not result.value:
            # Each is required to return an actual boolean.
            return result._replace(value=False)

    return Result(True, ())


@solve.implementation(for_type=ast.Any)
def solve_any(expr, vars):
    """Same as Each, except returning True on first true result at LHS."""
    lhs_values = solve(expr.lhs, vars).value

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


@solve.implementation(for_type=ast.Complement)
def solve_complement(expr, vars):
    result = solve(expr.value, vars)
    return result._replace(value=not result.value)


@solve.implementation(for_type=ast.Intersection)
def solve_intersection(expr, vars):
    for child in expr.children:
        result = solve(child, vars).value
        if repeated.isrepeating(result) and not any(result):
            return Result(False, ())
        elif not result:
            return Result(False, ())

    return Result(True, ())


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
    """Handle numerical operators.

    We can mix scalars and repeated elements freely. The result is
    always repeated. Scalars are turned into repeated lists of the
    scalar while repeated values are turned into lists padded with the
    pad element to the longest list we operate on.

    Examples:
       # Scalars are expanded to repeat themselves.
       [1, 2] + 4 -> [1, 2] + [4, 4] -> [5, 6]

       # Lists are padded
       [1, 2] + [1, 2, 3] -> [1, 2, 0] + [1, 2, 3] -> [2, 4, 3]

       # Subselects are expanded if they contain a single column.
       select hex(offset), hexdump from dump(
           offset: (-0x20 + (
               select _EPROCESS.obj_offset from pslist(proc_regex: "svchost"))),
           rows: 5 )
    """
    iterators = convert_to_iterators(expr, vars, pad=0)

    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        total = 0
        for element in elements:
            if number.isnumber(element):
                total = number.sum(element, total)

            # If we encounter a non-number we swallow the error and
            # return None. This could happen for example if one of the
            # columns in the select returns NoneObject() or something
            # which is not a number.
            else:
                total = None
                break

        result.append(total)

    return Result(result, ())


def convert_to_list(expr, repeated_list):
    if not repeated.isrepeating(repeated_list):
        return [repeated_list]

    result = []
    for element in repeated_list:
        if element is not None:
            # The output from a select is a repeated structured
            # (dict). If it has a single member we just use that,
            # otherwise we raise because the query is probably bad
            # (it should only return a single column).
            if structured.isstructured(element):
                members = structured.getmembers(element)
                if len(members) != 1:
                    raise errors.EfilterTypeError(
                        message="Expecting a single column in subselect - "
                        "got %s columns" % len(members),
                        query=expr.source)

                element = structured.resolve(element, members[0])
            result.append(element)

    return result


def convert_to_iterators(expr, vars, pad=0):
    """Solve all children in expr and return a list of iterators.

    Each iterator is expanded or repeated so they are all the same
    length.
    """
    max_length = 0
    iterators = []
    # Expand each child into a list.
    for child in expr.children:
        val = solve(child, vars).value
        if repeated.isrepeating(val) and not number.isnumber(val):
            val = convert_to_list(expr, val)
            if len(val) > max_length:
                max_length = len(val)

        # This is a scalar - at least of length 1.
        else:
            max_length = max(max_length, 1)

        iterators.append(val)

    # Pad all iterator lists to be the same length.
    for i, item in enumerate(iterators):
        # Repeat scalar values.
        if not isinstance(item, list):
            iterators[i] = [item] * max_length

        # Extend short lists to the required length
        elif len(item) < max_length:
            item.extend([pad] * (max_length - len(item)))

    return iterators


@solve.implementation(for_type=ast.Difference)
def solve_difference(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)

    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        total = None
        for element in elements:
            if number.isnumber(element):
                if total is None:
                    total = element
                else:
                    total = -number.difference(element, total)

            # If we encounter a non-number we swallow the error and
            # return None. This could happen for example if one of the
            # columns in the select returns NoneObject() or something
            # which is not a number.
            else:
                total = None
                break

        result.append(total)

    return Result(result, ())


@solve.implementation(for_type=ast.Product)
def solve_product(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)

    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        total = None
        for element in elements:
            if number.isnumber(element):
                if total is None:
                    total = element
                else:
                    total = number.product(element, total)

            # If we encounter a non-number we swallow the error and
            # return None. This could happen for example if one of the
            # columns in the select returns NoneObject() or something
            # which is not a number.
            else:
                total = None
                break

        result.append(total)

    return Result(result, ())


@solve.implementation(for_type=ast.Quotient)
def solve_quotient(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)

    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        total = None
        for element in elements:
            if number.isnumber(element):
                if total is None:
                    total = element
                else:
                    # Division by 0.
                    if eq.eq(element, 0):
                        total = None
                        break

                    total = number.quotient(total, element)

            # If we encounter a non-number we swallow the error and
            # return None. This could happen for example if one of the
            # columns in the select returns NoneObject() or something
            # which is not a number.
            else:
                total = None
                break

        result.append(total)

    return Result(result, ())


@solve.implementation(for_type=ast.Equivalence)
def solve_equivalence(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)

    # Add each element individually.
    for elements in zip(*iterators):
        elements = iter(elements)
        try:
            first = next(elements)
        except StopIteration:
            return Result(True, ())

        if not all(eq.eq(first, rest) for rest in elements):
            return Result(False, ())

    return Result(True, ())


@solve.implementation(for_type=ast.Membership)
def solve_membership(expr, vars):
    needle = solve(expr.element, vars).value
    haystack = convert_to_list(expr.set, solve(expr.set, vars).value)

    for haystack_item in haystack:
        # Using in as a substring (This is not so useful, Should
        # we just make users use a regex?)
        if string.isstring(haystack_item):
            if unicode(needle) in string.string(haystack_item):
                return Result(True, ())

        elif haystack_item == needle:
            return Result(True, ())

    return Result(False, ())


@solve.implementation(for_type=ast.RegexFilter)
def solve_regexfilter(expr, vars):
    """A Regex filter which can operate on both strings and repeated.

    If any item in the array matches, we return the entire row.
    """
    pattern = re.compile(solve(expr.regex, vars).value, re.I)
    string_ = solve(expr.string, vars).value
    if repeated.isrepeating(string_):
        for item in string_:
            match = pattern.search(six.text_type(str(item)))
            if match:
                return Result(match, ())

    else:
        match = pattern.search(six.text_type(str(string_)))
        if match:
            return Result(match, ())

    return Result(False, ())


def _lt(x, y):
    if ordered.isordered(x):
        return ordered.lt(x, y)
    elif ordered.isordered(y):
        return not ordered.lt(y, x)

    # Non orderable filter should return False.
    return False


def _is_monotonic(elements, inc=True, strict=False):
    """Is the sequence in elements monotonically increasing?

    Args: inc: Direction of monotonicity (increasing or decreasing).
          strict: If true elements may not repeat.
    """
    last = None
    for i, element in enumerate(elements):
        if i == 0:
            last = element
            continue

        # Strict monotonic means this element can not be equal to
        # the last one.
        if eq.eq(element, last):
            if strict:
                return False
            continue

        if inc and _lt(element, last):
            return False

        if not inc and _lt(last, element):
            return False

    return True


@solve.implementation(for_type=ast.StrictOrderedSet)
def solve_strictorderedset(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)
    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        result.append(_is_monotonic(elements, strict=True))

    return Result(result, ())


@solve.implementation(for_type=ast.PartialOrderedSet)
def solve_partialorderedset(expr, vars):
    iterators = convert_to_iterators(expr, vars, pad=0)
    # Add each element individually.
    result = []
    for elements in zip(*iterators):
        result.append(_is_monotonic(elements, strict=False))

    return Result(result, ())
