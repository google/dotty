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
EFILTER query type inference.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import ast
from efilter import dispatch
from efilter import errors
from efilter import protocol
from efilter import query as q
from efilter import scope as s

from efilter.stdlib import core as std_core

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import structured


@dispatch.multimethod
def infer_type(expr, scope=None):
    """Determine the return type of 'expr'.

    If 'expr' is evaluated with solve, what will be the type of the result?

    This employes two strategies to determine the types:
    1) Some expression types have a return signature that never changes. For
    example, intersection (AND) or unions (OR) always return a boolean.
    2) For types that are dependent on values (such as variables or user
    functions), IReflective.reflect is run on the 'scope' argument.

    Arguments:
        expr: The expression or query to infer return type of.
        scope (OPTIONAL): An instance of ScopeStack.

    Returns:
        A type, if known. On failure or in undecidable cases, returns AnyType.
    """
    _ = expr, scope
    raise NotImplementedError()


@infer_type.implementation(for_type=q.Query)
def infer_type(query, scope=None):
    # Always include stdcore at the top level.
    if scope:
        scope = s.ScopeStack(std_core.MODULE, scope)
    else:
        scope = s.ScopeStack(std_core.MODULE)

    try:
        return infer_type(query.root, scope)
    except errors.EfilterError as error:
        error.query = query.source
        raise


@infer_type.implementation(for_type=ast.Literal)
def infer_type(expr, scope):
    _ = scope
    return type(expr.value)


@infer_type.implementation(for_type=ast.Var)
def infer_type(expr, scope):
    if not isinstance(scope, s.ScopeStack):
        scope = s.ScopeStack(scope)

    return scope.reflect(expr.value) or protocol.AnyType


@infer_type.implementation(for_type=ast.Complement)
def infer_type(expr, scope):
    _ = expr, scope
    return bool


@infer_type.implementation(for_type=ast.IsInstance)
def infer_type(expr, scope):
    _ = expr, scope
    return bool


@infer_type.implementation(for_type=ast.BinaryExpression)
def infer_type(expr, scope):
    _ = scope
    return expr.return_signature


@infer_type.implementation(for_type=ast.Select)
def infer_type(expr, scope):
    """Try to infer the type of x[y] if y is a known value (literal)."""
    # Do we know what the key even is?
    if isinstance(expr.key, ast.Literal):
        key = expr.key.value
    else:
        return protocol.AnyType

    container_type = infer_type(expr.value, scope)

    try:
        # Associative types are not subject to scoping rules so we can just
        # reflect using IAssociative.
        return associative.reflect(container_type, key) or protocol.AnyType
    except NotImplementedError:
        return protocol.AnyType


@infer_type.implementation(for_type=ast.Resolve)
def infer_type(expr, scope):
    """Try to infer the type of x.y if y is a known value (literal)."""
    # Do we know what the member is?
    if isinstance(expr.member, ast.Literal):
        member = expr.member.value
    else:
        return protocol.AnyType

    container_type = infer_type(expr.obj, scope)

    try:
        # We are not using lexical scope here on purpose - we want to see what
        # the type of the member is only on the container_type.
        return structured.reflect(container_type, member) or protocol.AnyType
    except NotImplementedError:
        return protocol.AnyType


@infer_type.implementation(for_type=ast.VariadicExpression)
def infer_type(expr, scope):
    _ = scope
    return expr.return_signature


@infer_type.implementation(for_type=ast.Apply)
def infer_type(expr, scope):
    func_type = infer_type(expr.func, scope)

    try:
        return applicative.reflect_return(func_type) or protocol.AnyType
    except NotImplementedError:
        return protocol.AnyType


@infer_type.implementation(for_type=ast.Repeat)
def infer_type(expr, scope):
    """Check the type of the repeated value (all members have the same type.)"""
    return infer_type(expr.children[0], scope)


@infer_type.implementation(for_type=ast.Map)
def infer_type(expr, scope):
    t = infer_type(expr.context, scope)
    return infer_type(expr.expression, s.ScopeStack(scope, t))


@infer_type.implementation(for_type=ast.Filter)
def infer_type(expr, scope):
    return infer_type(expr.lhs, scope)


@infer_type.implementation(for_type=ast.Sort)
def infer_type(expr, scope):
    return infer_type(expr.lhs, scope)


@infer_type.implementation(for_type=ast.Any)
def infer_type(expr, scope):
    _ = expr, scope
    return bool


@infer_type.implementation(for_type=ast.Each)
def infer_type(expr, scope):
    _ = expr, scope
    return bool
