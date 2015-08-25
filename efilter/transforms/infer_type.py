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

from efilter import dispatch
from efilter import errors
from efilter import ast
from efilter import protocol
from efilter import query as q

from efilter.protocols import associative
from efilter.protocols import boolean
from efilter.protocols import name_delegate


@dispatch.polymorphic
def infer_type(expr, app_delegate, scope=None):
    """Determines the types of each subexpression and validates sanity."""
    _ = expr, app_delegate, scope
    raise NotImplementedError()


@infer_type.implementation(for_type=q.Query)
def infer_type(query, app_delegate, scope=None):
    try:
        return infer_type(query.root, app_delegate, scope)
    except errors.EfilterError as error:
        error.query = query.source
        raise


@infer_type.implementation(for_type=ast.Literal)
def infer_type(expr, app_delegate, scope):
    _ = app_delegate, scope
    return type(expr.value)


@infer_type.implementation(for_type=ast.Binding)
def infer_type(expr, app_delegate, scope):
    # If the app delegate implements INameDelegate then we can ask it for types.
    if protocol.implements(app_delegate, name_delegate.INameDelegate):
        result = name_delegate.reflect(app_delegate, expr.value, scope)

        if result:
            return result

    return protocol.AnyType


@infer_type.implementation(for_type=ast.Complement)
def infer_type(expr, app_delegate, scope):
    t = infer_type(expr.value, app_delegate, scope)
    if not protocol.isa(t, boolean.IBoolean):
        raise errors.EfilterTypeError(root=expr,
                                      actual=t,
                                      expected=boolean.IBoolean)

    return bool


@infer_type.implementation(for_type=ast.ComponentLiteral)
def infer_type(expr, app_delegate, scope):
    _ = expr, app_delegate, scope
    return bool


@infer_type.implementation(for_type=ast.IsInstance)
def infer_type(expr, app_delegate, scope):
    _ = expr, app_delegate, scope
    return bool


@infer_type.implementation(for_type=ast.BinaryExpression)
def infer_type(expr, app_delegate, scope):
    lhs_type = infer_type(expr.lhs, app_delegate, scope)
    if not protocol.isa(lhs_type, expr.type_signature[0]):
        raise errors.EfilterTypeError(root=expr.lhs,
                                      expected=expr.type_signature[0],
                                      actual=lhs_type)

    rhs_type = infer_type(expr.rhs, app_delegate, scope)
    if not protocol.isa(rhs_type, expr.type_signature[1]):
        raise errors.EfilterTypeError(root=expr.rhs,
                                      expected=expr.type_signature[1],
                                      actual=rhs_type)

    return expr.return_signature


@infer_type.implementation(for_type=ast.VariadicExpression)
def infer_type(expr, app_delegate, scope):
    for subexpr in expr.children:
        t = infer_type(subexpr, app_delegate, scope)
        if not protocol.isa(t, expr.type_signature):
            raise errors.EfilterTypeError(root=subexpr,
                                          expected=expr.type_signature,
                                          actual=t)

    return expr.return_signature


@infer_type.implementation(for_type=ast.Let)
def infer_type(expr, app_delegate, scope):
    t = infer_type(expr.context, app_delegate, scope)
    if not (t is protocol.AnyType
            or protocol.isa(t, associative.IAssociative)):
        raise errors.EfilterTypeError(root=expr,
                                      actual=t,
                                      expected=associative.IAssociative)

    return infer_type(expr.expression, app_delegate, t)


@infer_type.implementation(for_type=ast.LetAny)
def infer_type(expr, app_delegate, scope):
    t = infer_type(expr.context, app_delegate, scope)
    if not protocol.isa(t, boolean.IBoolean):
        raise errors.EfilterTypeError(root=expr,
                                      actual=t,
                                      expected=boolean.IBoolean)

    return bool


@infer_type.implementation(for_type=ast.LetEach)
def infer_type(expr, app_delegate, scope):
    t = infer_type(expr, app_delegate, scope)
    if not protocol.isa(t, boolean.IBoolean):
        raise errors.EfilterTypeError(root=expr,
                                      actual=t,
                                      expected=boolean.IBoolean)

    return bool
