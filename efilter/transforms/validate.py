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

from efilter.protocols import boolean

from efilter.transforms import infer_type


@dispatch.multimethod
def validate(expr, scope=None):
    """Use infer_type to get actual types for 'expr' and validate sanity."""
    _ = expr, scope
    raise NotImplementedError()


@validate.implementation(for_type=q.Query)
def validate(query, scope=None):
    try:
        return validate(query.root, scope)
    except errors.EfilterError as error:
        error.query = query.source
        raise


@validate.implementation(for_type=ast.ValueExpression)
def validate(expr, scope):
    _ = expr, scope
    return True


@validate.implementation(for_type=ast.IfElse)
def validate(expr, scope):
    # Make sure there's an ELSE block.
    if expr.default() is None:
        raise errors.EfilterLogicError(
            root=expr,
            message="Else blocks are required in EFILTER.")

    # Make sure conditions evaluate to IBoolean.
    for condition, _ in expr.conditions():
        t = infer_type.infer_type(condition, scope)
        if not protocol.isa(t, boolean.IBoolean):
            raise errors.EfilterTypeError(root=expr, actual=t,
                                          expected=boolean.IBoolean)


@validate.implementation(for_type=ast.Complement)
def validate(expr, scope):
    t = infer_type.infer_type(expr.value, scope)
    if not protocol.isa(t, boolean.IBoolean):
        raise errors.EfilterTypeError(root=expr,
                                      actual=t,
                                      expected=boolean.IBoolean)

    return True


@validate.implementation(for_type=ast.BinaryExpression)
def validate(expr, scope):
    lhs_type = infer_type.infer_type(expr.lhs, scope)
    if not (lhs_type is protocol.AnyType
            or protocol.isa(lhs_type, expr.type_signature[0])):
        raise errors.EfilterTypeError(root=expr.lhs,
                                      expected=expr.type_signature[0],
                                      actual=lhs_type)

    rhs_type = infer_type.infer_type(expr.rhs, scope)
    if not (lhs_type is protocol.AnyType
            or protocol.isa(rhs_type, expr.type_signature[1])):
        raise errors.EfilterTypeError(root=expr.rhs,
                                      expected=expr.type_signature[1],
                                      actual=rhs_type)

    return True


@validate.implementation(for_type=ast.VariadicExpression)
def validate(expr, scope):
    for subexpr in expr.children:
        validate(subexpr, scope)

        t = infer_type.infer_type(subexpr, scope)
        if not (t is protocol.AnyType
                or protocol.isa(t, expr.type_signature)):
            raise errors.EfilterTypeError(root=subexpr,
                                          expected=expr.type_signature,
                                          actual=t)

    return True
