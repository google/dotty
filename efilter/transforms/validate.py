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


@dispatch.multimethod
def validate(expr, scope=None):
    """Validate sanity for expr."""
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


@validate.implementation(for_type=ast.VariadicExpression)
def validate(expr, scope):
    for subexpr in expr.children:
        validate(subexpr, scope)

    return True
