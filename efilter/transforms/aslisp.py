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
EFILTER lisp syntax output.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import six

from efilter import dispatch
from efilter import ast
from efilter import syntax
from efilter import query as q

from efilter.parsers import lisp


EXPRESSIONS = dict((v, k) for k, v in six.iteritems(lisp.EXPRESSIONS))


@dispatch.multimethod
def aslisp(expr):
    """Produces equivalent lisp output to the AST."""
    _ = expr
    raise NotImplementedError()


syntax.Syntax.register_formatter(shorthand="lisp", formatter=aslisp)


@aslisp.implementation(for_type=ast.Expression)
def aslisp(expr):
    expr_name = EXPRESSIONS[type(expr)]
    return tuple([expr_name] + [aslisp(child) for child in expr.children])


@aslisp.implementation(for_type=ast.Literal)
def aslisp(expr):
    return expr.value


@aslisp.implementation(for_type=ast.Var)
def aslisp(expr):
    return ("var", expr.value)


@aslisp.implementation(for_type=q.Query)
def aslisp(query):
    return aslisp(query.root)
