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
EFILTER dotty syntax output.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import dispatch
from efilter import ast
from efilter import syntax
from efilter import query as q

from efilter.parsers import dotty


def __build_operator_lookup(*tables):
    lookup = {}
    for table in tables:
        for token, operator in table.iteritems():
            if not (isinstance(operator.handler, type) and
                    issubclass(operator.handler, ast.Expression)):
                continue

            lookup[operator.handler] = token

    return lookup


TOKENS = __build_operator_lookup(dotty.INFIX, dotty.PREFIX)


@dispatch.multimethod
def asdotty(expr):
    """Produces equivalent Dotty output to the AST.

    This class follows the visitor pattern. See documentation on VisitorEngine.
    """
    _ = expr
    raise NotImplementedError()


syntax.Syntax.register_formatter(shorthand="dotty", formatter=asdotty)


@asdotty.implementation(for_type=ast.Expression)
def asdotty(query):
    _ = query
    return "<subexpression cannot be formatted as dotty>"


@asdotty.implementation(for_type=q.Query)
def asdotty(query):
    return asdotty(query.root)


@asdotty.implementation(for_type=ast.Within)
def asdotty(expr):
    lhs = expr.lhs
    rhs = expr.rhs
    left = asdotty(lhs)
    right = asdotty(rhs)
    token = "."

    if not isinstance(expr.lhs, (ast.ValueExpression,
                                 ast.Within)):
        left = "(%s)" % left
        token = " where "

    if not isinstance(expr.rhs, (ast.ValueExpression,
                                 ast.Within)):
        right = "(%s)" % right
        token = " where "

    return token.join((left, right))


@asdotty.implementation(for_type=ast.Any)
def asdotty(expr):
    return "any %s" % asdotty(ast.Within(expr.lhs, expr.rhs))


@asdotty.implementation(for_type=ast.Each)
def asdotty(expr):
    return "each %s" % asdotty(ast.Within(expr.lhs, expr.rhs))


@asdotty.implementation(for_type=ast.Literal)
def asdotty(expr):
    return repr(expr.value)


@asdotty.implementation(for_type=ast.Var)
def asdotty(expr):
    return expr.value


@asdotty.implementation(for_type=ast.Complement)
def asdotty(expr):
    child = expr.value
    if (isinstance(child, ast.Equivalence) and
            len(child.children) == 2):
        return "%s != %s" % (asdotty(child.children[0]),
                             asdotty(child.children[1]))

    if isinstance(child, (ast.Within, ast.Var,
                          ast.Literal)):
        return "not %s" % asdotty(child)

    # Put parens around everything else to be safe.
    return "not (%s)" % asdotty(child)


@asdotty.implementation(for_type=ast.BinaryExpression)
def asdotty(expr):
    try:
        token = TOKENS[type(expr)]
        separator = " %s " % token
        return "%s%s%s" % (asdotty(expr.lhs), separator, asdotty(expr.rhs))
    except KeyError:
        return "<subexpression cannot be formatted as dotty>"


@asdotty.implementation(for_type=ast.VariadicExpression)
def asdotty(expr):
    try:
        token = TOKENS[type(expr)]
        separator = " %s " % token
        return separator.join(asdotty(x) for x in expr.children)
    except KeyError:
        return "<subexpression cannot be formatted as dotty>"
