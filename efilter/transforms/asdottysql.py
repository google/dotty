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
EFILTER DottySQL syntax output.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import dispatch
from efilter import ast
from efilter import syntax
from efilter import query as q

from efilter.parsers.experiments.dottysql import grammar


def __build_operator_lookup(table):
    lookup = {}
    for operator in table.itervalues():
        if not (isinstance(operator.handler, type) and
                issubclass(operator.handler, ast.Expression)):
            continue

        lookup[operator.handler] = operator

    return lookup


@dispatch.memoize
def infix():
    return __build_operator_lookup(grammar.INFIX)


@dispatch.memoize
def prefix():
    return __build_operator_lookup(grammar.PREFIX)


@dispatch.memoize
def mixfix():
    return __build_operator_lookup(grammar.MIXFIX)


@dispatch.memoize
def operators():
    result = {}
    result.update(infix())
    result.update(prefix())
    result.update(mixfix())

    return result


BUILTINS = dict((v, k) for k, v in grammar.BUILTINS.iteritems())


def __expression_precedence(expr):
    operator = operators().get(type(expr))
    if operator:
        return operator.precedence, operator.assoc

    return None, None


@dispatch.multimethod
def asdottysql(expr):
    """Produces equivalent DottySQL output to the AST.

    This class follows the visitor pattern. See documentation on VisitorEngine.
    """
    _ = expr
    raise NotImplementedError()


@asdottysql.implementation(for_type=q.Query)
def asdottysql(query):
    return asdottysql(query.root)


@asdottysql.implementation(for_type=ast.Within)
def asdottysql(expr):
    if not type(expr) in BUILTINS:
        return "<Subexpression cannot be formatted as DottySQL.>"

    body = ", ".join([asdottysql(x) for x in expr.children])
    return "%s(%s)" % (BUILTINS[type(expr)], body)


@asdottysql.implementation(for_type=ast.Map)
def asdottysql(expr):
    lhs = asdottysql(expr.lhs)
    rhs = asdottysql(expr.rhs)

    if (isinstance(expr.lhs, (ast.Map, ast.Var))
            and isinstance(expr.rhs, (ast.Map, ast.Var))):
        return "%s.%s" % (lhs, rhs)

    return "map(%s, %s)" % (lhs, rhs)


@asdottysql.implementation(for_types=(ast.NumericExpression, ast.Relation,
                                      ast.LogicalOperation))
def asdottysql(expr):
    operator = infix()[type(expr)]
    children = []

    for child in expr.children:
        precedence, _ = __expression_precedence(child)

        if precedence is not None and precedence < operator.precedence:
            children.append("(%s)" % asdottysql(child))
        else:
            children.append(asdottysql(child))

    separator = " %s " % operator.name
    return separator.join(children)


def _format_binary(lhs, rhs, operator, lspace=" ", rspace=" "):
    left = asdottysql(lhs)
    right = asdottysql(rhs)

    lhs_precedence, lassoc = __expression_precedence(lhs)
    if lassoc == "left" and lhs_precedence is not None:
        lhs_precedence += 1

    if lhs_precedence is not None and lhs_precedence < operator.precedence:
        left = "(%s)" % left

    rhs_precedence, rassoc = __expression_precedence(rhs)
    if rassoc == "right" and rhs_precedence is not None:
        rhs_precedence += 1

    if rhs_precedence is not None and rhs_precedence < operator.precedence:
        right = "(%s)" % right

    return "".join((left, lspace, operator.name, rspace, right))


@asdottysql.implementation(for_type=ast.Complement)
def asdottysql(expr):
    if (isinstance(expr.value, ast.Equivalence)
            and len(expr.value.children) == 2):
        return _format_binary(expr.value.children[0],
                              expr.value.children[1],
                              grammar.INFIX["!="])

    if isinstance(expr.value, ast.Membership):
        return _format_binary(expr.value.children[0],
                              expr.value.children[1],
                              grammar.INFIX["not in"])

    child_precedence, assoc = __expression_precedence(expr.value)

    if assoc == "left" and child_precedence:
        child_precedence += 1

    if (child_precedence is not None
            and child_precedence < __expression_precedence(expr)):
        return "not (%s)" % asdottysql(expr.value)

    return "not %s" % asdottysql(expr.value)


@asdottysql.implementation(for_type=ast.Bind)
def asdottysql(expr):
    return "bind(%s)" % ", ".join(asdottysql(x) for x in expr.children)


@asdottysql.implementation(for_type=ast.Pair)
def asdottysql(expr):
    return _format_binary(expr.lhs, expr.rhs, grammar.INFIX[":"], lspace="")


@asdottysql.implementation(for_types=(ast.IsInstance, ast.RegexFilter,
                                      ast.Membership))
def asdottysql(expr):
    return _format_binary(expr.lhs, expr.rhs, infix()[type(expr)])


@asdottysql.implementation(for_type=ast.Apply)
def asdottysql(expr):
    arguments = iter(expr.children)
    func = next(arguments)

    return "%s(%s)" % (asdottysql(func),
                       ", ".join([asdottysql(arg) for arg in arguments]))


@asdottysql.implementation(for_type=ast.Select)
def asdottysql(expr):
    arguments = iter(expr.children)
    source = asdottysql(next(arguments))

    if not isinstance(expr.lhs, (ast.ValueExpression, ast.Repeat, ast.Tuple,
                                 ast.Map, ast.Select, ast.Apply, ast.Bind)):
        source = "(%s)" % source

    return "%s[%s]" % (source,
                       ", ".join([asdottysql(arg) for arg in arguments]))


@asdottysql.implementation(for_type=ast.Resolve)
def asdottysql(expr):
    if not isinstance(expr.rhs, ast.Literal):
        return "<expression cannot be formatted as DottySQL>"

    return _format_binary(expr.lhs, ast.Var(expr.rhs.value),
                          infix()[ast.Resolve], lspace="", rspace="")


@asdottysql.implementation(for_type=ast.Repeat)
def asdottysql(expr):
    return "(%s)" % ", ".join(asdottysql(x) for x in expr.children)


@asdottysql.implementation(for_type=ast.Tuple)
def asdottysql(expr):
    return "[%s]" % ", ".join(asdottysql(x) for x in expr.children)


@asdottysql.implementation(for_type=ast.IfElse)
def asdottysql(expr):
    branches = ["if %s then %s" % (asdottysql(c), asdottysql(v))
                for c, v in expr.conditions()]

    if_ = " else ".join(branches)

    else_ = expr.default()
    if not else_ or else_ == ast.Literal(None):
        return if_

    return "%s else %s" % (if_, asdottysql(else_))


@asdottysql.implementation(for_type=ast.Literal)
def asdottysql(expr):
    return repr(expr.value)


@asdottysql.implementation(for_type=ast.Var)
def asdottysql(expr):
    return expr.value


syntax.Syntax.register_formatter(shorthand="dottysql", formatter=asdottysql)
