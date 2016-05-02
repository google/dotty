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
This module implements the DottySQL grammar (on tokens, not on a query string).
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import ast
from efilter import errors

from efilter.parsers.common import ast_transforms as transforms
from efilter.parsers.common import grammar as common


# DottySQL's operator table. The parser only supports pure prefix and infix
# operators, as well as infix operators that have a suffix (like x[y]).
#
# Circumfix and pure suffix operators can be declared, but won't do anything.
OPERATORS = common.OperatorTable(

    # Infix operators:
    common.Operator(name="or", precedence=0, assoc="left",
                    handler=ast.Union, docstring="Logical OR.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "or")),
    common.Operator(name="and", precedence=1, assoc="left",
                    handler=ast.Intersection, docstring="Logical AND.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "and")),
    common.Operator(name="==", precedence=3, assoc="left",
                    handler=ast.Equivalence,
                    docstring="Equivalence (same as 'is').",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "==")),
    common.Operator(name="=~", precedence=3, assoc="left",
                    handler=ast.RegexFilter,
                    docstring="Left-hand operand where regex.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "=~")),
    common.Operator(name="!=", precedence=3, assoc="left",
                    handler=transforms.ComplementEquivalence,
                    docstring="Inequivalence (same as 'is not').",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "!=")),
    common.Operator(name="not in", precedence=3, assoc="left",
                    handler=transforms.ComplementMembership,
                    docstring="Left-hand operand is not in list.",
                    prefix=None, suffix=None,
                    infix=(common.Token("symbol", "not"),
                           common.Token("symbol", "in"))),
    common.Operator(name="in", precedence=3, assoc="left",
                    handler=ast.Membership,
                    docstring="Left-hand operand is in list.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "in")),
    common.Operator(name="isa", precedence=3, assoc="left",
                    handler=ast.IsInstance,
                    docstring="LHS must be instance of RHS.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", "isa")),
    common.Operator(name=">=", precedence=3, assoc="left",
                    handler=ast.PartialOrderedSet,
                    docstring="Equal-or-greater-than.", prefix=None,
                    suffix=None, infix=common.Token("symbol", ">=")),
    common.Operator(name="<=", precedence=3, assoc="left",
                    handler=transforms.ReversePartialOrderedSet,
                    docstring="Equal-or-less-than.", prefix=None,
                    suffix=None, infix=common.Token("symbol", "<=")),
    common.Operator(name=">", precedence=3, assoc="left",
                    handler=ast.StrictOrderedSet,
                    docstring="Greater-than.", prefix=None, suffix=None,
                    infix=common.Token("symbol", ">")),
    common.Operator(name="<", precedence=3, assoc="left",
                    handler=transforms.ReverseStrictOrderedSet,
                    docstring="Less-than.", prefix=None, suffix=None,
                    infix=common.Token("symbol", "<")),
    common.Operator(name="+", precedence=4, assoc="left", handler=ast.Sum,
                    docstring="Arithmetic addition.", prefix=None,
                    suffix=None, infix=common.Token("symbol", "+")),
    common.Operator(name="-", precedence=4, assoc="left",
                    handler=ast.Difference,
                    docstring="Arithmetic subtraction.", prefix=None,
                    suffix=None, infix=common.Token("symbol", "-")),
    common.Operator(name="*", precedence=6, assoc="left",
                    handler=ast.Product,
                    docstring="Arithmetic multiplication.", prefix=None,
                    suffix=None, infix=common.Token("symbol", "*")),
    common.Operator(name="/", precedence=6, assoc="left",
                    handler=ast.Quotient,
                    docstring="Arithmetic division.", prefix=None,
                    suffix=None, infix=common.Token("symbol", "/")),
    common.Operator(name=":", precedence=10, assoc="left",
                    handler=ast.Pair,
                    docstring="Key/value pair.", prefix=None,
                    suffix=None, infix=common.Token("symbol", ":")),
    common.Operator(name=".", precedence=12, assoc="left",
                    handler=ast.Resolve,
                    docstring="OBJ.MEMBER -> return MEMBER of OBJ.",
                    prefix=None, suffix=None,
                    infix=common.Token("symbol", ".")),

    # Mixfix:
    common.Operator(name="[]", precedence=12, assoc="left",
                    handler=ast.Select, docstring="Array subscript.",
                    prefix=None, infix=common.Token("lbracket", "["),
                    suffix=common.Token("rbracket", "]")),
    common.Operator(name="()", precedence=11, assoc="left",
                    handler=ast.Apply, docstring="Function application.",
                    prefix=None, infix=common.Token("lparen", "("),
                    suffix=common.Token("rparen", ")")),

    # Prefix:
    common.Operator(name="not", precedence=6, assoc="right",
                    handler=ast.Complement, docstring="Logical NOT.",
                    suffix=None, infix=None,
                    prefix=common.Token("symbol", "not")),
    common.Operator(name="unary -", precedence=5, assoc="right",
                    handler=transforms.NegateValue,
                    docstring="Unary -.", infix=None, suffix=None,
                    prefix=common.Token("symbol", "-")),
)


# These keywords are not allowed outside of the SELECT expression. They are not
# the full list of SQL keywords (for example LIMIT and OFFSET are not included),
# just ones that will be rejected by the parser unless they follow in proper
# order after SELECT.
SQL_RESERVED_KEYWORDS = frozenset([
    "SELECT", "FROM", "ANY", "WHERE", "DESC", "ASC", "ORDER BY",
])


# Builtin pseudo-functions which cannot be overriden.
BUILTINS = {
    "map": ast.Map,
    "sort": ast.Sort,
    "filter": ast.Filter,
    "bind": ast.Bind,
    "any": ast.Any,
    "each": ast.Each,
    "cast": ast.Cast
}


# Additional grammar used by the parser.

def bool_literal(tokens):
    match = common.keyword(tokens, "true")
    if match:
        return match._replace(value=True)

    match = common.keyword(tokens, "false")
    if match:
        return match._replace(value=False)


def literal(tokens):
    return bool_literal(tokens) or common.literal(tokens)


def prefix(tokens):
    return common.prefix(tokens, OPERATORS)


def infix(tokens):
    return common.infix(tokens, OPERATORS)


def param(tokens):
    return common.token_name(tokens, "param")


def builtin(tokens):
    """Matches a call to a builtin pseudo-function (like map or sort)."""
    return common.keywords(tokens, BUILTINS)


def let(tokens):
    """Matches a let expression."""
    return common.keyword(tokens, "let")


def let_assign(tokens):
    """Matches a '=' in the let expression."""
    return common.keyword(tokens, "=")


def application(tokens):
    """Matches function call (application)."""
    tokens = iter(tokens)
    func = next(tokens)
    paren = next(tokens)

    if func and func.name == "symbol" and paren.name == "lparen":
        # We would be able to unambiguously parse function application with
        # whitespace between the function name and the lparen, but let's not
        # do that because it's unexpected in most languages.
        if func.end != paren.start:
            raise errors.EfilterParseError(
                start=func.start, end=paren.end,
                message="No whitespace allowed between function and paren.")

        return common.TokenMatch(None, func.value, (func, paren))


def if_if(tokens):
    """Matches an if-else block."""
    return common.keyword(tokens, "if")


def if_then(tokens):
    return common.keyword(tokens, "then")


def if_else_if(tokens):
    return common.multi_keyword(tokens, ("else", "if"))


def if_else(tokens):
    return common.keyword(tokens, "else")


# SQL subgrammar:

def select(tokens):
    return common.keyword(tokens, "select")


def select_any(tokens):
    return common.keyword(tokens, "any")


def select_all(tokens):
    return common.keyword(tokens, "*")


def select_as(tokens):
    return common.keyword(tokens, "as")


def select_from(tokens):
    return common.keyword(tokens, "from")


def select_where(tokens):
    return common.keyword(tokens, "where")


def select_limit(tokens):
    return common.keyword(tokens, "limit")


def select_offset(tokens):
    return common.keyword(tokens, "offset")


def select_order(tokens):
    return common.multi_keyword(tokens, ("order", "by"))


def select_asc(tokens):
    return common.keyword(tokens, "asc")


def select_desc(tokens):
    return common.keyword(tokens, "desc")


def sql_keyword(tokens):
    return (common.keywords(tokens, SQL_RESERVED_KEYWORDS)
            or common.multi_keyword(tokens, ("order", "by")))
