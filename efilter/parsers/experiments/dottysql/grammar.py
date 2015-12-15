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

import collections

from efilter import ast
from efilter import errors

from efilter.parsers.experiments.dottysql import ast_transforms as transforms


class Operator(collections.namedtuple(
        "Operator", "name precedence assoc handler docstring postfix")):
    """Defines an operator in the DottySQL expression syntax.

    Arguments:
        precedence: Integer precedence with operators of the same arity.
        handler: Callable that emits AST for this operator.
        docstring: Documentation for the operator.
        assoc: Associativity - can be left or right for infix operators.
        postfix: The grammar function for the postfix part of this operator.
    """


# Grammar primitives, which need to be defined before operators.

class TokenMatch(collections.namedtuple(
        "TokenMatch", "operator value tokens")):
    """Represents a match.

    Arguments:
        operator: The Operator instance that matched, if any.
        value: The literal value that matched, if any.
        tokens: The actual tokens the match consumed.
    """


def _keyword(tokens, keyword):
    """Case-insensitive keyword match."""
    token = next(iter(tokens))
    if token and token.name == "symbol" and token.value.lower() == keyword:
        return TokenMatch(None, token.value, (token,))


def _multi_keyword(tokens, keyword_parts):
    """Match a case-insensitive keyword consisting of multiple tokens."""
    tokens = iter(tokens)
    matched_tokens = []
    limit = len(keyword_parts)

    for idx in xrange(limit):
        try:
            token = next(tokens)
        except StopIteration:
            return

        if (not token or token.name != "symbol" or
                token.value.lower() != keyword_parts[idx]):
            return

        matched_tokens.append(token)

    return TokenMatch(None, token.value, matched_tokens)


def _keywords(tokens, keywords):
    """Match against any of a set/dict of keywords.

    Not that this doesn't support multi-part keywords. Any multi-part keywords
    must be special-cased in their grammar function (look at infix for an
    example using _multi_keyword).
    """
    token = next(iter(tokens))
    if token and token.name == "symbol" and token.value.lower() in keywords:
        return TokenMatch(None, token.value, (token,))


def _operator(tokens, operators):
    """Case-insensitive operator match."""
    match = _keywords(tokens, operators)
    if match:
        operator_name = [token.value for token in match.tokens]
        if len(operator_name) == 1:
            operator_name = operator_name[0]

        operator = operators[operator_name.lower()]
        return match._replace(operator=operator)


def _name(tokens, name):
    """Match a token name (type)."""
    token = next(iter(tokens))
    if token and token.name == name:
        return TokenMatch(None, token.value, (token,))


def lparen(tokens):
    return _name(tokens, "lparen")


def rparen(tokens):
    return _name(tokens, "rparen")


def lbracket(tokens):
    return _name(tokens, "lbracket")


def rbracket(tokens):
    return _name(tokens, "rbracket")


def comma(tokens):
    return _name(tokens, "comma")


# Operators.

INFIX = collections.OrderedDict([
    ("or", Operator(name="or", precedence=0, assoc="left", handler=ast.Union,
                    docstring="Logical OR.", postfix=None)),
    ("and", Operator(name="and", precedence=1, assoc="left",
                     handler=ast.Intersection,
                     docstring="Logical AND.", postfix=None)),
    ("==", Operator(name="==", precedence=3, assoc="left",
                    handler=ast.Equivalence,
                    docstring="Equivalence (same as 'is').", postfix=None)),
    ("=~", Operator(name="=~", precedence=3, assoc="left",
                    handler=ast.RegexFilter,
                    docstring="Left-hand operand where regex.",
                    postfix=None)),
    ("!=", Operator(name="!=", precedence=3, assoc="left",
                    handler=transforms.ComplementEquivalence,
                    docstring="Inequivalence (same as 'is not').",
                    postfix=None)),
    ("not in", Operator(name="not in", precedence=3, assoc="left",
                        handler=transforms.ComplementMembership,
                        docstring="Left-hand operand is not in list.",
                        postfix=None)),
    ("in", Operator(name="in", precedence=3, assoc="left",
                    handler=ast.Membership,
                    docstring="Left-hand operand is in list.", postfix=None)),
    ("isa", Operator(name="isa", precedence=3, assoc="left",
                     handler=ast.IsInstance,
                     docstring="Matching object must be instance of type.",
                     postfix=None)),
    (">=", Operator(name=">=", precedence=3, assoc="left",
                    handler=ast.PartialOrderedSet,
                    docstring="Equal-or-greater-than.", postfix=None)),
    ("<=", Operator(name="<=", precedence=3, assoc="left",
                    handler=transforms.ReversePartialOrderedSet,
                    docstring="Equal-or-less-than.", postfix=None)),
    (">", Operator(name=">", precedence=3, assoc="left",
                   handler=ast.StrictOrderedSet,
                   docstring="Greater-than.", postfix=None)),
    ("<", Operator(name="<", precedence=3, assoc="left",
                   handler=transforms.ReverseStrictOrderedSet,
                   docstring="Less-than.", postfix=None)),
    ("+", Operator(name="+", precedence=4, assoc="left", handler=ast.Sum,
                   docstring="Arithmetic addition.", postfix=None)),
    ("-", Operator(name="-", precedence=4, assoc="left", handler=ast.Difference,
                   docstring="Arithmetic subtraction.", postfix=None)),
    ("*", Operator(name="*", precedence=6, assoc="left", handler=ast.Product,
                   docstring="Arithmetic multiplication.", postfix=None)),
    ("/", Operator(name="/", precedence=6, assoc="left", handler=ast.Quotient,
                   docstring="Arithmetic division.", postfix=None)),
    (":", Operator(name=":", precedence=10, assoc="left", handler=ast.Pair,
                   docstring="Key/value pair.", postfix=None)),
    (".", Operator(name=".", precedence=12, assoc="left",
                   handler=ast.Resolve,
                   docstring="OBJ.MEMBER -> return MEMBER of OBJ.",
                   postfix=None)),
])


# Mixfix operators work just like infix, but they have a part that comes after
# the RHS.
MIXFIX = collections.OrderedDict([
    ("[", Operator(name="[]", precedence=12, assoc="left",
                   handler=ast.Select, docstring="Array subscript.",
                   postfix=rbracket)),

    # This is not actually currently used, because function calls are atoms
    # and the application has a special subgrammar. However, it is still useful
    # to think of this, conceptually, as a mixfix operator with a very high
    # precedence.
    ("(", Operator(name="()", precedence=11, assoc="left",
                   handler=ast.Apply, docstring="Function call.",
                   postfix=rparen)),
])


PREFIX = collections.OrderedDict([
    ("not", Operator(name="not", precedence=6, assoc="right",
                     handler=ast.Complement, docstring="Logical NOT.",
                     postfix=None)),
    ("-", Operator(name="-", precedence=5, assoc="right",
                   handler=transforms.NegateValue,
                   docstring="Unary -.", postfix=None)),
])


SQL_KEYWORDS = frozenset([
    "SELECT", "FROM", "ANY", "WHERE", "DESC", "ASC", "ORDER BY"
])


# Builtin pseudo-functions which cannot be overriden.
BUILTINS = {
    "map": ast.Map,
    "sort": ast.Sort,
    "filter": ast.Filter,
    "bind": ast.Bind,
    "any": ast.Any,
    "each": ast.Each
}


# Additional grammar used by the parser.

def bool_literal(tokens):
    match = _keyword(tokens, "true")
    if match:
        return match._replace(value=True)

    match = _keyword(tokens, "false")
    if match:
        return match._replace(value=False)


def literal(tokens):
    return bool_literal(tokens) or _name(tokens, "literal")


def symbol(tokens):
    return _name(tokens, "symbol")


def prefix(tokens):
    return _operator(tokens, PREFIX)


def param(tokens):
    return _name(tokens, "param")


def not_in(tokens):
    match = _multi_keyword(tokens, ("not", "in"))
    if match:
        return match._replace(operator=INFIX["not in"])


def infix(tokens):
    return _operator(tokens, INFIX) or not_in(tokens)


def mixfix(tokens):
    """Match a mixfix operator, like () (not really) or [].

    () isn't actually matched, because function application is special-cased
    in the parser, even though it is, conceptually, a binary operator just like
    the array subscript. For rationale, see the parser method 'application'.
    """
    match = lbracket(tokens)
    if match:
        return match._replace(operator=MIXFIX["["])


def binary_operator(tokens):
    """Binary operators in dottysql are infix or mixfix (infix + postfix)."""
    return infix(tokens) or mixfix(tokens)


def builtin(tokens):
    """Matches a call to a builtin pseudo-function (like map or sort)."""
    return _keywords(tokens, BUILTINS)


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

        return TokenMatch(None, func.value, (func, paren))


def if_if(tokens):
    """Matches an if-else block."""
    return _keyword(tokens, "if")


def if_then(tokens):
    return _keyword(tokens, "then")


def if_else_if(tokens):
    return _multi_keyword(tokens, ("else", "if"))


def if_else(tokens):
    return _keyword(tokens, "else")


# SQL subgrammar:

def select(tokens):
    return _keyword(tokens, "select")


def select_any(tokens):
    return _keyword(tokens, "any")


def select_all(tokens):
    return _keyword(tokens, "*")


def select_as(tokens):
    return _keyword(tokens, "as")


def select_from(tokens):
    return _keyword(tokens, "from")


def select_where(tokens):
    return _keyword(tokens, "where")


def select_order(tokens):
    return _multi_keyword(tokens, ("order", "by"))


def select_asc(tokens):
    return _keyword(tokens, "asc")


def select_desc(tokens):
    return _keyword(tokens, "desc")


def sql_keyword(tokens):
    return (_keywords(tokens, SQL_KEYWORDS)
            or _multi_keyword(tokens, ("order", "by")))
