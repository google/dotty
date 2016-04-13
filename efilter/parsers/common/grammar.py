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
This module provides grammar primitives common across most parsers.

### What is a grammar?

In the EFILTER world, we use the word 'grammar' to mean a collection of
stateless functions that take an iterable of tokens and return a TokenMatch
if the tokens match the grammatical construct the function represents.

These functions are called 'grammar functions' (gasp!).

For example, a grammar function that matches a parenthesis would be:

def lparen(tokens):
    first_token = next(iter(tokens))
    if first_token.name == "lparen":
        return TokenMatch(operator=None, value=None, tokens=[first_token])

To make writing grammar functions easier, this module provides a number of
primitives that largely insulate the programmer from having to write all of
the above. The real world lparen function actually looks like this:

def lparen(tokens):
    return token_name(tokens, "lparen")

### Operators

A common theme across most grammars are operators, and this module provides
a convenient container to group grammar functions related to operators.

The 'Operator' container groups basic information about an operator, starting
with its name and docstring, its suffix, infix and prefix parts, and also an
AST construct that the operator maps onto.

For example, the addition operator would look like this:

plus = Operator(
    handler=ast.Sum,
    assoc="left",
    infix="+"
    ...)
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import collections
import itertools
import six


class Token(collections.namedtuple("Token", "name value start end")):
    """Represents one token, which is what grammars operate on."""

    def __new__(cls, name, value, start=None, end=None):
        return super(Token, cls).__new__(cls, name, value, start, end)

    def __repr__(self):
        return "Token(name='%s', value='%s', start=%d, end=%d)" % (
            self.name, self.value, self.start or 0, self.end or 0)

    def __eq__(self, other):
        """Tokens compare on name and value, not on position."""
        return (self.name, self.value) == (other.name, other.value)

    def __hash__(self):
        """Tokens hash on name and value, not on position."""
        return hash((self.name, self.value))


class Operator(collections.namedtuple(
        "Operator",
        "name precedence assoc handler docstring prefix infix suffix")):
    """Declares an operator in a grammar with functions to match it.

    Operators can have prefix, infix and suffix parts, each of which is
    represented by the token (like Token("keyword", "+", None)). Each operator
    must have at least one of the *fixes. This class has no restriction on which
    *fixes can be used together, but the individual parsers may not support
    every combination. For example, DottySQL doesn't parse circumfix
    (prefix + suffix) operators.

    Previously, DottySQL used grammar functions for suffixes, which works well
    when there is only a small number of them, but is very slow if there are
    many operators. In practice, the grammar functions matching *fixes almost
    always just call _keyword, which means they can be replaced with a lookup
    in the operator table.

    Arguments:
        name: The literal name of the operator, such as "+" or "not".
        precedence: Integer precedence with operators of the same arity.
        handler: Callable that emits AST for this operator.
        docstring: Documentation for the operator.
        assoc: Associativity - can be left or right for infix operators.
        suffix: (OPTIONAL) The token (not grammar function) of the suffix.
        prefix: (OPTIONAL) The token (not grammar function) of the prefix.
        infix: (OPTIONAL) The token (not grammar function) of the infix.
    """


class TokenLookupTable(object):
    """Ordered associative container where tokens are keys.

    Public properties:
        case_sensitive (default False): If set to False, all lookups will be
            converted to lower case. NOTE: Does not affect insertion:
            case-insensitive grammar should insert operators in lower case.
    """
    _max_len = 1  # Longest match so far.
    _table = None  # Ordered dict keyed on tokens.

    # This affects only lookups, not insertion.
    case_sensitive = False

    def __init__(self, *entries):
        self._table = collections.OrderedDict()

        for tokens, entry in entries:
            self.set(tokens, entry)

    def set(self, tokens, entry):
        if isinstance(tokens, Token):
            tokens = (tokens,)
        elif isinstance(tokens, tuple):
            self._max_len = max(self._max_len, len(tokens))
        else:
            raise TypeError(
                "TokenLookupTable only supports instances of Token or "
                "tuples thereof for keys. Got %r." % tokens)

        if tokens in self._table:
            raise ValueError("Duplicate token key %r for %r." % (
                tokens, entry))

        self._table[tokens] = entry

    def _normalize_token(self, token):
        if (isinstance(token.value, six.string_types)
                and not self.case_sensitive):
            return token._replace(value=token.value.lower())

        return token

    def match(self, tokens):
        # Try to match longest known match first.
        for match_len in range(self._max_len, 0, -1):
            needle = tuple((self._normalize_token(t)
                            for t in itertools.islice(tokens, match_len)))
            result = self._table.get(needle)
            if result:
                return result, needle

        return None, None


class OperatorTable(object):
    """A complete set of operators in a grammar, keyed on their *fix tokens."""
    prefix = None
    infix = None
    suffix = None
    by_name = None
    by_handler = None

    def __init__(self, *operators):
        self.prefix = TokenLookupTable()
        self.infix = TokenLookupTable()
        self.suffix = TokenLookupTable()
        self.by_name = dict()
        self.by_handler = dict()

        for operator in operators:
            if operator.name in self.by_name:
                raise ValueError("Duplicit operator name %r." % operator.name)
            self.by_name[operator.name] = operator

            if operator.handler not in self.by_handler:
                # Multiple operators can have the same handler, in which case
                # they are probably aliases that mean the same thing. In that
                # case the first operator "wins" and will likely be what
                # the formatter for this syntax ends up using as default when
                # it formats this AST.
                self.by_handler[operator.handler] = operator

            # An operator can have multiple components, but it is only indexed
            # by the first one to prevent ambiguity.
            if operator.prefix:
                self.prefix.set(operator.prefix, operator)
            elif operator.infix:
                self.infix.set(operator.infix, operator)
            elif operator.suffix:
                self.suffix.set(operator.suffix, operator)


# Grammar primitives and helpers. (No grammar functions until the end of file.)

class TokenMatch(collections.namedtuple(
        "TokenMatch", "operator value tokens")):
    """Represents a one or more matching tokens and, optionally, their contents.

    Arguments:
        operator: The Operator instance that matched, if any.
        value: The literal value that matched, if any.
        tokens: The actual tokens the match consumed.
    """

    @property
    def start(self):
        return self.tokens[0].start

    @property
    def end(self):
        return self.tokens[-1].end

    @property
    def first(self):
        return self.tokens[0]


def keyword(tokens, expected):
    """Case-insensitive keyword match."""
    try:
        token = next(iter(tokens))
    except StopIteration:
        return

    if token and token.name == "symbol" and token.value.lower() == expected:
        return TokenMatch(None, token.value, (token,))


def multi_keyword(tokens, keyword_parts):
    """Match a case-insensitive keyword consisting of multiple tokens."""
    tokens = iter(tokens)
    matched_tokens = []
    limit = len(keyword_parts)

    for idx in six.moves.range(limit):
        try:
            token = next(tokens)
        except StopIteration:
            return

        if (not token or token.name != "symbol" or
                token.value.lower() != keyword_parts[idx]):
            return

        matched_tokens.append(token)

    return TokenMatch(None, token.value, matched_tokens)


def keywords(tokens, expected):
    """Match against any of a set/dict of keywords.

    Not that this doesn't support multi-part keywords. Any multi-part keywords
    must be special-cased in their grammar function.
    """
    try:
        token = next(iter(tokens))
    except StopIteration:
        return

    if token and token.name == "symbol" and token.value.lower() in expected:
        return TokenMatch(None, token.value, (token,))


def prefix(tokens, operator_table):
    """Match a prefix of an operator."""
    operator, matched_tokens = operator_table.prefix.match(tokens)
    if operator:
        return TokenMatch(operator, None, matched_tokens)


def infix(tokens, operator_table):
    """Match an infix of an operator."""
    operator, matched_tokens = operator_table.infix.match(tokens)
    if operator:
        return TokenMatch(operator, None, matched_tokens)


def suffix(tokens, operator_table):
    """Match a suffix of an operator."""
    operator, matched_tokens = operator_table.suffix.match(tokens)
    if operator:
        return TokenMatch(operator, None, matched_tokens)


def token_name(tokens, expected):
    """Match a token name (type)."""
    try:
        token = next(iter(tokens))
    except StopIteration:
        return

    if token and token.name == expected:
        return TokenMatch(None, token.value, (token,))


def match_tokens(expected_tokens):
    """Generate a grammar function that will match 'expected_tokens' only."""
    if isinstance(expected_tokens, Token):
        # Match a single token.
        def _grammar_func(tokens):
            try:
                next_token = next(iter(tokens))
            except StopIteration:
                return

            if next_token == expected_tokens:
                return TokenMatch(None, next_token.value, (next_token,))

    elif isinstance(expected_tokens, tuple):
        # Match multiple tokens.
        match_len = len(expected_tokens)
        def _grammar_func(tokens):
            upcoming = tuple(itertools.islice(tokens, match_len))
            if upcoming == expected_tokens:
                return TokenMatch(None, None, upcoming)
    else:
        raise TypeError(
            "'expected_tokens' must be an instance of Token or a tuple "
            "thereof. Got %r." % expected_tokens)

    return _grammar_func


# Some common grammar functions:


def literal(tokens):
    return token_name(tokens, "literal")


def symbol(tokens):
    return token_name(tokens, "symbol")


def lparen(tokens):
    return token_name(tokens, "lparen")


def rparen(tokens):
    return token_name(tokens, "rparen")


def lbracket(tokens):
    return token_name(tokens, "lbracket")


def rbracket(tokens):
    return token_name(tokens, "rbracket")


def comma(tokens):
    return token_name(tokens, "comma")
