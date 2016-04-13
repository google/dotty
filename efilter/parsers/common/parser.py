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
This module implements a customizable precedence-climbing parser.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import ast
from efilter import errors

from efilter.parsers.common import grammar
from efilter.parsers.common import token_stream


class ExpressionParser(object):
    """Precedence-climbing parser with support for *fix operators.

    Precedence-climbing parsers refer to an operator precedence table which can
    be modified at runtime. This implementation supports prefix, infix, suffix
    and mixfix operators and can be used to support grammars that aren't known
    ahead of time.

    This parser also supports circumfix operators with repeated infix
    separators, which allows for list builders and the like. For example:

        # This builds a list:
        Operator(prefix=Token("lbracket", "["),
                 infix=Token("comma", ","),
                 suffix=Token("rbracket", "]"),
                 handler=ast.Tuple)

        # The above doesn't conflict with, for example, array subscription
        # because mixfix and circumfix operators are non-ambiguous:
        Operator(prefix=None,
                 infix=Token("lbracket", "["),
                 suffix=Token("rbracket", "]"),
                 handler=ast.Select)

    Precedence-climbing is particularly suitable for atom/operator expressions,
    but doesn't extend well to more complex grammars, such as SQL, function
    application, C-like languages, etc. For those more complex use-cases, this
    class can still be invoked for the subsections that are pure expression
    syntax.

    * Sometimes called postcirfumfix: infix + suffix part, like x[y].
    """

    operators = None

    @property
    def original(self):
        return self.tokens.tokenizer.source

    def __init__(self, operators, tokenizer):
        self.operators = grammar.OperatorTable(*operators)
        self.tokens = token_stream.TokenStream(tokenizer)

    def parse(self):
        result = self.expression()
        if self.tokens.peek(0):
            token = self.tokens.peek(0)
            raise errors.EfilterParseError(
                message="Unexpected %s '%s' here." % (token.name, token.value),
                query=self.original, token=token)

        if result is None:
            raise errors.EfilterParseError(
                message="Query %r is empty." % self.original)

        return result

    def expression(self, previous_precedence=0):
        lhs = self.atom()
        return self.operator(lhs, previous_precedence)

    def atom(self):
        # Unary operator.
        if self.tokens.accept(grammar.prefix, self.operators):
            operator = self.tokens.matched.operator
            start = self.tokens.matched.start
            children = [self.expression(operator.precedence)]

            # Allow infix to be repeated in circumfix operators.
            if operator.infix:
                while self.tokens.accept(grammar.match_tokens(operator.infix)):
                    children.append(self.expression())

            # If we have a suffix expect it now.
            if operator.suffix:
                self.tokens.expect(grammar.match_tokens(operator.suffix))

            return operator.handler(*children, start=start,
                                    end=self.tokens.matched.end,
                                    source=self.original)

        if self.tokens.accept(grammar.literal):
            return ast.Literal(self.tokens.matched.value, source=self.original,
                               start=self.tokens.matched.start,
                               end=self.tokens.matched.end)

        if self.tokens.accept(grammar.symbol):
            return ast.Var(self.tokens.matched.value, source=self.original,
                           start=self.tokens.matched.start,
                           end=self.tokens.matched.end)

        if self.tokens.accept(grammar.lparen):
            expr = self.expression()
            self.tokens.expect(grammar.rparen)
            return expr

        if self.tokens.peek(0):
            raise errors.EfilterParseError(
                message="Was not expecting %r here." % self.tokens.peek(0).name,
                token=self.tokens.peek(0))
        else:
            raise errors.EfilterParseError("Unexpected end of input.")

    def _infix_of_min_precedence(self, tokens, precedence):
        match = grammar.infix(tokens, self.operators)
        if not match:
            return

        if match.operator.precedence < precedence:
            return

        return match

    def operator(self, lhs, min_precedence):
        while self.tokens.accept(self._infix_of_min_precedence, min_precedence):
            operator = self.tokens.matched.operator

            if operator.prefix:
                raise ValueError("infix+prefix operators aren't supported.")

            if operator.suffix:
                rhs = self.expression()
                self.tokens.expect(grammar.match_tokens(operator.suffix))
                rhs.end = self.tokens.matched.end
            else:
                rhs = self.atom()

            next_min_precedence = operator.precedence
            if operator.assoc == "left":
                next_min_precedence += 1

            while self.tokens.match(grammar.infix, self.operators):
                if (self.tokens.matched.operator.precedence
                        < next_min_precedence):
                    break

                rhs = self.operator(rhs,
                                    self.tokens.matched.operator.precedence)

            if not rhs:
                raise errors.EfilterParseError(
                    message="Expecting the operator RHS here.",
                    token=self.tokens.peek(0))
            lhs = operator.handler(lhs, rhs, start=lhs.start, end=rhs.end,
                                   source=self.original)

        return lhs
