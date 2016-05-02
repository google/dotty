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
This module implements the DottySQL language.

Sketch of the DottySQL grammar follows, in pseudo-EBNF. This is not meant to be
correct, by the way - or exhaustive - but to give the reader a sense of what the
parser is doing.

# Simplified - the actual binary_expressions are parsed using
# precedence-climbing.
expression = atom | binary_expression .

binary_expression =
    atom { [ infix_operator atom ] }
    | atom { [ mixfix_operator expression suffix ] }

atom =
    [ prefix ]
    ( select_expression
    | any_expression
    | func_application
    | let_expr
    | var
    | literal
    | list
    | "(" expression ["," expression ] ")" ).

list = "[" literal [ { "," literal } ] "]" .

let_expr = "let" var "=" expression [ "," var "=" expression ] expression .

select_expression = "select" ("*" | "any" | what_expression ) from_expression .
what_expression = expression ["as" var ] { "," expression ["as" var ] } .
from_expression = expression [ ( where_expression | order_expression ) ] .
where_expression = expression [ order_expression ] .
order_expression = expression [ ( "asc" | "desc" ) ] .
any_expression = [ "select" ] "any" [ "from" ] expression .

func_application = var "(" [ expression [ { "," expression } ] ] ")" .

# infix, prefix, literal and var should be obvious.

"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import itertools
import six

from efilter import ast
from efilter import errors
from efilter import syntax

from efilter.parsers.dottysql import grammar

from efilter.parsers.common import grammar as common_grammar
from efilter.parsers.common import tokenizer
from efilter.parsers.common import token_stream


class Parser(syntax.Syntax):
    """Parses DottySQL and produces an efilter AST.

    This is a basic recursive descend parser that handles infix expressions by
    precedence climbing.
    """

    last_match = common_grammar.TokenMatch(None, None, None)
    last_param = 0
    tokens = None

    def __init__(self, original, params=None):
        super(Parser, self).__init__(original)

        self.tokens = token_stream.TokenStream(
            tokenizer.LazyTokenizer(self.original))

        if isinstance(params, list):
            self.params = {}
            for idx, val in enumerate(params):
                self.params[idx] = val
        elif isinstance(params, dict):
            self.params = params
        elif params is None:
            self.params = {}
        else:
            raise TypeError("Params must be a list or a dict, not %r." %
                            type(params))

    def parse(self):
        # If we get any exceptions, make sure they have access to the query
        # source code.
        try:
            result = self.expression()
        except errors.EfilterError as e:
            e.query = self.original
            raise

        if self.tokens.peek(0):
            token = self.tokens.peek(0)
            return self.error(
                "Unexpected %s '%s'. Were you looking for an operator?" %
                (token.name, token.value),
                token)

        return result

    @property
    def root(self):
        return self.parse()

    def error(self, message=None, start_token=None, end_token=None):
        start = self.tokens.tokenizer.position
        end = start + 20
        if start_token:
            start = start_token.start
            end = start_token.end

        if end_token:
            end = end_token.end

        raise errors.EfilterParseError(
            query=self.original, start=start, end=end, message=message,
            token=start_token)

    # Recursive grammar.

    def expression(self, previous_precedence=0):
        """An expression is an atom or an infix expression.

        Grammar (sort of, actually a precedence-climbing parser):
            expression = atom [ binary_operator expression ] .

        Args:
            previous_precedence: What operator precedence should we start with?
        """
        lhs = self.atom()

        return self.operator(lhs, previous_precedence)

    def atom(self):
        """Parse an atom, which is most things.

        Grammar:
            atom =
                [ prefix ]
                ( select_expression
                | any_expression
                | func_application
                | let_expr
                | var
                | literal
                | list
                | "(" expression ")" ) .
        """
        # Parameter replacement with literals.
        if self.tokens.accept(grammar.param):
            return self.param()

        # Let expressions (let(x = 5, y = 10) x + y)
        if self.tokens.accept(grammar.let):
            return self.let()

        # At the top level, we try to see if we are recursing into an SQL query.
        if self.tokens.accept(grammar.select):
            return self.select()

        # A SELECT query can also start with 'ANY'.
        if self.tokens.accept(grammar.select_any):
            return self.select_any()

        # Explicitly reject any keywords from SQL other than SELECT and ANY.
        # If we don't do this they will match as valid symbols (variables)
        # and that might be confusing to the user.
        self.tokens.reject(grammar.sql_keyword)

        # Match if-else before other things that consume symbols.
        if self.tokens.accept(grammar.if_if):
            return self.if_if()

        # Operators must be matched first because the same symbols could also
        # be vars or applications.
        if self.tokens.accept(grammar.prefix):
            operator = self.tokens.matched.operator
            start = self.tokens.matched.start
            expr = self.expression(operator.precedence)
            return operator.handler(expr, start=start, end=expr.end,
                                    source=self.original)

        if self.tokens.accept(grammar.literal):
            return ast.Literal(self.tokens.matched.value, source=self.original,
                               start=self.tokens.matched.start,
                               end=self.tokens.matched.end)

        # Match builtin pseudo-functions before functions and vars to prevent
        # overrides.
        if self.tokens.accept(grammar.builtin):
            return self.builtin(self.tokens.matched.value)

        # Match applications before vars, because obviously.
        if self.tokens.accept(grammar.application):
            return self.application(
                ast.Var(self.tokens.matched.value, source=self.original,
                        start=self.tokens.matched.start,
                        end=self.tokens.matched.end))

        if self.tokens.accept(common_grammar.symbol):
            return ast.Var(self.tokens.matched.value, source=self.original,
                           start=self.tokens.matched.start,
                           end=self.tokens.matched.end)

        if self.tokens.accept(common_grammar.lparen):
            # Parens will contain one or more expressions. If there are several
            # expressions, separated by commas, then they are a repeated value.
            #
            # Unlike lists, repeated values must all be of the same type,
            # otherwise evaluation of the query will fail at runtime (or
            # type-check time, for simple cases.)
            start = self.tokens.matched.start
            expressions = [self.expression()]

            while self.tokens.accept(common_grammar.comma):
                expressions.append(self.expression())

            self.tokens.expect(common_grammar.rparen)

            if len(expressions) == 1:
                return expressions[0]
            else:
                return ast.Repeat(*expressions, source=self.original,
                                  start=start, end=self.tokens.matched.end)

        if self.tokens.accept(common_grammar.lbracket):
            return self.list()

        # We've run out of things we know the next atom could be. If there is
        # still input left then it's illegal syntax. If there is nothing then
        # the input cuts off when we still need an atom. Either is an error.
        if self.tokens.peek(0):
            return self.error(
                "Was not expecting %r here." % self.tokens.peek(0).name,
                start_token=self.tokens.peek(0))
        else:
            return self.error("Unexpected end of input.")

    def let(self):
        saved_start = self.tokens.matched.start

        expect_rparens = 0
        while self.tokens.accept(common_grammar.lparen):
            expect_rparens += 1

        bindings = []
        while True:
            symbol = self.tokens.expect(common_grammar.symbol)
            binding = ast.Literal(symbol.value, start=symbol.start,
                                  end=symbol.end, source=self.original)

            self.tokens.expect(grammar.let_assign)

            value = self.expression()
            bindings.append(ast.Pair(binding, value, start=binding.start,
                                     end=value.end, source=self.original))

            if not self.tokens.accept(common_grammar.comma):
                break

        bind = ast.Bind(*bindings, start=bindings[0].start,
                        end=bindings[-1].end, source=self.original)

        while expect_rparens:
            self.tokens.expect(common_grammar.rparen)
            expect_rparens -= 1

        nested_expression = self.expression()
        return ast.Let(bind, nested_expression, start=saved_start,
                       end=nested_expression.end, source=self.original)

    def param(self):
        if self.tokens.matched.value is None:
            param = self.last_param
            self.last_param += 1
        elif isinstance(self.tokens.matched.value, int):
            param = self.last_param = self.tokens.matched.value
        elif isinstance(self.tokens.matched.value, six.string_types):
            param = self.tokens.matched.value
        else:
            return self.error(
                "Invalid param %r." % self.tokens.matched.value,
                start_token=self.tokens.matched.first)

        if param not in self.params:
            return self.error(
                "Param %r unavailable. (Available: %r)" % (param, self.params),
                start_token=self.tokens.matched.first)

        return ast.Literal(self.params[param], start=self.tokens.matched.start,
                           end=self.tokens.matched.end, source=self.original)

    def accept_operator(self, precedence):
        """Accept the next binary operator only if it's of higher precedence."""
        match = grammar.infix(self.tokens)
        if not match:
            return

        if match.operator.precedence < precedence:
            return

        # The next thing is an operator that we want. Now match it for real.
        return self.tokens.accept(grammar.infix)

    def operator(self, lhs, min_precedence):
        """Climb operator precedence as long as there are operators.

        This function implements a basic precedence climbing parser to deal
        with binary operators in a sane fashion. The outer loop will keep
        spinning as long as the next token is an operator with a precedence
        of at least 'min_precedence', parsing operands as atoms (which,
        in turn, recurse into 'expression' which recurses back into 'operator').

        This supports both left- and right-associativity. The only part of the
        code that's not a regular precedence-climber deals with mixfix
        operators. A mixfix operator in DottySQL consists of an infix part
        and a suffix (they are still binary, they just have a terminator).
        """

        # Spin as long as the next token is an operator of higher
        # precedence. (This may not do anything, which is fine.)
        while self.accept_operator(precedence=min_precedence):
            operator = self.tokens.matched.operator

            # If we're parsing a mixfix operator we can keep going until
            # the suffix.
            if operator.suffix:
                rhs = self.expression()
                self.tokens.expect(common_grammar.match_tokens(operator.suffix))
                rhs.end = self.tokens.matched.end
            elif operator.name == ".":
                # The dot operator changes the meaning of RHS.
                rhs = self.dot_rhs()
            else:
                # The right hand side is an atom, which might turn out to be
                # an expression. Isn't recursion exciting?
                rhs = self.atom()

            # Keep going as long as the next token is an infix operator of
            # higher precedence.
            next_min_precedence = operator.precedence
            if operator.assoc == "left":
                next_min_precedence += 1

            while self.tokens.match(grammar.infix):
                if (self.tokens.matched.operator.precedence
                        < next_min_precedence):
                    break
                rhs = self.operator(rhs,
                                    self.tokens.matched.operator.precedence)

            lhs = operator.handler(lhs, rhs, start=lhs.start, end=rhs.end,
                                   source=self.original)

        return lhs

    def dot_rhs(self):
        """Match the right-hand side of a dot (.) operator.

        The RHS must be a symbol token, but it is interpreted as a literal
        string (because that's what goes in the AST of Resolve.)
        """
        self.tokens.expect(common_grammar.symbol)
        return ast.Literal(self.tokens.matched.value,
                           start=self.tokens.matched.start,
                           end=self.tokens.matched.end, source=self.original)

    # SQL subgrammar:

    def select(self):
        """First part of an SQL query."""
        # Try to match the asterisk, any or list of vars.
        if self.tokens.accept(grammar.select_any):
            return self.select_any()

        if self.tokens.accept(grammar.select_all):
            # The FROM after SELECT * is required.
            self.tokens.expect(grammar.select_from)
            return self.select_from()

        return self.select_what()

    def select_any(self):
        saved_match = self.tokens.matched
        # Any can be either a start of a pseudosql query or the any builtin.
        if self.tokens.match(common_grammar.lparen):
            self.tokens.matched = saved_match
            # The paren means we're calling 'any(...)' - the builtin.
            return self.builtin(self.tokens.matched.value)

        # An optional FROM can go after ANY.
        # "SELECT ANY FROM", "ANY FROM", "SELECT ANY" and just "ANY" all mean
        # the exact same thing. The full form of SELECT ANY FROM is preferred
        # but the shorthand is very useful for writing boolean indicators and
        # so it's worth allowing it.
        start = self.tokens.matched.start
        self.tokens.accept(grammar.select_from)

        source_expression = self.expression()

        if self.tokens.accept(grammar.select_where):
            map_expression = self.expression()
        else:
            map_expression = None

        # ORDER after ANY doesn't make any sense.
        self.tokens.reject(grammar.select_order)

        if map_expression:
            return ast.Any(source_expression, map_expression,
                           start=start, end=map_expression.end,
                           source=self.original)

        return ast.Any(source_expression, start=start,
                       end=self.tokens.matched.end, source=self.original)

    def _guess_name_of(self, expr):
        """Tries to guess what variable name 'expr' ends in."""
        if isinstance(expr, ast.Var):
            return expr.value

        if isinstance(expr, ast.Resolve):
            # We know the RHS of resolve is a Literal because that's what
            # Parser.dot_rhs does.
            return expr.rhs.value

    def select_what(self):
        # Each value we select is in form EXPRESSION [AS SYMBOL]. Values are
        # separated by commas.
        start = self.tokens.matched.start
        used_names = set()  # Keeps track of named values to prevent duplicates.
        vars = []
        for watermark in itertools.count():
            value_expression = self.expression()

            if self.tokens.accept(grammar.select_as):
                # If there's an AS then we have an explicit name for this value.
                self.tokens.expect(common_grammar.symbol)

                if self.tokens.matched.value in used_names:
                    return self.error(
                        "Duplicate 'AS' name %r." % self.tokens.matched.value)

                key_expression = ast.Literal(self.tokens.matched.value,
                                             start=self.tokens.matched.start,
                                             end=self.tokens.matched.end,
                                             source=self.original)
                used_names.add(self.tokens.matched.value)
            else:
                # If the value expression is a map of var (x.y.z...) then
                # we can guess the name from the last var.
                name = self._guess_name_of(value_expression)

                if not name or name in used_names:
                    # Give up and just use the current watermark for key.
                    name = watermark
                else:
                    used_names.add(name)

                key_expression = ast.Literal(name)

            end = key_expression.end or value_expression.end
            vars.append(ast.Pair(key_expression, value_expression,
                                 start=value_expression.start, end=end,
                                 source=self.original))

            if self.tokens.accept(grammar.select_from):
                # Make ast.Bind here.
                source_expression = self.select_from()
                return ast.Map(
                    source_expression,
                    ast.Bind(*vars, start=start, end=vars[-1].end,
                             source=self.original),
                    start=start,
                    end=self.tokens.matched.end,
                    source=self.original)

            self.tokens.expect(common_grammar.comma)

    def select_from(self):
        source_expression = self.expression()
        if self.tokens.accept(grammar.select_where):
            return self.select_where(source_expression)

        if self.tokens.accept(grammar.select_order):
            return self.select_order(source_expression)

        if self.tokens.accept(grammar.select_limit):
            return self.select_limit(source_expression)

        return source_expression

    def select_where(self, source_expression):
        start = self.tokens.matched.start
        filter_expression = ast.Filter(source_expression, self.expression(),
                                       start=start, end=self.tokens.matched.end,
                                       source=self.original)

        if self.tokens.accept(grammar.select_order):
            return self.select_order(filter_expression)

        if self.tokens.accept(grammar.select_limit):
            return self.select_limit(filter_expression)

        return filter_expression

    def select_order(self, source_expression):
        start = self.tokens.matched.start
        sort_expression = ast.Sort(source_expression, self.expression(),
                                   start=start, end=self.tokens.matched.end,
                                   source=self.original)

        if self.tokens.accept(grammar.select_asc):
            sort_expression.end = self.tokens.matched.end
            return sort_expression

        if self.tokens.accept(grammar.select_desc):
            # Descending sort uses the stdlib function 'reverse' on the sorted
            # results. Standard library's core functions should ALWAYS be
            # available.
            sort_expression = ast.Apply(
                ast.Var("reverse",
                        start=sort_expression.start,
                        end=self.tokens.matched.end,
                        source=self.original),
                sort_expression,
                start=sort_expression.start,
                end=self.tokens.matched.end,
                source=self.original)

        if self.tokens.accept(grammar.select_limit):
            return self.select_limit(sort_expression)

        if self.tokens.accept(grammar.select_limit):
            return self.select_limit(sort_expression)

        return sort_expression

    def select_limit(self, source_expression):
        """Match LIMIT take [OFFSET drop]."""
        start = self.tokens.matched.start

        # The expression right after LIMIT is the count to take.
        limit_count_expression = self.expression()

        # Optional OFFSET follows.
        if self.tokens.accept(grammar.select_offset):
            offset_start = self.tokens.matched.start
            offset_end = self.tokens.matched.end

            # Next thing is the count to drop.
            offset_count_expression = self.expression()

            # We have a new source expression, which is drop(count, original).
            offset_source_expression = ast.Apply(
                ast.Var("drop", start=offset_start, end=offset_end,
                        source=self.original),
                offset_count_expression,
                source_expression,
                start=offset_start, end=offset_count_expression.end,
                source=self.original)

            # Drop before taking, because obviously.
            source_expression = offset_source_expression

        limit_expression = ast.Apply(
            ast.Var("take", start=start, end=limit_count_expression.end,
                    source=self.original),
            limit_count_expression,
            source_expression,
            start=start, end=self.tokens.matched.end, source=self.original)

        return limit_expression

    # Builtin pseudo-function application subgrammar.

    def builtin(self, keyword):
        """Parse the pseudo-function application subgrammar."""
        # The match includes the lparen token, so the keyword is just the first
        # token in the match, not the whole thing.
        keyword_start = self.tokens.matched.first.start
        keyword_end = self.tokens.matched.first.end
        self.tokens.expect(common_grammar.lparen)

        if self.tokens.matched.start != keyword_end:
            return self.error(
                "No whitespace allowed between function and lparen.",
                start_token=self.tokens.matched.first)

        expr_type = grammar.BUILTINS[keyword.lower()]
        arguments = [self.expression()]
        while self.tokens.accept(common_grammar.comma):
            arguments.append(self.expression())

        self.tokens.expect(common_grammar.rparen)

        if expr_type.arity and expr_type.arity != len(arguments):
            return self.error(
                "%s expects %d arguments, but was passed %d." % (
                    keyword, expr_type.arity, len(arguments)),
                start_token=self.tokens.matched.first)

        return expr_type(*arguments, start=keyword_start,
                         end=self.tokens.matched.end, source=self.original)

    # If-else if-else grammar.
    def if_if(self):
        start = self.tokens.matched.start

        # Even-numbered children are conditions; odd-numbered are results.
        # Last child is the else expression.
        children = [self.expression()]

        self.tokens.expect(grammar.if_then)
        children.append(self.expression())

        while self.tokens.accept(grammar.if_else_if):
            children.append(self.expression())
            self.tokens.expect(grammar.if_then)
            children.append(self.expression())

        if self.tokens.accept(grammar.if_else):
            children.append(self.expression())
        else:
            children.append(ast.Literal(None))

        return ast.IfElse(*children, start=start, end=self.tokens.matched.end,
                          source=self.original)

    # Function application subgrammar.

    def application(self, func):
        """Parse the function application subgrammar.

        Function application can, conceptually, be thought of as a mixfix
        operator, similar to the way array subscripting works. However, it is
        not clear at this point whether we want to allow it to work as such,
        because doing so would permit queries to, at runtime, select methods
        out of an arbitrary object and then call them.

        While there is a function whitelist and preventing this sort of thing
        in the syntax isn't a security feature, it still seems like the
        syntax should make it clear what the intended use of application is.

        If we later decide to extend DottySQL to allow function application
        over an arbitrary LHS expression then that syntax would be a strict
        superset of the current syntax and backwards compatible.
        """
        start = self.tokens.matched.start
        if self.tokens.accept(common_grammar.rparen):
            # That was easy.
            return ast.Apply(func, start=start, end=self.tokens.matched.end,
                             source=self.original)

        arguments = [self.expression()]
        while self.tokens.accept(common_grammar.comma):
            arguments.append(self.expression())

        self.tokens.expect(common_grammar.rparen)
        return ast.Apply(func, *arguments, start=start,
                         end=self.tokens.matched.end, source=self.original)

    # Tuple grammar.

    def list(self):
        """Parse a list (tuple) which can contain any combination of types."""
        start = self.tokens.matched.start

        if self.tokens.accept(common_grammar.rbracket):
            return ast.Tuple(start=start, end=self.tokens.matched.end,
                             source=self.original)

        elements = [self.expression()]

        while self.tokens.accept(common_grammar.comma):
            elements.append(self.expression())

        self.tokens.expect(common_grammar.rbracket)
        return ast.Tuple(*elements, start=start, end=self.tokens.matched.end,
                         source=self.original)


syntax.Syntax.register_parser(Parser, shorthand="dottysql")
