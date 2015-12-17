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
    | atom { [ mixfix_operator expression postfix ] }

atom =
    [ prefix ]
    ( select_expression
    | any_expression
    | func_application
    | var
    | literal
    | list
    | "(" expression ["," expression ] ")" ).

list = "[" literal [ { "," literal } ] "]" .

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

from efilter import ast
from efilter import errors
from efilter import syntax

from efilter.parsers.experiments.dottysql import grammar
from efilter.parsers.experiments.dottysql import lexer


class Parser(syntax.Syntax):
    """Parses DottySQL and produces an efilter AST.

    This is a basic recursive descend parser that handles infix expressions by
    precedence climbing.
    """

    last_match = grammar.TokenMatch(None, None, None)
    last_param = 0

    def __init__(self, original, params=None):
        super(Parser, self).__init__(original)
        self.lexer = lexer.Lexer(self.original)

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

        if self.lexer.peek(0):
            token = self.lexer.peek(0)
            return self.error(
                "Unexpected %s '%s'. Were you looking for an operator?" %
                (token.name, token.value),
                token)

        return result

    @property
    def root(self):
        return self.parse()

    # Convenience accessors.

    @property
    def matched_operator(self):
        return self.last_match.operator

    @property
    def matched_value(self):
        return self.last_match.value

    @property
    def matched_tokens(self):
        return self.last_match.tokens

    @property
    def matched_start(self):
        return self.last_match.tokens[0].start

    @property
    def matched_end(self):
        return self.last_match.tokens[0].end

    @property
    def matched_wide_end(self):
        return self.last_match.tokens[-1].end

    def match(self, f):
        try:
            match = f(self.lexer)
        except StopIteration:
            # Some functions try to match multiple tokens towards the end of
            # input and end up going past the end of the query. That's alright.
            return

        if not match:
            return

        self.last_match = match
        return match

    def accept(self, f):
        match = self.match(f)
        if not match:
            return

        self.lexer.skip(len(self.matched_tokens))
        return match

    def expect(self, f):
        match = self.accept(f)
        if match:
            return match

        try:
            func_name = f.func_name
        except AttributeError:
            func_name = "<unnamed grammar construct>"

        return self.error(
            start_token=self.lexer.peek(0),
            message="Was expecting a %s here." % func_name)

    def reject(self, f):
        match = self.match(f)
        if match:
            token = self.lexer.peek(0)
            return self.error("Was not expecting a %s here." % token.name,
                              token)

    def error(self, message=None, start_token=None, end_token=None):
        start = self.lexer.position
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
                | var
                | literal
                | list
                | "(" expression ")" ) .
        """
        # Parameter replacement with literals.
        if self.accept(grammar.param):
            return self.param()

        # At the top level, we try to see if we are recursing into an SQL query.
        if self.accept(grammar.select):
            return self.select()

        # A SELECT query can also start with 'ANY'.
        if self.accept(grammar.select_any):
            return self.select_any()

        # Explicitly reject any keywords from SQL other than SELECT and ANY.
        # If we don't do this they will match as valid symbols (variables)
        # and that might be confusing to the user.
        self.reject(grammar.sql_keyword)

        # Match if-else before other things that consume symbols.
        if self.accept(grammar.if_if):
            return self.if_if()

        # Operators must be matched first because the same symbols could also
        # be vars or applications.
        if self.accept(grammar.prefix):
            operator = self.matched_operator
            start = self.matched_start
            expr = self.expression(operator.precedence)
            return operator.handler(expr, start=start, end=expr.end)

        if self.accept(grammar.literal):
            return ast.Literal(self.matched_value,
                               start=self.matched_start, end=self.matched_end)

        # Match builtin pseudo-functions before functions and vars to prevent
        # overrides.
        if self.accept(grammar.builtin):
            return self.builtin(self.matched_value)

        # Match applications before vars, because obviously.
        if self.accept(grammar.application):
            return self.application(
                ast.Var(self.matched_value,
                        start=self.matched_start, end=self.matched_end))

        if self.accept(grammar.symbol):
            return ast.Var(self.matched_value,
                           start=self.matched_start, end=self.matched_end)

        if self.accept(grammar.lparen):
            # Parens will contain one or more expressions. If there are several
            # expressions, separated by commas, then they are a repeated value.
            #
            # Unlike lists, repeated values must all be of the same type,
            # otherwise evaluation of the query will fail at runtime (or
            # type-check time, for simple cases.)
            start = self.matched_start
            expressions = [self.expression()]

            while self.accept(grammar.comma):
                expressions.append(self.expression())

            self.expect(grammar.rparen)

            if len(expressions) == 1:
                return expressions[0]
            else:
                return ast.Repeat(*expressions,
                                  start=start, end=self.matched_end)

        if self.accept(grammar.lbracket):
            return self.list()

        return self.error(
            "Was not expecting %r here." % self.lexer.peek(0).name,
            start_token=self.lexer.peek(0))

    def param(self):
        if self.matched_value is None:
            param = self.last_param
            self.last_param += 1
        elif isinstance(self.matched_value, int):
            param = self.last_param = self.matched_value
        elif isinstance(self.matched_value, basestring):
            param = self.matched_value
        else:
            return self.error(
                "Invalid param %r." % self.matched_value,
                start_token=self.matched_tokens[0])

        if param not in self.params:
            return self.error(
                "Param %r unavailable. (Available: %r)" % (param, self.params),
                start_token=self.matched_tokens[0])

        return ast.Literal(self.params[param], start=self.matched_start,
                           end=self.matched_end)

    def accept_operator(self, precedence):
        """Accept the next binary operator only if it's of higher precedence."""
        match = grammar.binary_operator(self.lexer)
        if not match:
            return

        if match.operator.precedence < precedence:
            return

        self.last_match = match
        self.lexer.skip(len(self.matched_tokens))
        return match

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
        and a postfix (they are still binary, they just have a terminator).
        """

        # Spin as long as the next token is an operator of higher
        # precedence. (This may not do anything, which is fine.)
        while self.accept_operator(precedence=min_precedence):
            operator = self.matched_operator

            # If we're parsing a mixfix operator we can keep going until
            # the postfix.
            if operator.postfix:
                rhs = self.expression()
                self.expect(operator.postfix)
                rhs.end = self.matched_end
            elif operator == grammar.INFIX["."]:
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

            while self.match(grammar.binary_operator):
                if self.matched_operator.precedence < next_min_precedence:
                    break
                rhs = self.operator(rhs, self.matched_operator.precedence)

            lhs = operator.handler(lhs, rhs, start=lhs.start, end=rhs.end)

        return lhs

    def dot_rhs(self):
        """Match the right-hand side of a dot (.) operator.

        The RHS must be a symbol token, but it is interpreted as a literal
        string (because that's what goes in the AST of Resolve.)
        """
        self.expect(grammar.symbol)
        return ast.Literal(self.matched_value, start=self.matched_start,
                           end=self.matched_end)

    # SQL subgrammar:

    def select(self):
        """First part of an SQL query."""
        # Try to match the asterisk, any or list of vars.
        if self.accept(grammar.select_any):
            return self.select_any()

        if self.accept(grammar.select_all):
            # The FROM after SELECT * is required.
            self.expect(grammar.select_from)
            return self.select_from()

        return self.select_what()

    def select_any(self):
        saved_match = self.last_match
        # Any can be either a start of a pseudosql query or the any builtin.
        if self.match(grammar.lparen):
            self.last_match = saved_match
            # The paren means we're calling 'any(...)' - the builtin.
            return self.builtin(self.matched_value)

        # An optional FROM can go after ANY.
        # "SELECT ANY FROM", "ANY FROM", "SELECT ANY" and just "ANY" all mean
        # the exact same thing. The full form of SELECT ANY FROM is preferred
        # but the shorthand is very useful for writing boolean indicators and
        # so it's worth allowing it.
        start = self.matched_start
        self.accept(grammar.select_from)

        source_expression = self.expression()

        if self.accept(grammar.select_where):
            map_expression = self.expression()
        else:
            map_expression = None

        # ORDER after ANY doesn't make any sense.
        self.reject(grammar.select_order)

        if map_expression:
            return ast.Any(source_expression, map_expression,
                           start=start, end=map_expression.end)

        return ast.Any(source_expression, start=start, end=self.matched_end)

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
        start = self.matched_start
        used_names = set()  # Keeps track of named values to prevent duplicates.
        vars = []
        for watermark in itertools.count():
            value_expression = self.expression()

            if self.accept(grammar.select_as):
                # If there's an AS then we have an explicit name for this value.
                self.expect(grammar.symbol)

                if self.matched_value in used_names:
                    return self.error(
                        "Duplicate 'AS' name %r." % self.matched_value)

                key_expression = ast.Literal(self.matched_value,
                                             start=self.matched_start,
                                             end=self.matched_wide_end)
                used_names.add(self.matched_value)
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
                                 start=value_expression.start, end=end))

            if self.accept(grammar.select_from):
                # Make ast.Bind here.
                source_expression = self.select_from()
                return ast.Map(
                    source_expression,
                    ast.Bind(*vars, start=start, end=vars[-1].end),
                    start=start,
                    end=self.matched_end)

            self.expect(grammar.comma)

    def select_from(self):
        source_expression = self.expression()
        if self.accept(grammar.select_where):
            return self.select_where(source_expression)

        if self.accept(grammar.select_order):
            return self.select_order(source_expression)

        return source_expression

    def select_where(self, source_expression):
        start = self.matched_start
        filter_expression = ast.Filter(source_expression, self.expression(),
                                       start=start, end=self.matched_end)

        if self.accept(grammar.select_order):
            return self.select_order(filter_expression)

        return filter_expression

    def select_order(self, source_expression):
        start = self.matched_start
        sort_expression = ast.Sort(source_expression, self.expression(),
                                   start=start, end=self.matched_end)

        if self.accept(grammar.select_asc):
            sort_expression.end = self.matched_end
            return sort_expression

        if self.accept(grammar.select_desc):
            return ast.Apply(
                ast.Var("reverse",
                        start=sort_expression.start,
                        end=self.matched_end),
                sort_expression,
                start=sort_expression.start,
                end=self.matched_end)

        return sort_expression

    # Builtin pseudo-function application subgrammar.

    def builtin(self, keyword):
        """Parse the pseudo-function application subgrammar."""
        keyword_start = self.matched_start
        keyword_end = self.matched_end
        self.expect(grammar.lparen)

        if self.matched_start != keyword_end:
            return self.error(
                "No whitespace allowed between function and lparen.",
                start_token=self.matched_tokens[0])

        expr_type = grammar.BUILTINS[keyword.lower()]
        arguments = [self.expression()]
        while self.accept(grammar.comma):
            arguments.append(self.expression())

        self.expect(grammar.rparen)

        if expr_type.arity and expr_type.arity != len(arguments):
            return self.error(
                "%s expects %d arguments, but was passed %d." % (
                    keyword, expr_type.arity, len(arguments)),
                start_token=self.matched_tokens[0])

        return expr_type(*arguments, start=keyword_start, end=self.matched_end)

    # If-else if-else grammar.
    def if_if(self):
        start = self.matched_start

        # Even-numbered children are conditions; odd-numbered are results.
        # Last child is the else expression.
        children = [self.expression()]

        self.expect(grammar.if_then)
        children.append(self.expression())

        while self.accept(grammar.if_else_if):
            children.append(self.expression())
            self.expect(grammar.if_then)
            children.append(self.expression())

        if self.accept(grammar.if_else):
            children.append(self.expression())
        else:
            children.append(ast.Literal(None))

        return ast.IfElse(*children, start=start, end=self.matched_end)

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
        start = self.matched_start
        if self.accept(grammar.rparen):
            # That was easy.
            return ast.Apply(func, start=start, end=self.matched_end)

        arguments = [self.expression()]
        while self.accept(grammar.comma):
            arguments.append(self.expression())

        self.expect(grammar.rparen)
        return ast.Apply(func, *arguments, start=start, end=self.matched_end)

    # Tuple grammar.

    def list(self):
        """Parse a list (tuple) which can contain any combination of types."""
        start = self.matched_start

        if self.accept(grammar.rbracket):
            return ast.Tuple(start=start, end=self.matched_end)

        elements = [self.expression()]

        while self.accept(grammar.comma):
            elements.append(self.expression())

        self.expect(grammar.rbracket)
        return ast.Tuple(*elements, start=start, end=self.matched_end)


syntax.Syntax.register_parser(Parser, shorthand="dottysql")
