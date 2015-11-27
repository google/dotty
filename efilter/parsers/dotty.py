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
Canonical EFILTER syntax parser.

This is the new recommended EFILTER syntax - EFILTER will now default to dotty
in most cases, and the legacy syntax (slashy) is going away soon.

Dotty is a simple expression language with a character-stream defined grammar
(as are most languages). It can express most of the constructs available in
the EFILTER AST (although some experimental expression classes may not always
have corresponding syntax). There is also a formatter for it (AST to source) in
efilter.transforms.asdotty.

The code below consists of a Tokenizer, which is a basic state machine, a
precedence climbing Parser, and a number of functions that normalize certain
constucts into actual EFILTER AST.

Assorted examples:

    # Most arithmetic expression behave as they would in Python or C:
    (10 + 5 * (20 - 10)) in (10, 20, 30) and not 5 > 10

    # Vars (vars) and literals are strongly typed:
    5 isa Number  # => True

    # Complicated map-forms (. and where) are supported:
    any Process.parent where (pid > 10)
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import collections
import re

from efilter import errors
from efilter import ast
from efilter import syntax

from efilter.transforms import normalize

# Transformation functions, for expressions that don't directly map to
# something in the AST.


def ComplementEquivalence(*args, **kwargs):
    return ast.Complement(
        ast.Equivalence(*args, **kwargs), **kwargs)


def ComplementMembership(*args, **kwargs):
    return ast.Complement(
        ast.Membership(*args, **kwargs), **kwargs)


def ReverseStrictOrderedSet(*args, **kwargs):
    return ast.StrictOrderedSet(*reversed(args), **kwargs)


def ReversePartialOrderedSet(*args, **kwargs):
    return ast.PartialOrderedSet(*reversed(args), **kwargs)


def NegateValue(*args, **kwargs):
    return ast.Product(
        ast.Literal(-1),
        *args,
        **kwargs)


def FlattenIsInstance(*args, **kwargs):
    if not isinstance(args[0], ast.Var):
        raise ValueError(
            "'isa' must be followed by a type. Got %s." % args[0])
    return ast.IsInstance(args[0].value, **kwargs)


def TransformAny(where, **kwargs):
    if not isinstance(where, ast.Within):
        raise ValueError("'any' must be followed by 'where'.")
    context, expr = where.children
    return ast.Any(context, expr, **kwargs)


def TransformEach(where, **kwargs):
    if not isinstance(where, ast.Within):
        raise ValueError("'each' must be followed by 'where'.")
    context, expr = where.children
    return ast.Each(context, expr, **kwargs)


def TransformFilter(where, **kwargs):
    if not isinstance(where, ast.Within):
        raise ValueError("'filter' must be followed by 'where'.")
    context, expr = where.children
    return ast.Filter(context, expr, **kwargs)


def TransformSort(where, **kwargs):
    if not isinstance(where, ast.Within):
        raise ValueError("'sort' must be followed by 'where'.")
    context, expr = where.children
    return ast.Sort(context, expr, **kwargs)


def TransformMap(where, **kwargs):
    if not isinstance(where, ast.Within):
        raise ValueError("'map' must be followed by 'where'.")
    context, expr = where.children
    return ast.Map(context, expr, **kwargs)


class WhereStub(object):
    """Placeholder for map/sort/etc. expressions only used during parsing."""

    children = None
    start = None
    end = None

    def __init__(self, lhs, rhs, start=None, end=None):
        self.children = (lhs, rhs)
        self.start = start
        self.end = end


# Operators - infix and prefix.

Operator = collections.namedtuple("Operator",
                                  "precedence assoc handler docstring")

# The order of precedence matters for generated matching rules, which is why
# this is an OrderedDict.
INFIX = collections.OrderedDict([
    ("+", Operator(precedence=4, assoc="left", handler=ast.Sum,
                   docstring="Arithmetic addition.")),
    ("-", Operator(precedence=4, assoc="left", handler=ast.Difference,
                   docstring="Arithmetic subtraction.")),
    ("*", Operator(precedence=6, assoc="left", handler=ast.Product,
                   docstring="Arithmetic multiplication.")),
    ("/", Operator(precedence=6, assoc="left", handler=ast.Quotient,
                   docstring="Arithmetic division.")),
    ("==", Operator(precedence=3, assoc="left",
                    handler=ast.Equivalence,
                    docstring="Equivalence (same as 'is').")),
    ("!=", Operator(precedence=3, assoc="left",
                    handler=ComplementEquivalence,
                    docstring="Inequivalence (same as 'is not').")),
    ("not in", Operator(precedence=3, assoc="left",
                        handler=ComplementMembership,
                        docstring="Left-hand operand is not in list.")),
    ("in", Operator(precedence=3, assoc="left",
                    handler=ast.Membership,
                    docstring="Left-hand operand is in list.")),
    ("isa", Operator(precedence=3, assoc="left",
                     handler=ast.IsInstance,
                     docstring="Matching object must be instance of type.")),
    (">=", Operator(precedence=3, assoc="left",
                    handler=ast.PartialOrderedSet,
                    docstring="Equal-or-greater-than.")),
    ("<=", Operator(precedence=3, assoc="left",
                    handler=ReversePartialOrderedSet,
                    docstring="Equal-or-less-than.")),
    (">", Operator(precedence=3, assoc="left",
                   handler=ast.StrictOrderedSet,
                   docstring="Greater-than.")),
    ("<", Operator(precedence=3, assoc="left",
                   handler=ReverseStrictOrderedSet,
                   docstring="Less-than.")),
    ("where", Operator(precedence=2, assoc="left",
                       handler=ast.Map,
                       docstring="VALUE where SUBEXPRESSION")),
    (".", Operator(precedence=7, assoc="left",
                   handler=ast.Map,
                   docstring="LHS.(EXPR) -> evaluate EXPR with LHS as vars.")),
    ("and", Operator(precedence=1, assoc="left",
                     handler=ast.Intersection,
                     docstring="Logical AND.")),
    ("or", Operator(precedence=0, assoc="left", handler=ast.Union,
                    docstring="Logical OR.")),
    ("=~", Operator(precedence=3, assoc="left",
                    handler=ast.RegexFilter,
                    docstring="Left-hand operand where regex.")),
])


PREFIX = {
    "not": Operator(precedence=6, assoc=None, handler=ast.Complement,
                    docstring="Logical NOT."),
    "-": Operator(precedence=5, assoc=None, handler=NegateValue,
                  docstring="Unary -."),
    "any": Operator(precedence=2, assoc=None, handler=TransformAny,
                    docstring=(
                        "any REPEATED.(EXPR) -> return true if EXPR is true "
                        "for any value of REPEATED.")),
    "each": Operator(precedence=2, assoc=None, handler=TransformEach,
                     docstring=(
                         "each REPEATED.(EXPR) -> return true if EXPR is true "
                         "for every value of REPEATED.")),
    "find": Operator(precedence=2, assoc=None, handler=TransformFilter,
                     docstring=(
                         "find REPEATED.(EXPR) -> use EXPR to filter "
                         "REPEATED.")),
    "sort": Operator(precedence=2, assoc=None, handler=TransformSort,
                     docstring=(
                         "sort REPEATED.(EXPR) -> use EXPR to sort "
                         "REPEATED.")),
    "map": Operator(precedence=2, assoc=None, handler=TransformMap,
                    docstring=(
                        "map REPEATED.(EXPR) -> use EXPR to transform "
                        "REPEATED."))
}


UNSAFE_PATTERN = re.compile(r".*?\w$")


def CompilePattern(pattern):
    """Compile the operator token into an appropriate regex."""
    # Patterns that look like they might conflict with symbols or variables
    # need to have a space immediately after.
    if UNSAFE_PATTERN.match(pattern):
        # print "sdgsdggg", pattern
        return "(%s) " % re.escape(pattern)

    return "(%s)" % re.escape(pattern)


class Token(object):
    """Represents a result from the tokenizer."""

    def __init__(self, name, value, start, end):
        self.name = name
        self.value = value
        self.start = start
        self.end = end

    def __repr__(self):
        return "Token(name='%s', value='%s', start=%d, end=%d)" % (
            self.name, self.value, self.start, self.end)


class Pattern(object):
    """A token pattern.

    Args:
      state_regex: If this regular expression where the current state this
                   rule is considered.
      regex: A regular expression to try and match from the current point.
      actions: A command separated list of method names in the Lexer to call.
      next_state: The next state we transition to if this Pattern where.
      flags: flags to re.compile.
    """

    def __init__(self, label, state_regex, regex, actions, next_state,
                 flags=re.I):
        self.state_regex = re.compile(
            state_regex, re.DOTALL | re.M | re.S | re.U | flags)
        self.regex = re.compile(regex, re.DOTALL | re.M | re.S | re.U | flags)
        self.label = label
        self.re_str = regex

        if actions:
            self.actions = actions.split(",")
        else:
            self.actions = []

        self.next_state = next_state


class Tokenizer(object):
    """Context-free tokenizer for the efilter language.

    This is a very basic pattern-based tokenizer. Any rule from patterns
    will try to match the next token in the buffer if its state_regex where
    the current state. Only meaningful tokens are emitted (not whitespace.)
    """
    _infix_patterns = [
        Pattern("infix", "INITIAL", CompilePattern(pattern), "emit", None)
        for pattern in INFIX.keys()
    ]

    _prefix_patterns = [
        Pattern("prefix", "INITIAL", CompilePattern(pattern), "emit", None)
        for pattern in PREFIX.keys()
    ]

    _patterns = [
        # Keywords, operators and symbols
        Pattern("lparen", "INITIAL", r"(\()",
                "emit", None),
        Pattern("rparen", "INITIAL", r"(\))",
                "emit", None),
        Pattern("comma", "INITIAL", r"(,)",
                "emit", None),
        Pattern("symbol", "INITIAL", r"([a-z_][a-z_0-9]+)", "emit", None),
        Pattern("param", "INITIAL", r"\{([a-z_0-9]*)\}", "emit_param", None),
        Pattern("param", "INITIAL", r"(\?)", "emit_param", None),

        # Numeric literals
        Pattern("literal", "INITIAL", r"(\d+\.\d+)", "emit_float", None),
        Pattern("literal", "INITIAL", r"(0x[0-9a-zA-Z]+)", "emit_int16", None),
        Pattern("literal", "INITIAL", r"(\d+)", "emit_int", None),

        # String literals
        Pattern(None, "INITIAL", r"(\")", "string_start", "STRING"),
        Pattern(None, "INITIAL", r"(')", "string_start", "SQ_STRING"),

        Pattern("literal", "STRING", "(\")", "pop_state,emit_string", None),
        Pattern(None, "STRING", r"\\(.)", "string_escape", None),
        Pattern(None, "STRING", r"([^\\\"]+)", "string_append", None),

        Pattern("literal", "SQ_STRING", "(')", "pop_state,emit_string", None),
        Pattern(None, "SQ_STRING", r"\\(.)", "string_escape", None),
        Pattern(None, "SQ_STRING", r"([^\\']+)", "string_append", None),

        # Whitespace is ignored.
        Pattern(None, ".", r"(\s+)", None, None),
    ]

    patterns = _infix_patterns + _prefix_patterns + _patterns

    def __init__(self, query):
        self.buffer = query
        self.state_stack = ["INITIAL"]
        self.current_token = None
        self._position = 0
        self.limit = len(query)
        self.lookahead = []
        self._param_idx = 0

    @property
    def position(self):
        """Returns the logical position (unaffected by lookahead)."""
        if self.lookahead:
            return self.lookahead[0].start

        return self._position

    def pop_state(self, **_):
        try:
            self.state_stack.pop()
        except IndexError:
            self.error("Pop state called on an empty stack.", self.position)

    def next_token(self):
        """Returns the next logical token.

        Will trigger parsing if it has to.
        """
        if self.lookahead:
            self.current_token = self.lookahead.pop(0)
            return self.current_token

        self.current_token = self._parse_next_token()
        return self.current_token

    def _parse_next_token(self):
        """Will parse patterns until it gets to the next token or EOF."""
        while self._position < self.limit:
            token = self.next_pattern()
            if token:
                return token

        return None

    def peek(self, steps=1):
        """Look ahead, doesn't affect current_token and next_token."""
        while len(self.lookahead) < steps:
            token = self._parse_next_token()
            if token is None:
                return None

            self.lookahead.append(token)

        return self.lookahead[steps - 1]

    def parse(self):
        """Yield every token in turn."""
        while self._position < self.limit:
            token = self.next_token()
            if not token:
                return

            yield token

    def next_pattern(self):
        """Parses the next pattern by matching each in turn."""
        current_state = self.state_stack[-1]
        position = self._position
        for pattern in self.patterns:
            if not pattern.state_regex.match(current_state):
                continue

            m = pattern.regex.match(self.buffer, position)
            if not m:
                continue

            position = m.end()
            token = None

            if pattern.next_state:
                self.state_stack.append(pattern.next_state)

            for action in pattern.actions:
                callback = getattr(self, action, None)
                if callback is None:
                    raise RuntimeError(
                        "No method defined for pattern action %s!" % action)

                token = callback(string=m.group(1), match=m, pattern=pattern)

            self._position = position

            return token

        self.error("Don't know how to match next. Did you forget quotes?",
                   start=self.position, end=self.position + 1)

    def error(self, message, start, end=None):
        """Print a nice error."""
        raise errors.EfilterParseError(
            query=self.buffer, start=start, end=end, message=message)

    def emit(self, string, match, pattern, **_):
        """Emits a token using the current pattern match and pattern label."""
        return Token(name=pattern.label, value=string, start=match.start(),
                     end=match.end())

    def emit_param(self, match, pattern, **_):
        param_name = match.group(1)

        if not param_name or param_name == "?":
            param_name = self._param_idx
            self._param_idx += 1

        return Token(name=pattern.label, value=param_name, start=match.start(),
                     end=match.end())

    def emit_int(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=int(string), start=match.start(),
                     end=match.end())

    def emit_int16(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=int(string, 16),
                     start=match.start(), end=match.end())

    def emit_float(self, string, match, pattern, **_):
        return Token(name=pattern.label, value=float(string),
                     start=match.start(), end=match.end())

    # String parsing

    def string_start(self, match, **_):
        self.string = ""
        self.string_position = match.start()

    def string_escape(self, string, match, **_):
        if match.group(1) in "'\"rnbt":
            self.string += string.decode("string_escape")
        else:
            self.string += string

    def string_append(self, string="", **_):
        self.string += string

    def emit_string(self, pattern, match, **_):
        return Token(name=pattern.label, value=self.string,
                     start=self.string_position, end=match.end())


class Parser(syntax.Syntax):
    """Parses the efilter language into the query AST.

    This is a basic precedence-climbing parser with support for prefix
    operators and a few special cases for list literals and such.
    """

    def __init__(self, original, params=None):
        super(Parser, self).__init__(original)

        self.tokenizer = Tokenizer(self.original)

        if isinstance(params, list):
            self.params = {}
            for idx, val in enumerate(params):
                self.params[idx] = val
        else:
            self.params = params

    def _handle_expr(self, operator, *args, **kwargs):
        try:
            return operator.handler(*args, **kwargs)
        except ValueError as e:
            return self.error(e.message,
                              start_token=args[0])

    def _replace_param(self, token):
        param_name = token.value
        value = self.params.get(param_name, None)
        if value is None:
            return self.error("No value provided for param %s" % param_name,
                              token)

        return value

    def next_atom(self):
        token = self.tokenizer.next_token()

        if token is None:
            return self.error("Unexpected end of input.")

        if token.name == "infix":
            if token.value == "-":
                # As it turns out, minus signs can be prefix operators! Who
                # knew? Certainly not the tokenizer.
                token.name = "prefix"
            else:
                return self.error("Unexpected infix operator.", token)

        if token.name == "prefix":
            operator = PREFIX[token.value]
            lhs = self.next_atom()
            rhs = self.next_expression(lhs, operator.precedence)
            return self._handle_expr(operator, rhs, start=token.start,
                                     end=rhs.end)

        if token.name == "literal":
            return ast.Literal(token.value, start=token.start,
                               end=token.end)

        if token.name == "param":
            return ast.Literal(self._replace_param(token),
                               start=token.start, end=token.end)

        if token.name == "symbol":
            return ast.Var(token.value, start=token.start,
                           end=token.end)

        if token.name == "lparen":
            # Parentheses can denote subexpressions or lists. Lists have at
            # least one comma before rparen (just like Python).
            lhs = self.next_atom()
            expr = self.next_expression(lhs, 0)
            if self.tokenizer.current_token is None:
                return self.error("End of input before closing parenthesis.",
                                  token)

            if self.tokenizer.peek().name == "comma":
                # It's a list, not an expression. Build it out as a literal.
                if not isinstance(lhs, ast.Literal):
                    return self.error(
                        "Non-literal value in list.", lhs)

                self.tokenizer.next_token()
                vals = [lhs.value]

                while (self.tokenizer.current_token and
                       self.tokenizer.current_token.name == "comma"):
                    atom = self.next_atom()
                    if not isinstance(atom, ast.Literal):
                        return self.error(
                            "Non-literal value in list", atom)
                    vals.append(atom.value)
                    self.tokenizer.next_token()

                if (self.tokenizer.current_token is None or
                        self.tokenizer.current_token.name != "rparen"):
                    self.error("Lists must end with a closing paren.",
                               self.tokenizer.current_token)

                return ast.Literal(tuple(vals), start=token.start,
                                   end=self.tokenizer.position)

            elif self.tokenizer.peek().name != "rparen":
                # We got here because there's still some stuff left to parse
                # and the next token is not an rparen. That can mean that an
                # infix operator is missing or that the parens are unmatched.
                # Decide which is more likely and raise the appropriate error.
                lparens = 1
                rparens = 0
                lookahead = 2
                while self.tokenizer.peek(lookahead):
                    if self.tokenizer.peek(lookahead).name == "lparen":
                        lparens += 1
                    elif self.tokenizer.peek(lookahead).name == "rparen":
                        rparens += 1

                    lookahead += 1

                if lparens > rparens:
                    return self.error("Ummatched left parenthesis.", token)
                else:
                    next_token = self.tokenizer.peek()
                    return self.error(
                        "Was not expecting %s here." % next_token.value,
                        next_token)

            self.tokenizer.next_token()
            return expr

        return self.error("Cannot handle token %s." % token, token)

    def next_expression(self, lhs, min_precedence):
        # This loop will spin as long as:
        # 1: There is a next token.
        # 2: It is an infix operator.
        # 3: Its precedence is higher than min_precedence.
        while self.tokenizer.peek():
            token = self.tokenizer.peek()

            if token.name != "infix":
                break

            operator = INFIX[token.value]
            if operator.precedence < min_precedence:
                break

            # We're a match - consume the next token.
            self.tokenizer.next_token()

            rhs = self.next_atom()
            next_min_precedence = operator.precedence
            if operator.assoc == "LEFT":
                next_min_precedence += 1

            # Let's see if the next infix operator (if any) is of higher
            # precedence than we are.
            while (self.tokenizer.peek() and
                   self.tokenizer.peek().name == "infix"):
                next_token = self.tokenizer.peek()
                next_operator = INFIX[next_token.value]
                if next_operator.precedence < next_min_precedence:
                    break
                rhs = self.next_expression(rhs, next_operator.precedence)

            lhs = self._handle_expr(operator, lhs, rhs, start=lhs.start,
                                    end=rhs.end)

        return lhs

    def parse(self):
        result = self.next_expression(self.next_atom(), 0)
        # If we didn't consume the whole query then raise.
        if self.tokenizer.peek():
            token = self.tokenizer.peek()
            return self.error(
                "Unexpected %s '%s'. Were you looking for an operator?" %
                (token.name, token.value),
                token)

        return result

    @property
    def root(self):
        dirty_ast = self.parse()
        return normalize.normalize(dirty_ast)

    def error(self, message, start_token=None, end_token=None):
        start = self.tokenizer.position
        end = start + 20
        if start_token:
            start = start_token.start
            end = start_token.end

        if end_token:
            end = end_token.end

        raise errors.EfilterParseError(
            query=self.original, start=start, end=end, message=message,
            token=start_token)


syntax.Syntax.register_parser(Parser, shorthand="dotty")
