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
This module implements the DottySQL lexer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import collections
import re

from efilter import errors


class Pattern(collections.namedtuple("Pattern",
                                     "name states regex action next_state")):
    """Defines a token pattern for the tokenizer.

    Arguments:
        name: The name of the pattern will be used to name the token.
        states: The pattern will only be applied if we're in one these states.
        regex: A regular expression to try and match from the current point.
        action: The handler to call.
        next_state: The next state we transition to if this pattern matched.
    """

    def __new__(cls, name, states, regex, action, next_state):
        return super(Pattern, cls).__new__(
            cls, name, states,
            re.compile(regex, re.DOTALL | re.M | re.S | re.U),
            action, next_state)


class Token(collections.namedtuple("Token",
                                   "name value start end")):
    """One token from the tokenizer. Corresponds to a pattern, but has value."""

    def __repr__(self):
        return "Token(name='%s', value='%s', start=%d, end=%d)" % (
            self.name, self.value, self.start, self.end)


class Lexer(object):
    """Context-free lexer for DottySQL.

    This is a very basic tokenizer that outputs a stream of tokens which can be
    either a literal, a symbol, a param or brackets/parens.

    Examples:

    SELECT proc.pid AS pid, proc.command FROM pslist(10) WHERE proc.pid == 10
    # Should yield:
    S(SELECT) S(proc) S(.) S(pid) S(AS) COMMA S(proc) S(.) S(command) S(FROM)
    S(pslist) LPAREN L(10) RPAREN S(WHERE) S(proc) S(.) S(pid) S(==) L(10)
    """

    patterns = (
        # Parens/brackets and separators.
        Pattern("lparen", ("INITIAL,"), r"(?P<token>\()", "emit", None),
        Pattern("rparen", ("INITIAL,"), r"(?P<token>\))", "emit", None),
        Pattern("lbracket", ("INITIAL,"), r"(?P<token>\[)", "emit", None),
        Pattern("rbracket", ("INITIAL,"), r"(?P<token>\])", "emit", None),
        Pattern("comma", ("INITIAL,"), r"(?P<token>,)", "emit", None),

        # Built-time parameters.
        Pattern("param", ("INITIAL",),
                r"\{(?P<token>[a-z_0-9]*)\}", "emit_param", None),
        Pattern("param", ("INITIAL,"), r"(?P<token>\?)", "emit_param", None),

        # Numberic literals.
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>\d+\.\d+)", "emit_float", None),
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>0\d+)", "emit_oct", None),
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>0x[0-9a-zA-Z]+)", "emit_hex", None),
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>\d+)", "emit_int", None),

        # String literals.
        Pattern(None, ("INITIAL",), r"\"", "string_start", "STRING"),
        Pattern(None, ("INITIAL",), r"'", "string_start", "SQ_STRING"),

        Pattern("literal", ("STRING",), "\"", "string_end", None),
        Pattern(None, ("STRING",), r"\\(.)", "string_escape", None),
        Pattern(None, ("STRING",), r"([^\\\"]+)", "string_append", None),

        Pattern("literal", ("SQ_STRING",), "'", "string_end", None),
        Pattern(None, ("SQ_STRING",), r"\\(.)", "string_escape", None),
        Pattern(None, ("SQ_STRING",), r"([^\\']+)", "string_append", None),

        # Prefer to match symbols only as far as they go, should they be
        # followed by a literal with no whitespace in between.
        Pattern("symbol", ("INITIAL",),
                r"([a-zA-Z_][\w_]*)", "emit", None),

        # Special characters are also valid as a symbol, but we won't match them
        # eagerly so as to not swallow valid literals that follow.
        Pattern("symbol", ("INITIAL",),
                r"([-+*\/=~\.><\[\]!:]+)", "emit", None),

        # Whitespace is ignored.
        Pattern(None, ("INITIAL",), r"(\s+)", None, None),
    )

    def __init__(self, query):
        self.buffer = query
        self.state_stack = ["INITIAL"]
        self.current_token = None
        self._position = 0
        self.limit = len(query)
        self.lookahead = collections.deque()
        self._param_idx = 0

        # Make sure current_token starts containing something.
        self.next_token()

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

    def __iter__(self):
        """Look ahead from current position."""
        yield self.current_token

        for token in self.lookahead:
            yield token

        while True:
            token = self._parse_next_token()
            if not token:
                return

            self.lookahead.append(token)
            yield token

    def peek(self, steps=1):
        """Look ahead, doesn't affect current_token and next_token."""

        try:
            tokens = iter(self)
            for _ in xrange(steps):
                next(tokens)

            return next(tokens)
        except StopIteration:
            return None

    def skip(self, steps=1):
        for _ in xrange(steps):
            self.next_token()

    def next_token(self):
        """Returns the next logical token.

        Will trigger parsing if it has to.
        """
        if self.lookahead:
            self.current_token = self.lookahead.popleft()
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

    def next_pattern(self):
        """Parses the next pattern by matching each in turn."""
        current_state = self.state_stack[-1]
        position = self._position
        for pattern in self.patterns:
            if current_state not in pattern.states:
                continue

            m = pattern.regex.match(self.buffer, position)
            if not m:
                continue

            position = m.end()
            token = None

            if pattern.next_state:
                self.state_stack.append(pattern.next_state)

            if pattern.action:
                callback = getattr(self, pattern.action, None)
                if callback is None:
                    raise RuntimeError(
                        "No method defined for pattern action %s!" %
                        pattern.action)

                if "token" in m.groups():
                    value = m.group("token")
                else:
                    value = m.group(0)
                token = callback(string=value, match=m,
                                 pattern=pattern)

            self._position = position

            return token

        self.error("Don't know how to match next. Did you forget quotes?",
                   start=self._position, end=self._position + 1)

    def error(self, message, start, end=None):
        """Raise a nice error, with the token highlighted."""
        raise errors.EfilterParseError(
            query=self.buffer, start=start, end=end, message=message)

    # State handlers:

    def emit(self, string, match, pattern, **_):
        """Emits a token using the current pattern match and pattern label."""
        return Token(name=pattern.name, value=string, start=match.start(),
                     end=match.end())

    def emit_param(self, match, pattern, **_):
        param_name = match.group(1)

        if not param_name or param_name == "?":
            param_name = self._param_idx
            self._param_idx += 1
        elif param_name and re.match(r"^\d+$", param_name):
            param_name = int(param_name)

        return Token(name=pattern.name, value=param_name, start=match.start(),
                     end=match.end())

    def emit_int(self, string, match, pattern, **_):
        return Token(name=pattern.name, value=int(string), start=match.start(),
                     end=match.end())

    def emit_oct(self, string, match, pattern, **_):
        return Token(name=pattern.name, value=int(string, 8),
                     start=match.start(), end=match.end())

    def emit_hex(self, string, match, pattern, **_):
        return Token(name=pattern.name, value=int(string, 16),
                     start=match.start(), end=match.end())

    def emit_float(self, string, match, pattern, **_):
        return Token(name=pattern.name, value=float(string),
                     start=match.start(), end=match.end())

    # String parsing:

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

    def string_end(self, pattern, match, **_):
        self.pop_state()
        return Token(name=pattern.name, value=self.string,
                     start=self.string_position, end=match.end())
