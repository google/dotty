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
This module implements a reusable expression tokenizer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import collections
import re
import six

from efilter import errors

from efilter.parsers.common import grammar


class Pattern(collections.namedtuple("Pattern",
                                     "name states regex action next_state")):
    """Defines a token pattern for the tokenizer.

    Arguments:
        name: The name of the pattern will be used to name the token.
        states: The pattern will only be applied if we're in one these states.
        regex: A regular expression to try and match from the current point.
            A named matched group 'token' will be saved in Token.value.
        action: The handler to call.
        next_state: The next state we transition to if this pattern matched.
    """

    def __new__(cls, name, states, regex, action, next_state):
        return super(Pattern, cls).__new__(
            cls, name, states,
            re.compile(regex, re.DOTALL | re.M | re.S | re.U),
            action, next_state)


class LazyTokenizer(object):
    """Configurable tokenizer usable with most expression grammars.

    This class is directly usable, and will, by default, produce tokens for
    string and number literals, parens, brackets, commas and words (symbols).

    Notes on performance:
        The runtime complexity grows with the number of patterns (m) and the
        number of tokens (n) in source. It is O(n*m) in the worst case.

        The tokenizer is lazy, and uses a deque to cache parsed tokens which
        haven't been skipped yet. When using 'peek' without 'skip' all tokens
        have to be cached, and this leads to O(n) memory complexity!

    Extending the tokenizer:
        This class is capable of tokenizing most any sane expression language,
        but can be further extended to (1) yield more specific token names for
        certain grammar (e.g. distinguishing between symbols and operators),
        as well as (2) supporting further tokens, such as curly braces.

        In the majority of cases, adding more patterns will be sufficient. For
        example, to support curly braces, one would add the following to
        DEFAULT_PATTERNS:

            Pattern("lbrace", # Give the token a new name.
                    ("INITIAL",), # Match this only if you're not in a string.
                    r"(?P<token>\\{)", # The regex should match an lbrace, and
                                      # capture it in the group named 'token'.
                    "emit", # This will yield a Token(name='lbrace', value='{').
                    None, # Matching an lbrace doesn't change the state.
            ),
            Pattern("rbrace", ("INITIAL",), r"(?P<token>\\})", "emit", None)

        For more complex use cases, it may be necessary to implement additional
        actions, which are just instance methods. Take a look at how string
        literals are implemented (string_start, string_end) for an example.

    Built-in actions:
        emit: Will emit a token with the supplied name and value set to whatever
            the named match group 'token' contains.
        emit_param: The tokenizer will emit a parse-time parameter for
            interpolation by a parser. The parameter token can be indexed,
            keyed on a string, or both. Indexing happens automatically, starting
            from 0.
        emit_int: The tokenizer will emit an integer obtained by interpreting
            the matched substring as an integer in base 10.
        emit_hex: Same as 'emit_int' but base 16.
        emit_oct: Same as 'emit_int' but base 8.
        emit_float: Same as 'emit_int' but emits a base 10 float.
        string_end: Emits a token with the last matched string.

    Public interface:
        next_token: Returns the next token and advances the tokenizer.
        skip: Skips N tokens ahead, without returning them.
        peek: Looks ahead over N tokens WITHOUT advancing the tokenizer. This
            fills up the token lookahead queue with N tokens - avoid supplying
            large values of N.
        __iter__: Returns an iterator that doesn't advance the tokenizer (
            same as calling peek() with increasing values of N). This can fill
            up the token queue quickly and should not be the primary interface.

    Arguments:
        source: Source string that will be lexed.
        patterns (optional): Overrides self.DEFAULT_PATTERNS
    """

    # Used if no patterns are supplied to the constructor. Subclasses can
    # override.
    DEFAULT_PATTERNS = (
        # Parens/brackets and separators.
        Pattern("lparen", ("INITIAL,"), r"(?P<token>\()", "emit", None),
        Pattern("rparen", ("INITIAL,"), r"(?P<token>\))", "emit", None),
        Pattern("lbracket", ("INITIAL,"), r"(?P<token>\[)", "emit", None),
        Pattern("rbracket", ("INITIAL,"), r"(?P<token>\])", "emit", None),
        Pattern("comma", ("INITIAL,"), r"(?P<token>,)", "emit", None),

        # Built-time parameters.
        Pattern("param", ("INITIAL",), r"\{(?P<token>[a-z_0-9]*)\}",
                "emit_param", None),
        Pattern("param", ("INITIAL,"), r"(?P<token>\?)", "emit_param", None),

        # Numeric literals.
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>\d+\.\d+)", "emit_float", None),
        Pattern("literal", ("INITIAL,"), r"(?P<token>0\d+)", "emit_oct", None),
        Pattern("literal", ("INITIAL,"),
                r"(?P<token>0x[0-9a-zA-Z]+)", "emit_hex", None),
        Pattern("literal", ("INITIAL,"), r"(?P<token>\d+)", "emit_int", None),

        # String literals.
        Pattern(None, ("INITIAL",), r"\"", "string_start", "STRING"),
        Pattern(None, ("INITIAL",), r"'", "string_start", "SQ_STRING"),

        Pattern("literal", ("STRING",), "\"", "string_end", None),
        Pattern(None, ("STRING",), r"\\(.)", "string_escape", None),
        Pattern(None, ("STRING",), r"([^\\\"]+)", "string_append", None),

        Pattern("literal", ("SQ_STRING",), "'", "string_end", None),
        Pattern(None, ("SQ_STRING",), r"\\(.)", "string_escape", None),
        Pattern(None, ("SQ_STRING",), r"([^\\']+)", "string_append",
                None),

        # Prefer to match symbols only as far as they go, should they be
        # followed by a literal with no whitespace in between.
        Pattern("symbol", ("INITIAL",), r"([a-zA-Z_][\w_]*)", "emit", None),

        # Special characters are also valid as a symbol, but we won't match them
        # eagerly so as to not swallow valid literals that follow.
        Pattern("symbol", ("INITIAL",), r"([-+*\/=~\.><\[\]!:]+)", "emit",
                None),

        # Whitespace is ignored.
        Pattern(None, ("INITIAL",), r"(\s+)", None, None),
    )

    # Ordered instances of Pattern.
    patterns = None

    # A deque with tokens that have been parsed, but haven't been skipped yet.
    lookahead = None

    # The input string being tokenized.
    source = None

    # List of states, as determined by rules in 'patterns'.
    state_stack = None

    # The length of 'source'.
    limit = None

    # The latest matched literal string.
    string = None

    def __init__(self, source, patterns=None):
        self.source = source
        self.state_stack = ["INITIAL"]
        self.current_token = None
        self._position = 0
        self.limit = len(source)
        self.lookahead = collections.deque()
        self._param_idx = 0

        self.patterns = patterns or self.DEFAULT_PATTERNS

        # Make sure current_token starts containing something.
        self.next_token()

    # API for the parser:

    @property
    def position(self):
        """Returns the logical position (unaffected by lookahead)."""
        if self.lookahead:
            return self.lookahead[0].start

        return self._position

    def __iter__(self):
        """Look ahead from current position."""
        if self.current_token is not None:
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
            for _ in six.moves.range(steps):
                next(tokens)

            return next(tokens)
        except StopIteration:
            return None

    def skip(self, steps=1):
        """Skip ahead by 'steps' tokens."""
        for _ in six.moves.range(steps):
            self.next_token()

    def next_token(self):
        """Returns the next logical token, advancing the tokenizer."""
        if self.lookahead:
            self.current_token = self.lookahead.popleft()
            return self.current_token

        self.current_token = self._parse_next_token()
        return self.current_token

    # Implementation:

    def _pop_state(self, **_):
        try:
            self.state_stack.pop()
        except IndexError:
            self._error("Pop state called on an empty stack.", self.position)

    def _parse_next_token(self):
        """Will parse patterns until it gets to the next token or EOF."""
        while self._position < self.limit:
            token = self._next_pattern()
            if token:
                return token

        return None

    def _next_pattern(self):
        """Parses the next pattern by matching each in turn."""
        current_state = self.state_stack[-1]
        position = self._position
        for pattern in self.patterns:
            if current_state not in pattern.states:
                continue

            m = pattern.regex.match(self.source, position)
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

        self._error("Don't know how to match next. Did you forget quotes?",
                    start=self._position, end=self._position + 1)

    def _error(self, message, start, end=None):
        """Raise a nice error, with the token highlighted."""
        raise errors.EfilterParseError(
            source=self.source, start=start, end=end, message=message)

    # Actions:

    def emit(self, string, match, pattern, **_):
        """Emits a token using the current pattern match and pattern label."""
        return grammar.Token(name=pattern.name, value=string,
                             start=match.start(), end=match.end())

    def emit_param(self, match, pattern, **_):
        param_name = match.group(1)

        if not param_name or param_name == "?":
            param_name = self._param_idx
            self._param_idx += 1
        elif param_name and re.match(r"^\d+$", param_name):
            param_name = int(param_name)

        return grammar.Token(name=pattern.name, value=param_name,
                             start=match.start(), end=match.end())

    def emit_int(self, string, match, pattern, **_):
        return grammar.Token(name=pattern.name, value=int(string),
                             start=match.start(), end=match.end())

    def emit_oct(self, string, match, pattern, **_):
        return grammar.Token(name=pattern.name, value=int(string, 8),
                             start=match.start(), end=match.end())

    def emit_hex(self, string, match, pattern, **_):
        return grammar.Token(name=pattern.name, value=int(string, 16),
                             start=match.start(), end=match.end())

    def emit_float(self, string, match, pattern, **_):
        return grammar.Token(name=pattern.name, value=float(string),
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
        self._pop_state()
        return grammar.Token(name=pattern.name, value=self.string,
                             start=self.string_position, end=match.end())
