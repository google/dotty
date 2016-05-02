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
This module implements a parser that manages tokenizer output based on rules.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import errors

from efilter.parsers.common import grammar


class TokenStream(object):
    """Manages and enforces grammar over tokenizer output.

    Most recursive descent parsers need a mechanism to accept, reject, expect
    or peek at the next token based on matching loging supplied by grammar
    functions. This class manages the tokenizer for the parser, and enforces
    the expectations set by grammar.

    Arguments:
        tokenizer: Must support the tokenizer interface (skip and peek).
    """

    tokenizer = None
    matched = None

    def __init__(self, tokenizer=None):
        self.tokenizer = tokenizer

    def match(self, f, *args):
        """Match grammar function 'f' against next token and set 'self.matched'.

        Arguments:
            f: A grammar function - see efilter.parsers.common.grammar. Must
                return TokenMatch or None.
            args: Passed to 'f', if any.

        Returns:
            Instance of efilter.parsers.common.grammar.TokenMatch or None.

        Comment:
            If a match is returned, it will also be stored in self.matched.
        """
        try:
            match = f(self.tokenizer, *args)
        except StopIteration:
            # The grammar function might have tried to access more tokens than
            # are available. That's not really an error, it just means it didn't
            # match.
            return

        if match is None:
            return

        if not isinstance(match, grammar.TokenMatch):
            raise TypeError("Invalid grammar function %r returned %r."
                            % (f, match))

        self.matched = match
        return match

    def accept(self, f, *args):
        """Like 'match', but consume the token (tokenizer advances.)"""
        match = self.match(f, *args)
        if match is None:
            return

        self.tokenizer.skip(len(match.tokens))
        return match

    def reject(self, f, *args):
        """Like 'match', but throw a parse error if 'f' matches.

        This is useful when a parser wants to be strict about specific things
        being prohibited. For example, DottySQL bans the use of SQL keywords as
        variable names.
        """
        match = self.match(f, *args)
        if match:
            token = self.peek(0)
            raise errors.EfilterParseError(
                query=self.tokenizer.source, token=token,
                message="Was not expecting a %s here." % token.name)

    def expect(self, f, *args):
        """Like 'accept' but throws a parse error if 'f' doesn't match."""
        match = self.accept(f, *args)
        if match:
            return match

        try:
            func_name = f.func_name
        except AttributeError:
            func_name = "<unnamed grammar function>"

        start, end = self.current_position()
        raise errors.EfilterParseError(
            query=self.tokenizer.source, start=start, end=end,
            message="Was expecting %s here." % (func_name))

    def current_position(self):
        """Return a tuple of (start, end)."""
        token = self.tokenizer.peek(0)
        if token:
            return token.start, token.end

        return self.tokenizer.position, self.tokenizer.position + 1

    def peek(self, n):
        """Same as self.tokenizer.peek."""
        return self.tokenizer.peek(n)

    def skip(self, n):
        """Same as self.tokenizer.skip."""
        return self.tokenizer.skip(n)

    def __iter__(self):
        """Self as iter(self.tokenizer)."""
        return iter(self.tokenizer)
