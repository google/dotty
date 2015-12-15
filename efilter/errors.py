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
EFILTER abstract syntax.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


class EfilterError(Exception):
    query = None
    _root = None
    message = None
    start = None
    end = None

    def __init__(self, query=None, message=None, root=None, start=None,
                 end=None):
        super(EfilterError, self).__init__(message)

        self.query = query
        self.message = message
        self.root = root

        if start is not None:
            self.start = start

        if end is not None:
            self.end = end

    @property
    def root(self):
        return self._root

    @root.setter
    def root(self, value):
        self._root = value

        try:
            self.start = value.start
            self.end = value.end
        except AttributeError:
            self.start = None
            self.end = None

    @property
    def text(self):
        return self.message

    @property
    def adjusted_start(self):
        """Start of the error in self.source (with the >>> and <<< delims)."""
        if self.start is not None:
            return self.start

    @property
    def adjusted_end(self):
        """End of the error in self.source (with the >>> and <<< delims)."""
        if self.end is not None:
            return self.end + 9

    @property
    def source(self):
        if not self.query:
            return None

        if self.start is not None and self.end is not None:
            return "%s >>> %s <<< %s" % (
                self.query[0:self.start],
                self.query[self.start:self.end],
                self.query[self.end:])
        elif self.query:
            return self.query

    def __str__(self):
        return "%s (%s) in query %r" % (
            type(self).__name__,
            self.text,
            self.source)

    def __repr__(self):
        return "%s(message=%r, start=%r, end=%r)" % (
            type(self), self.message, self.start, self.end)


class EfilterLogicError(EfilterError):
    pass


class EfilterNoneError(EfilterError):
    pass


class EfilterParseError(EfilterError):
    token = None

    def __init__(self, *args, **kwargs):
        self.token = kwargs.pop("token", None)
        super(EfilterParseError, self).__init__(*args, **kwargs)


class EfilterKeyError(EfilterError):
    key = None

    @property
    def text(self):
        if self.message:
            return self.message

        if self.key:
            return "No such key %r." % self.key

        return None

    def __init__(self, *args, **kwargs):
        self.key = kwargs.pop("key", None)

        super(EfilterKeyError, self).__init__(*args, **kwargs)


class EfilterTypeError(EfilterError):
    expected = None
    actual = None

    @property
    def text(self):
        if self.message:
            return self.message

        if self.expected and self.actual:
            return "Expected type %r, got %r instead." % (self.expected,
                                                          self.actual)

        return None

    def __init__(self, *args, **kwargs):
        self.expected = kwargs.pop("expected", None)
        self.actual = kwargs.pop("actual", None)

        super(EfilterTypeError, self).__init__(*args, **kwargs)
