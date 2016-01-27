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
EFILTER query wrapper.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import six

from efilter import syntax as s
from efilter import ast


def guess_source_syntax(source):
    if isinstance(source, ast.Expression):
        return "expression"

    if isinstance(source, six.string_types):
        return "dottysql"

    if isinstance(source, tuple):
        return "lisp"

    return None


class Query(object):
    source = None
    root = None
    syntax = None
    application_delegate = None
    params = None

    def __init__(self, source, root=None, params=None, syntax=None,
                 application_delegate=None):
        super(Query, self).__init__()

        if isinstance(source, Query):
            # Run as a copy constructor with optional overrides.
            self.root = source.root
            self.source = source.source
            self.application_delegate = source.application_delegate
            self.syntax = source.syntax
            self.params = source.params
        elif isinstance(source, ast.Expression):
            # TODO: This will go away when other stops relying on it.
            self.root = source
        else:
            self.source = source

        # Override anything set by above code with explicit args.
        if syntax is not None:
            self.syntax = syntax

        if application_delegate is not None:
            self.application_delegate = application_delegate

        if params is not None:
            self.params = params

        if root is not None:
            if root != self.root:
                self.source = None  # No longer valid.
            self.root = root

        # Generate missing information.
        if not self.source and not self.root:
            raise ValueError("Must pass at least 'source' or 'root'.")

        if self.source and not self.root:
            # Run parser to generate AST.
            if not self.syntax:
                self.syntax = guess_source_syntax(self.source)

            parser_cls = s.Syntax.get_syntax(self.syntax)
            if not parser_cls:
                raise ValueError(
                    "Cannot find parser for syntax %r. Source was %r." %
                    (self.syntax, self.source))
            parser = parser_cls(original=self.source, params=self.params)
            self.root = parser.root
        elif self.root and not self.source:
            # Run formatter to generate the source.
            if not self.syntax:
                # Good, fully expressive default.
                self.syntax = "dottysql"

            formatter = s.Syntax.get_formatter(self.syntax)
            if not formatter:
                # If we don't have a formatter for the explicit syntax, just
                # generate at least /something/.
                formatter = s.Syntax.get_formatter("dottysql")
            self.source = formatter(self.root)

    def __str__(self):
        return unicode(self)

    def __unicode__(self):
        return unicode(self.source)

    def __repr__(self):
        return "Query(%s)" % repr(self.source)

    def __hash__(self):
        return hash(self.root)

    def __eq__(self, other):
        if not isinstance(other, Query):
            return False

        return self.root == other.root

    def __ne__(self, other):
        return not self.__eq__(other)
