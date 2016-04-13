#!/usr/bin/env python

# EFILTER sample project - star catalog filter.
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
A sample project that uses EFILTER to implement a custom indicator format.
"""

from __future__ import print_function


__author__ = "Adam Sindelar <adamsh@google.com>"

import argparse
import re

from efilter import api
from efilter import ast
from efilter import query
from efilter import syntax

from efilter.transforms import asdottysql


def main():
    parser = argparse.ArgumentParser(description="Convert a tafile to DottySQL")
    parser.add_argument("path", type=str)
    args = parser.parse_args()

    with open(args.path, "r") as fd:
        tag_rules = query.Query(fd, syntax="tagfile")

    # What does the query look like as DottySQL?
    dottysql = asdottysql.asdottysql(tag_rules)
    print("# Tagfile %r converted:\n\n%s" % (args.path, dottysql))

    # How will the query tag this event?
    event = {
        "data_type": "windows:evtx:record",
        "timestamp_desc": "",
        "strings": ("foo", "bar"),
        "source_name": "Microsoft-Windows-Kernel-Power",
        "event_identifier": 42
    }

    tags = api.apply(tag_rules, vars=event)
    print("\n# Tagfile %r returned %r." % (args.path, list(tags)))


class TagFile(syntax.Syntax):
    """Parses the plaso tagfile format."""

    # A line with no indent is a tag name.
    TAG_DECL_LINE = re.compile(r"^(\w+)")
    # A line with leading indent is one of the rules for the preceding tag.
    TAG_RULE_LINE = re.compile(r"^\s+(.+)")
    # If any of these words are in the query then it's probably objectfilter.
    OBJECTFILTER_WORDS = re.compile(
        r"\s(is|isnot|equals|notequals|inset|notinset|contains|notcontains)\s")

    _root = None

    def __init__(self, path=None, original=None, **kwargs):
        if original is None:
            if path is not None:
                original = open(path, "r")
            else:
                raise ValueError("Either path to a tag file or a file-like "
                                 "object must be provided as path or original.")
        elif path is not None:
            raise ValueError("Cannot provide both a path and an original.")
        elif not callable(getattr(original, "__iter__", None)):
            raise TypeError("The 'original' argument to TagFile must be "
                            "an iterable of lines (like a file object).")

        super(TagFile, self).__init__(original=original, **kwargs)

    def __del__(self):
        if not self.original.closed:
            self.original.close()

    def _parse_query(self, source):
        """Parse one of the rules as either objectfilter or dottysql.

        Example:
            _parse_query("5 + 5")
            # Returns Sum(Literal(5), Literal(5))

        Arguments:
            source: A rule in either objectfilter or dottysql syntax.

        Returns:
            The AST to represent the rule.
        """
        if self.OBJECTFILTER_WORDS.search(source):
            syntax_ = "objectfilter"
        else:
            syntax_ = None  # Default it is.

        return query.Query(source, syntax=syntax_)

    def _parse_tagfile(self):
        """Parse the tagfile and yield tuples of tag_name, list of rule ASTs."""
        rules = None
        tag = None
        for line in self.original:
            match = self.TAG_DECL_LINE.match(line)
            if match:
                if tag and rules:
                    yield tag, rules
                rules = []
                tag = match.group(1)
                continue

            match = self.TAG_RULE_LINE.match(line)
            if match:
                source = match.group(1)
                rules.append(self._parse_query(source))

    @property
    def root(self):
        if not self._root:
            self._root = self.parse()

        return self._root

    def parse(self):
        tags = []
        for tag_name, rules in self._parse_tagfile():
            tag = ast.IfElse(
                # Union will be true if any of the 'rules' match.
                ast.Union(*[rule.root for rule in rules]),
                # If so then evaluate to a string with the name of the tag.
                ast.Literal(tag_name),
                # Otherwise don't return anything.
                ast.Literal(None))
            tags.append(tag)

        self.original.close()
        # Generate a repeated value with all the tags (None will be skipped).
        return ast.Repeat(*tags)

# We can register our parser with the Syntax baseclass. Subsequently, the
# shorthand can be given to query.Query(syntax=...) argument without having to
# invoke our parser manually.
syntax.Syntax.register_parser(TagFile, shorthand="tagfile")


if __name__ == "__main__":
    main()
