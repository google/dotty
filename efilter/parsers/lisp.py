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
Lisp-like EFILTER syntax.

This is mostly used in tests, in situations where dotty doesn't make it
obvious what the AST is going to look like, and manually setting up expression
classes is too verbose.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter import ast
from efilter import syntax


EXPRESSIONS = {
    "var": ast.Var,
    "!": ast.Complement,
    "select": ast.Select,
    "cast": ast.Cast,
    "isa": ast.IsInstance,
    "map": ast.Map,
    "filter": ast.Filter,
    "reducer": ast.Reducer,
    "group": ast.Group,
    "sort": ast.Sort,
    "any": ast.Any,
    "each": ast.Each,
    "in": ast.Membership,
    "apply": ast.Apply,
    "repeat": ast.Repeat,
    "tuple": ast.Tuple,
    "bind": ast.Bind,
    "if": ast.IfElse,
    ":": ast.Pair,
    ".": ast.Resolve,
    "|": ast.Union,
    "&": ast.Intersection,
    ">": ast.StrictOrderedSet,
    ">=": ast.PartialOrderedSet,
    "==": ast.Equivalence,
    "=~": ast.RegexFilter,
    "+": ast.Sum,
    "-": ast.Difference,
    "*": ast.Product,
    "/": ast.Quotient,
    "literal": ast.Literal,
}


class Parser(syntax.Syntax):
    """Parses the lisp expression language into the query AST."""

    @property
    def root(self):
        return self._parse_atom(self.original)

    def _parse_atom(self, atom):
        if isinstance(atom, tuple):
            return self._parse_s_expression(atom)

        return ast.Literal(atom)

    def _parse_s_expression(self, atom):
        car = atom[0]
        cdr = atom[1:]

        # Vars are a little special. Don't make the value a Literal.
        if car == "var":
            return ast.Var(cdr[0])

        # Params are interpolated right away.
        if car == "param":
            return ast.Literal(self.params[cdr[0]])

        return EXPRESSIONS[car](*[self._parse_atom(a) for a in cdr])


syntax.Syntax.register_parser(Parser, shorthand="lisp")
