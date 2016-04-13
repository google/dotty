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
This module implements a syntax similar to objectfilter [1], with the following
differences:

 - The context operator (@) isn't implemented. It would probably not be
   too difficult to add, but isn't actually being used by any of the
   objectfilter projects, as far as I know.

 - The handling of list literals is different:
   - Nested lists ARE supported (the grammar is fully recursive).
   - Elements in lists MUST be separated by commas, and commas MUST separete
     elements in lists (so, "[,,]" isn't allowed).

There are probably other subtle differences owing to the very different design
of the canonical objectfilter parser. The below seems to work well enough in
all the cases I've tested, though.

1: https://github.com/google/objectfilter/
"""

from efilter import ast
from efilter import syntax

from efilter.parsers.common import ast_transforms
from efilter.parsers.common import grammar
from efilter.parsers.common import parser
from efilter.parsers.common import tokenizer


class ObjectFilterSyntax(syntax.Syntax):
    OPERATORS = [
        # Aliases for equivalence:
        grammar.Operator(name="equals", precedence=3, assoc="left",
                         handler=ast.Equivalence, docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "equals"), suffix=None),
        grammar.Operator(name="is", precedence=3, assoc="left",
                         handler=ast.Equivalence, docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "is"), suffix=None),
        grammar.Operator(name="==", precedence=3, assoc="left",
                         handler=ast.Equivalence, docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "=="), suffix=None),
        grammar.Operator(name="notequals", precedence=3, assoc="left",
                         handler=ast_transforms.ComplementEquivalence,
                         docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "notequals"),
                         suffix=None),
        grammar.Operator(name="isnot", precedence=3, assoc="left",
                         handler=ast_transforms.ComplementEquivalence,
                         docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "isnot"), suffix=None),
        grammar.Operator(name="!=", precedence=3, assoc="left",
                         handler=ast_transforms.ComplementEquivalence,
                         docstring=None, prefix=None,
                         infix=grammar.Token("symbol", "!="), suffix=None),

        # Logical:
        grammar.Operator(name="or", precedence=0, assoc="left",
                         handler=ast.Union, docstring="Logical OR.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "or")),
        grammar.Operator(name="and", precedence=1, assoc="left",
                         handler=ast.Intersection, docstring="Logical AND.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "and")),
        grammar.Operator(name="||", precedence=0, assoc="left",
                         handler=ast.Union, docstring="Logical OR.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "||")),
        grammar.Operator(name="&&", precedence=1, assoc="left",
                         handler=ast.Intersection, docstring="Logical AND.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "&&")),

        # Comparisons:
        grammar.Operator(name=">=", precedence=3, assoc="left",
                         handler=ast.PartialOrderedSet,
                         docstring="Equal-or-greater-than.", prefix=None,
                         suffix=None, infix=grammar.Token("symbol", ">=")),
        grammar.Operator(name="<=", precedence=3, assoc="left",
                         handler=ast_transforms.ReversePartialOrderedSet,
                         docstring="Equal-or-less-than.", prefix=None,
                         suffix=None, infix=grammar.Token("symbol", "<=")),
        grammar.Operator(name=">", precedence=3, assoc="left",
                         handler=ast.StrictOrderedSet,
                         docstring="Greater-than.", prefix=None, suffix=None,
                         infix=grammar.Token("symbol", ">")),
        grammar.Operator(name="<", precedence=3, assoc="left",
                         handler=ast_transforms.ReverseStrictOrderedSet,
                         docstring="Less-than.", prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "<")),

        # Set ops:
        grammar.Operator(name="notinset", precedence=3, assoc="left",
                         handler=ast_transforms.ComplementMembership,
                         docstring="Left-hand operand is not in list.",
                         prefix=None, suffix=None,
                         infix=(grammar.Token("symbol", "notinset"))),
        grammar.Operator(name="inset", precedence=3, assoc="left",
                         handler=ast.Membership,
                         docstring="Left-hand operand is in list.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "inset")),
        grammar.Operator(name="notcontains", precedence=3, assoc="left",
                         handler=ast_transforms.ReverseComplementMembership,
                         docstring="Right-hand operand is not in list.",
                         prefix=None, suffix=None,
                         infix=(grammar.Token("symbol", "notcontains"))),
        grammar.Operator(name="contains", precedence=3, assoc="left",
                         handler=ast_transforms.ReverseMembership,
                         docstring="Right-hand operand is in list.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "contains")),

        # Miscellaneous:
        grammar.Operator(name="unary -", precedence=5, assoc="right",
                         handler=ast_transforms.NegateValue,
                         docstring=None, infix=None, suffix=None,
                         prefix=grammar.Token("symbol", "-")),
        grammar.Operator(name="list builder", precedence=14, assoc="left",
                         handler=ast.Tuple, docstring=None,
                         prefix=grammar.Token("lbracket", "["),
                         infix=grammar.Token("comma", ","),
                         suffix=grammar.Token("rbracket", "]")),
        grammar.Operator(name="regexp", precedence=3, assoc="left",
                         handler=ast.RegexFilter,
                         docstring="Match LHS against regex on RHS.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", "regexp")),
        grammar.Operator(name=".", precedence=12, assoc="left",
                         handler=ast_transforms.NormalizeResolve,
                         docstring="OBJ.MEMBER -> return MEMBER of OBJ.",
                         prefix=None, suffix=None,
                         infix=grammar.Token("symbol", ".")),
    ]

    def __init__(self, original, params=None):
        super(ObjectFilterSyntax, self).__init__(original)
        if params is not None:
            raise ValueError("ObjectFilterSyntax doesn't support parameters.")

        t = tokenizer.LazyTokenizer(original)
        self.parser = parser.ExpressionParser(operators=self.OPERATORS,
                                              tokenizer=t)

    @property
    def root(self):
        return self.parser.parse()


syntax.Syntax.register_parser(ObjectFilterSyntax, shorthand="objectfilter")
