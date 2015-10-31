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
EFILTER rule-based query analyzer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import collections

from efilter import dispatch
from efilter import query as q
from efilter import errors
from efilter import ast
from efilter import protocol

from efilter.protocols import iset


Analysis = collections.namedtuple("Analysis",
                                  ("symbols", "eq_indexables"))


@dispatch.multimethod
def analyse(query, scope=None):
    """This is a rule-driven analyzer that gets a list of symbols and indexing.

    This class follows the visitor pattern. See documentation on VisitorEngine.

    The analyzer will produce a list of symbols required by the query (based on
    the Bindings/variables) and recommend a list of Bindings suitable for
    building an equivalence-based index (based on Equivalence expressions in
    the query).
    """
    _ = query, scope
    raise NotImplementedError()


@analyse.implementation(for_type=q.Query)
def analyse(query, scope=None):
    return analyse(query.root, scope)


@analyse.implementation(for_type=ast.Binding)
def analyse(expr, scope=None):
    _ = scope
    return Analysis((expr.value,), ())


@analyse.implementation(for_type=ast.Complement)
def analyse(expr, scope=None):
    return analyse(expr.value, scope)


@analyse.implementation(for_type=ast.Literal)
def analyse(expr, scope=None):
    _ = expr, scope
    return Analysis((), ())


@analyse.implementation(for_type=ast.BinaryExpression)
def analyse(expr, scope=None):
    lhsa = analyse(expr.lhs, scope)
    rhsa = analyse(expr.rhs, scope)

    return Analysis(
        iset.union(lhsa.symbols, rhsa.symbols),
        iset.union(lhsa.eq_indexables, rhsa.eq_indexables))


@analyse.implementation(for_type=ast.VariadicExpression)
def analyse(expr, scope=None):
    symbols = set()
    eq_indexables = set()

    for child in expr.children:
        analysis = analyse(child, scope)
        symbols.update(analysis.symbols)
        eq_indexables.update(analysis.eq_indexables)

    return Analysis(symbols, eq_indexables)


@analyse.implementation(for_type=ast.Within)
def analyse(expr, scope=None):
    if not isinstance(expr.lhs, ast.Binding):
        # Technically, the LHS context can be anything that implements
        # IAssociative, so a literal, or a subexpression that evaluates to
        # one are possible. Unfortunately, when that happens it is
        # non-trivial (read hard (read impossible)) to correctly determine
        # the scope for the RHS of the within-form.
        #
        # As this is the case, we are unable to create any hints, and
        # any symbols in the RHS expression are bound to an anonymous scope
        # and, as such, not useful.
        return analyse(ast.BinaryExpression(*expr), scope)

    scope = expr.lhs.value
    rhsa = analyse(expr.rhs, scope)
    symbols = set("%s.%s" % (scope, symbol) for symbol in rhsa.symbols)
    symbols.update(rhsa.symbols)
    symbols.add(expr.lhs.value)
    return rhsa._replace(symbols=symbols)


@analyse.implementation(for_type=ast.Membership)
def analyse(expr, scope=None):
    symbols = set()
    lha = analyse(expr.lhs, scope)
    rha = analyse(expr.rhs, scope)
    symbols.update(lha.symbols)
    symbols.update(rha.symbols)

    if (not isinstance(expr.rhs, ast.Literal)
            or not isinstance(expr.lhs, ast.Binding)):
        return Analysis(symbols, ())

    if not protocol.implements(expr.rhs.value, iset.ISet):
        # Yup, no can do.
        raise errors.EfilterTypeError(root=expr.rhs,
                                      actual=type(expr.rhs.value),
                                      expected=iset.ISet)

    return Analysis(symbols, (expr.lhs.value,))


@analyse.implementation(for_type=ast.Equivalence)
def analyse(expr, scope=None):
    literal = None
    indexables = set()
    symbols = set()
    for child in expr.children:
        if isinstance(child, ast.Literal):
            if literal is not None and literal != child.value:
                # This means something like 5 == 6 is being asked. This
                # expression will always be false and it makes no sense to
                # continue.
                return Analysis((), ())
            else:
                literal = child.value
        elif isinstance(child, ast.Binding):
            indexables.add(child.value)
            symbols.add(child.value)
        elif isinstance(child, ast.Within):
            # If we get a within-form, follow down as long as RHS is another
            # left form and the LHS is a binding. (something like
            # foo.bar.baz)
            within = child
            path = []
            while (isinstance(within, ast.Within)
                   and isinstance(within.lhs, ast.Binding)):
                path.append(within.lhs.value)
                symbols.add(".".join(path))
                within = within.rhs

            if isinstance(within, ast.Binding):
                path.append(within.value)

            remainder = analyse(child, scope)
            symbols.update(remainder.symbols)

            symbol = ".".join(path)
            symbols.add(symbol)
            indexables.add(symbol)
        else:
            analysis = analyse(child, scope)
            symbols.update(analysis.symbols)

    return Analysis(symbols, indexables)
