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
EFILTER query hinter.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import dispatch
from efilter import errors
from efilter import ast
from efilter import query as q

from efilter.transforms import normalize


@dispatch.multimethod
def hint(expr, selector):
    """Retargets the query to apply to a subexpression, to be used for hinting.

    Discussion of mechanism and rationale:
    ======================================

    Bear with me on this one.

    As with any database-like system, certain EFILTER queries can be satisfied
    by following several equally valid, but differently expensive strategies.
    Because traditional notions of cardinality and available indexing do not
    apply to most systems that provide EFILTER with data (and, at any rate,
    such concerns are usually negligible in comparison with the actual
    collection of data), it becomes useful for the expert system supplying the
    data to be able to influence the strategy based on what it knows about the
    relative trade-offs.

    To give a concrete example, take the following query:
        VAD.flags contains {'execute', 'write'} and VAD.process.name == 'init'

    (In this example a VAD is a virtual address descriptor, which is a data
    structure used by operating systems to keep track of pageable memory.)

    A naive expert (uh...) system will generate all possible VADs and feed them
    to the EFILTER solve function. An optimized system - lets call it an expert
    expert system - can only collect VADs belonging to the 'init' process at
    fraction of the cost, and supply those to EFILTER for indexing and
    filtering. This is possible, because the expert system knows that processes
    are the first to be collected, and that each process holds a reference to
    related VADs, making it beneficial to skip processes that don't apply. What
    the expert system needs is a way to signal that such a strategy is
    available, and a way to recognize the processes which cannot be skipped.

    Enter the Hinter - taking the example above, the expert system can run:
        q = Query("VAD.flags contains {'execute', 'write'} "
                  " and VAD.process.name == 'init'")
        h = hint(q, selector='VAD.process')

    This will cause the Hinter to generate a hint query equivalent to the
    expression "name == 'init'", which can be applied to a process object
    for prefiltering. Amazing.
    """
    _ = expr, selector
    raise NotImplementedError()


@hint.implementation(for_type=q.Query)
def hint(query, selector):
    parsed_selector = tuple(selector.split(".")) if selector else ()

    # Make sure the query is reasonably shaped with respect to let-forms.
    query = normalize.normalize(query)
    new_root = hint(query.root, parsed_selector)
    return q.Query(query, root=new_root)


@hint.implementation(for_type=ast.Within)
def hint(expr, selector):
    # Are we already in a branch that we're preserving?
    if not selector:
        return expr

    # Verify that the AST below is well-formed.
    if not isinstance(expr.lhs, ast.Binding):
        # Can't do anything - might not be correct - perhaps we should
        # blow up here? (Only within-forms with a Binding on the LHS can be
        # hinted.)
        #
        # TODO(adamsh): It's likely that a let with an LHS that's not a binding
        # has very limited uses anyway - maybe consider not allowing it in the
        # AST.
        raise errors.EfilterError(
            message=("Hinter can only optimize let forms where lhs is a "
                     "binding (a variable). Got %r instead.") % expr,
            root=expr)

    if selector[0] == expr.lhs.value:
        # Next part of the selector is the same as our LHS. Descend.
        return hint(expr.rhs, selector[1:])

    return None  # Eliminate this branch.


def _build_variadic(expr, selector):
    children = []
    for child in expr.children:
        branch = hint(child, selector)
        if branch:
            children.append(branch)

    return children


@hint.implementation(for_type=ast.VariadicExpression)
def hint(expr, selector):
    children = _build_variadic(expr, selector)
    if not children:
        return None

    if len(children) == 1:
        # We play it safe and keep the only child in case the return type
        # of this expression isn't just a boolean (math).
        # More specific visitors will eliminate the whole thing.
        return children[0]

    return type(expr)(*children)


@hint.implementation(for_type=ast.Relation)
def hint(expr, selector):
    children = _build_variadic(expr, selector)

    if len(children) == 1:
        return None  # It's pointless to execute this relation.

    return type(expr)(*children)


@hint.implementation(for_type=ast.Complement)
def hint(expr, selector):
    child = hint(expr.value, selector)
    if child is None:
        return None

    return type(expr)(child)


@hint.implementation(for_type=ast.IsInstance)
def hint(expr, selector):
    _ = selector
    return expr


@hint.implementation(for_type=ast.BinaryExpression)
def hint(expr, selector):
    lhs = hint(expr.lhs, selector)
    if not lhs:
        return None

    rhs = hint(expr.rhs, selector)
    if not rhs:
        return None

    return type(expr)(lhs, rhs)


@hint.implementation(for_type=ast.Literal)
def hint(expr, selector):
    _ = selector
    return expr


@hint.implementation(for_type=ast.Binding)
def hint(expr, selector):
    if not selector:
        return expr

    return None
