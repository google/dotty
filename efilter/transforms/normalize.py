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
EFILTER query normalizer.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import dispatch
from efilter import ast
from efilter import query as q


@dispatch.multimethod
def normalize(expr):
    """Optimizes the AST for better performance and simpler structure.

    The returned query will be logically equivalent to what was provided but
    transformations will be made to flatten and optimize the structure. This
    works by recognizing certain patterns and replacing them with nicer ones,
    eliminating pointless expressions, and so on.

    # Collapsing nested variadic expressions:

    Example:
        Intersection(x, Interestion(y, z)) => Intersection(x, y, z)

    # Empty branch elimination:

    Example:
        Intersection(x) => x
    """
    _ = expr
    raise NotImplementedError()


@normalize.implementation(for_type=q.Query)
def normalize(query):
    new_root = normalize(query.root)
    return q.Query(query, root=new_root)


@normalize.implementation(for_type=ast.Expression)
def normalize(expr):
    return expr


@normalize.implementation(for_type=ast.BinaryExpression)
def normalize(expr):
    """Normalize both sides, but don't eliminate the expression."""
    lhs = normalize(expr.lhs)
    rhs = normalize(expr.rhs)
    return type(expr)(lhs, rhs, start=lhs.start, end=rhs.end)


@normalize.implementation(for_type=ast.Apply)
def normalize(expr):
    """No elimination, but normalize arguments."""
    args = [normalize(arg) for arg in expr.args]

    return type(expr)(expr.func, *args, start=expr.start, end=expr.end)


@normalize.implementation(for_type=ast.VariadicExpression)
def normalize(expr):
    """Pass through n-ary expressions, and eliminate empty branches.

    Variadic and binary expressions recursively visit all their children.

    If all children are eliminated then the parent expression is also
    eliminated:

    (& [removed] [removed]) => [removed]

    If only one child is left, it is promoted to replace the parent node:

    (& True) => True
    """
    children = []
    for child in expr.children:
        branch = normalize(child)
        if branch is None:
            continue

        if type(branch) is type(expr):
            children.extend(branch.children)
        else:
            children.append(branch)

    if len(children) == 0:
        return None

    if len(children) == 1:
        return children[0]

    return type(expr)(*children, start=children[0].start,
                      end=children[-1].end)
