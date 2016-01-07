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
This module contains functions that map consructs in DottySQL to the AST.

Most constructs in DottySQL map directly to something in the EFILTER AST, but
some constructs don't. For example, EFILTER supports a Complement ('NOT') and
an Equivalence ('=='), but not a non-Equivalence ('!='), therefore, this module
contains a function that simulates a non-Equivalence AST node by transforming
it to a Completement of Equivalence.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import ast


def ComplementEquivalence(*args, **kwargs):
    """Change x != y to not(x == y)."""
    return ast.Complement(
        ast.Equivalence(*args, **kwargs), **kwargs)


def ComplementMembership(*args, **kwargs):
    """Change (x not in y) to not(x in y)."""
    return ast.Complement(
        ast.Membership(*args, **kwargs), **kwargs)


def ReverseStrictOrderedSet(*args, **kwargs):
    """Change x < y to y > x."""
    return ast.StrictOrderedSet(*reversed(args), **kwargs)


def ReversePartialOrderedSet(*args, **kwargs):
    """Change x <= y to y >= x."""
    return ast.PartialOrderedSet(*reversed(args), **kwargs)


def NegateValue(*args, **kwargs):
    """Change -x to (-1 * x)."""
    return ast.Product(
        ast.Literal(-1),
        *args,
        **kwargs)
