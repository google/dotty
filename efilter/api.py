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
EFILTER convenience API.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter import query as q
from efilter.transforms import solve


def apply(query, replacements=None, **vars):
    """Run 'query' on 'vars' and return results (potentially as IRepeated)."""
    query = q.Query(query, params=replacements)
    results = solve.solve(query, vars).value

    return results


def search(query, data, replacements=None):
    """Yield objects from 'data' that match the 'query'."""
    query = q.Query(query, params=replacements)
    for entry in data:
        if solve.solve(query, entry).value:
            yield entry
