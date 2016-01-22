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
EFILTER test suite.

This benchmark suite operates on a small file, but runs complex queries.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter_tests import benchmark


class SmallPassthrough(benchmark.EfilterBenchmarkCase):
    fixture_name = "small.csv"
    query = "csv(?)"
    name = "small_passthrough"


class SmallFilter(benchmark.EfilterBenchmarkCase):
    fixture_name = "small.csv"
    query = ("SELECT lower(Name) as name FROM csv(?, decode_header: true)"
             " WHERE Name AND City"
             " ORDER BY (Name, Age)"
             " LIMIT 1 OFFSET 1")
    name = "small_filter"
