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

This benchmark test tries to filter a large star catalog read from a CSV file.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


from efilter.ext import csv_reader

from efilter_tests import benchmark
from efilter_tests import testlib


class HYGDataPassthrough(benchmark.EfilterBenchmarkCase):
    fixture_name = "hygdata_v3.csv"
    query = "csv(?)"
    name = "hygdata_passthrough"


class HYGDataDictPassthrough(benchmark.EfilterBenchmarkCase):
    fixture_name = "hygdata_v3.csv"
    query = "csv(?, decode_header: true)"
    name = "hygdata_dicts"


class HYGDataFilter(benchmark.EfilterBenchmarkCase):
    fixture_name = "hygdata_v3.csv"
    # The number we're comparing 'dist' to is a string because 'dist' is a
    # string... This will go away when I implement a cast operator.
    query = ("SELECT proper as name, id FROM csv(?, decode_header: true)"
             " WHERE dist < '300' AND count(proper) > 1")
    name = "hygdata_filter_basic"


class HYGDataHandcoded(benchmark.EfilterBenchmarkCase):
    name = "hygdata_filter_basic_handcoded"

    def run(self):
        with open(testlib.get_fixture_path("hygdata_v3.csv"), "r") as fd:
            for line in csv_reader.LazyCSVReader(fd, output_dicts=True):
                if float(line["dist"]) < 300 and len(line["proper"]) > 1:
                    _ = dict(name=line["proper"], id=line["id"])


class HYGDataFilterLimit(benchmark.EfilterBenchmarkCase):
    fixture_name = "hygdata_v3.csv"
    # The number we're comparing 'dist' to is a string because 'dist' is a
    # string... This will go away when I implement a cast operator.
    query = ("SELECT proper as name, id FROM csv(?, decode_header: true)"
             " WHERE dist > '10' LIMIT 10")
    name = "hygdata_filter_limit"
