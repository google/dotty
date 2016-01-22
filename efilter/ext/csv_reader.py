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
Implements IRepeated for text files and some common formats.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import csv

from efilter.protocols import counted
from efilter.protocols import repeated


class LazyCSVReader(object):
    source = None
    delim = ","
    quote = "\""
    output_dicts = False
    trim = True

    def __init__(self, fd, delim=",", quote="\"", output_dicts=False,
                 trim=True):
        self.source = repeated.lines(fd)
        self.delim = delim
        self.quote = quote
        self.output_dicts = output_dicts
        self.trim = trim

    def __iter__(self):
        return self.getvalues()

    # IRepeated implementation.

    def getvalues(self):
        reader_cls = csv.DictReader if self.output_dicts else csv.reader
        return reader_cls(iter(self.source),
                          delimiter=self.delim,
                          quotechar=self.quote,
                          skipinitialspace=self.trim,
                          escapechar="\\")

    def value_type(self):
        return dict if self.output_dicts else list

    def value_eq(self, other):
        if isinstance(other, type(self)):
            return self.source.fd == other.source.fd

        return list(self) == list(other)

    def value_apply(self, f):
        for value in self:
            yield f(value)

    # ICounted implementation.

    def count(self):
        return counted.count(self.source)


counted.ICounted.implicit_static(LazyCSVReader)
repeated.IRepeated.implicit_static(LazyCSVReader)
