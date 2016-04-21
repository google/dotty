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
EFILTER stdlib - IO module.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import six

from efilter.ext import csv_reader

from efilter.protocols import repeated

from efilter.stdlib import core


class Lines(core.TypedFunction):
    """Return an IRepeated with lines from text file 'path'.

    Arguments:
        path: String with the path to the file to read in.

    Raises:
        IOError if the file can't be opened for whatever reason.

    Returns:
        An object implementing IRepeated containing the lines of in the file
        as strings.
    """

    name = "lines"

    def __call__(self, path):
        fd = open(path, "r")
        # We don't close fd here, because repeated.lines is lazy and will read
        # on demand. The descriptor will be closed in the repeated value's
        # destructor.
        return repeated.lines(fd)

    @classmethod
    def reflect_static_args(cls):
        return (six.string_types[0],)

    @classmethod
    def reflect_static_return(cls):
        return repeated.IRepeated


class CSV(core.TypedFunction):
    """Return an IRepeated with file at 'path' decoded as CSV.

    Arguments:
        path: Same as 'Lines'
        decode_header: Use the first line in the file for column names and
            return a dict per line, instead of tuple per line. (default: False.)
        delim: Column separator (default: ",").
        quote: Quote character (defalt: double quote).
        trim: Eliminate leading whitespace (default: True).

    Raises:
        IOError if the file can't be opened for whatever reason.

    Returns:
        An IRepeated containing the lines in the CSV file decoded as either
        a tuple of values per line, or a dict of values per line, if
        'decode_header' is True.
    """

    name = "csv"

    def __call__(self, path, decode_header=False, delim=",", quote="\"",
                 trim=True):
        fd = open(path, "r")
        # We don't close fd here, because repeated.lines is lazy and will read
        # on demand. The descriptor will be closed in the repeated value's
        # destructor.
        return csv_reader.LazyCSVReader(fd=fd, output_dicts=decode_header,
                                        delim=delim, quote=quote, trim=trim)

    @classmethod
    def reflect_static_args(cls):
        return (six.string_types[0], bool)

    @classmethod
    def reflect_static_return(cls):
        return repeated.IRepeated


MODULE = core.LibraryModule(name="stdio",
                            vars={CSV.name: CSV(),
                                  Lines.name: Lines()})
