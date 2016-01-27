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

import six
import threading

from efilter.protocols import counted
from efilter.protocols import repeated


class LazyLineReader(object):
    """Reads in a line at a time and supports restarting."""

    fd = None
    _seek_lock = None

    def __init__(self, fd):
        self.fd = fd
        self._seek_lock = threading.Lock()

    def __iter__(self):
        return self.getvalues()

    def __del__(self):
        """Close 'fd' if it hasn't been closed already.

        If LazyLineReader was instantiated using EFILTER's stdlib.io functions
        then it won't be inside of a with block and we need to close fd when
        the repeated is deallocated.
        """
        if not self.fd.closed:
            self.fd.close()

    # IRepeated implementation.

    def readline_at_offset(self, offset):
        self._seek_lock.acquire()
        self.fd.seek(offset)
        line = self.fd.readline()
        new_offset = self.fd.tell()
        self._seek_lock.release()

        return line, new_offset

    def getvalues(self):
        line, offset = self.readline_at_offset(0)
        while line:
            yield line
            line, offset = self.readline_at_offset(offset)

    def value_type(self):
        return six.string_types[0]

    def value_eq(self, other):
        if isinstance(other, type(self)):
            return self.fd == other.fd

        return list(self) == list(other)

    def value_apply(self, f):
        for value in self:
            yield f(value)

    # Counted implementation.

    def count(self):
        c = 0
        for _ in self:
            c += 1

        return c

counted.ICounted.implicit_static(for_type=LazyLineReader)
repeated.IRepeated.implicit_static(LazyLineReader)


if six.PY2:
    # Python 3 doesn't have a file class. open() just returns a StringIO
    repeated.lines.implement(for_type=file, implementation=LazyLineReader)

if six.PY3:
    import io
    repeated.lines.implement(for_type=io.IOBase, implementation=LazyLineReader)

repeated.lines.implement(for_type=six.StringIO, implementation=LazyLineReader)
