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
EFILTER test helpers.
"""

from builtins import object
__author__ = "Adam Sindelar <adamsh@google.com>"

import collections
import six

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import repeated
from efilter.protocols import structured


class MockFunction(object):
    def apply(self, args, kwargs):
        return self(*args, **kwargs)

    def __call__(self, x, y):
        return x * y

    @classmethod
    def reflect_static_args(cls):
        return ("x", int), ("y", int)

    @classmethod
    def reflect_static_return(cls):
        return int


class Process(collections.namedtuple("Process", ["pid", "name", "parent"])):
    @classmethod
    def reflect_static_member(cls, name):
        return PROCESS_DEFS.get(name)

    @classmethod
    def reflect_static_key(cls, key):
        return cls.reflect_static_member(key)

    @classmethod
    def getkeys(cls):
        return list(PROCESS_DEFS.keys())

    def resolve(self, name):
        return getattr(self, name)

    def select(self, key):
        return self.resolve(key)


PROCESS_DEFS = {
    "pid": int,
    "name": six.text_type,
    "parent": Process}


class _proc(collections.namedtuple("_proc", ["p_pid", "p_comm", "p_ppid"])):
    @classmethod
    def reflect_static_member(cls, name):
        return PROC_DEFS.get(name)

    @classmethod
    def reflect_static_key(cls, key):
        return cls.reflect_static_member(key)

    @classmethod
    def getkeys(cls):
        return list(PROC_DEFS.keys())

    def resolve(self, name):
        return getattr(self, name)

    def select(self, key):
        return self.resolve(key)


PROC_DEFS = {
    "p_pid": int,
    "p_comm": six.text_type,
    "p_ppid": int}


structured.IStructured.implicit_static(for_types=(Process, _proc))
associative.IAssociative.implicit_static(for_types=(Process, _proc))
applicative.IApplicative.implicit_static(MockFunction)


class MockRootType(object):
    DATA = {
        "Process": Process,
        "proc": Process(10, "Finder", None),
        "MockFunction": MockFunction(),
        "pslist": repeated.meld(Process(1, "init", None),
                                Process(10, "Finder", None))
    }

    def resolve(self, name):
        return self.DATA[name]

    @classmethod
    def getmembers(cls):
        return list(cls.DATA.keys())


structured.IStructured.implicit_static(MockRootType)
