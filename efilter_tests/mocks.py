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

__author__ = "Adam Sindelar <adamsh@google.com>"

import collections

from efilter.protocols import applicative
from efilter.protocols import associative
from efilter.protocols import structured

from efilter.stdlib import core as std_core


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
        return PROCESS_DEFS.keys()

    def resolve(self, name):
        return getattr(self, name)

    def select(self, key):
        return self.resolve(key)


PROCESS_DEFS = {
    "pid": int,
    "name": unicode,
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
        return PROC_DEFS.keys()

    def resolve(self, name):
        return getattr(self, name)

    def select(self, key):
        return self.resolve(key)


PROC_DEFS = {
    "p_pid": int,
    "p_comm": unicode,
    "p_ppid": int}


structured.IStructured.implicit_static(for_types=(Process, _proc))
associative.IAssociative.implicit_static(for_types=(Process, _proc))
applicative.IApplicative.implicit_static(MockFunction)


class MockRootType(object):
    DEFS = {
        "Process": {
            "_": Process,
            "pid": int,
            "name": unicode,
            "parent": Process,
        },
        "_proc": {
            "_": _proc,
            "p_pid": int,
            "p_comm": unicode,
            "p_ppid": int,
        },
        "MockFunction": {
            "_": MockFunction,
        }
    }

    def resolve(self, name):
        return self.DEFS[name]()

    @classmethod
    def reflect_static_member(cls, name):
        if name in cls.DEFS:
            return cls.DEFS[name]["_"]

        return type(std_core.FUNCTIONS.get(name))

    @classmethod
    def getmembers_static(cls):
        return cls.DEFS.keys()


structured.IStructured.implicit_static(MockRootType)
