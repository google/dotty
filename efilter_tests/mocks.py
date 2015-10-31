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

from efilter.protocols import associative
from efilter.protocols import reflective


class Process(collections.namedtuple("Process", ["pid", "name", "parent"])):
    @classmethod
    def reflect(cls, name):
        return PROCESS_DEFS.get(name)

    @classmethod
    def getkeys(cls):
        return PROCESS_DEFS.keys()


PROCESS_DEFS = {
    "pid": int,
    "name": unicode,
    "parent": Process}


class _proc(collections.namedtuple("_proc", ["p_pid", "p_comm", "p_ppid"])):
    @classmethod
    def reflect(cls, name):
        return PROCESS_DEFS.get(name)

    @classmethod
    def getkeys(cls):
        return PROCESS_DEFS.keys()


PROC_DEFS = {
    "p_pid": int,
    "p_comm": unicode,
    "p_ppid": int}


associative.IAssociative.implement(
    for_types=(Process, _proc),
    implementations={
        associative.select: lambda x, k: getattr(x, k, None),
        associative.resolve: lambda x, k: getattr(x, k, None)
    }
)


reflective.IReflective.implicit_dynamic(Process)
reflective.IReflective.implicit_dynamic(_proc)


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
        }
    }

    GLOBALS = {
        "_root_proc": _proc(1, "init", 0),
        "_current_proc": _proc(2, "foo", 1),
    }

    @classmethod
    def reflect(cls, name):
        if name == "Process":
            return Process

        if name == "_proc":
            return _proc

        return None

    @classmethod
    def getkeys(cls):
        return ("Process", "_proc")


reflective.IReflective.implicit_dynamic(MockRootType)
