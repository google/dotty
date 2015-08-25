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
from efilter.protocols import name_delegate


Process = collections.namedtuple("Process", ["pid", "name", "parent"])
_proc = collections.namedtuple("_proc", ["p_pid", "p_comm", "p_ppid"])


associative.IAssociative.implement(
    for_types=(Process, _proc),
    implementations={
        associative.select: lambda x, k: getattr(x, k, None),
        associative.resolve: lambda x, k: getattr(x, k, None),
        associative.getkeys: dir
    }
)


class MockApp(object):
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

    def reflect(self, name, scope=None):
        if scope is None:
            scope = name
            name = "_"
        elif isinstance(scope, type):
            scope = scope.__name__

        return self.DEFS.get(scope, {}).get(name)

    def provide(self, name):
        return self.GLOBALS.get(name)

    def getnames(self, scope=None):
        if scope:
            return self.DEFS.get(scope).keys()

        return self.DEFS.keys()


name_delegate.INameDelegate.implement(
    for_type=MockApp,
    implementations={
        name_delegate.reflect: MockApp.reflect,
        name_delegate.provide: MockApp.provide,
        name_delegate.getnames: MockApp.getnames,
    }
)
