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
Tests for using the provider protocol. This is a work in progress.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import unittest

from efilter_tests import mocks

from efilter.protocols import data_provider


# pylint: disable=unused-argument, protected-access


class BaseProvider(object):
    pass


class ProcSource(BaseProvider):
    FIXTURES = (
        mocks._proc(1, "init", 0),
        mocks._proc(2, "foo", 1),
        mocks._proc(4, "login", 1),
        mocks._proc(5, "Finder", 4))

    def provide(self, query=None, params=None):
        if query:
            hint = query.run("hinter", selector="_proc")
        else:
            hint = None

        for proc in self.FIXTURES:
            if hint:
                if hint.run("matcher", proc):
                    yield proc
                    return
            else:
                yield proc

    def declare_output(self, query=None):
        return (mocks._proc,)

    def declare_input(self, query=None):
        return None


class ProcParser(BaseProvider):
    def provide(self, query=None, params=None):
        for proc in params["procs"]:
            yield mocks.Process(pid=proc.p_pid,
                                name=proc.p_comm,
                                parent=mocks.Process(pid=proc.p_ppid))

    def declare_output(self, query=None):
        return (mocks.Process,)

    def declare_input(self, query=None):
        return dict(procs="isa _proc")


data_provider.IDataProvider.implicit_dynamic(for_type=BaseProvider)


class StrategyTest(unittest.TestCase):
    def testFindProcess(self):
        pass
