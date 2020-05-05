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

import os
import sys
import subprocess
import unittest

from efilter import protocol

from efilter.protocols import repeated


# When messing around with the AST it can be handy to get the coverage tests
# to shut up temporarily.
TEST_COVERAGE = True


def get_fixture_path(name):
    return os.path.join("sample_data", name)


class EfilterTestCase(unittest.TestCase):
    def runPythonScript(self, script_path, args=()):
        cmd = [sys.executable, os.path.join(os.getcwd(), script_path)]
        cmd.extend(args)
        proc = subprocess.Popen(args=cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        err = proc.returncode

        return err, stdout, stderr

    def assertPythonScript(self, script_path, args=()):
        err, stdout, stderr = self.runPythonScript(script_path, args)

        self.assertEqual(err, 0)
        return stdout, stderr

    def assertImplemented(self, for_type, function):
        self.assertTrue(function.implemented_for_type(for_type),
                        "Multimethod %r is not implemented for %r." %
                        (function, for_type))

    def assertIsa(self, t, p):
        self.assertTrue(protocol.isa(t, p), "%r is not type %r." % (t, p))

    def assertItemsEqual(self, xv, yv):
        """Sorted comparison in a way that prevents Python 3 from bitching."""
        def _sortable_items(seq):
            for x in seq:
                if isinstance(x, dict):
                    yield sorted(x.items())
                else:
                    yield x

        self.assertEqual(sorted(_sortable_items(xv)),
                         sorted(_sortable_items(yv)))

    def assertValuesEqual(self, x, y):
        self.assertItemsEqual(repeated.getvalues(x), repeated.getvalues(y))

    def assertRaises(self, error_type, error_f=None):
        class _catcher(object):
            def __init__(self, case):
                self.case = case

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, tb):
                if exc_value is None:
                    return self.case.fail("Didn't raise %s!" % (error_type,))

                if not issubclass(exc_type, error_type):
                    return self.case.fail("Raised %s when %s was expected."
                                          " Full error: %s." % (
                                              exc_type, error_type, exc_value))

                if callable(error_f) and not error_f(exc_value):
                    return self.case.fail(
                        "Exception %r didn't match control lambda." % exc_value)

                return True

        return _catcher(self)
