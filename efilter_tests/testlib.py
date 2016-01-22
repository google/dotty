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

import os
import unittest

from efilter import protocol

from efilter.protocols import repeated


# When messing around with the AST it can be handy to get the coverage tests
# to shut up temporarily.
TEST_COVERAGE = True


def get_fixture_path(name):
    return os.path.join("efilter_tests", "fixtures", name)


class EfilterTestCase(unittest.TestCase):
    def assertImplemented(self, for_type, function):
        self.assertTrue(function.implemented_for_type(for_type),
                        "Multimethod %r is not implemented for %r." %
                        (function, for_type))

    def assertIsa(self, t, p):
        self.assertTrue(protocol.isa(t, p), "%r is not type %r." % (t, p))

    def assertValuesEqual(self, x, y):
        self.assertItemsEqual(repeated.getvalues(x), repeated.getvalues(y))
