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
EFILTER test suite.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import unittest

from efilter.ext import superposition


class SuperpositionTest(unittest.TestCase):
    """This file only tests the specifities of ext.superpositions.

    efilter.protocols.test_superpositon has additional tests, based on the
    generic protocol.
    """

    def testMutability(self):
        """Test adding states."""
        s = superposition.HashedSuperposition(1, 2, 3)
        s.add_state(4)
        self.assertEqual(sorted(s.getstates()), [1, 2, 3, 4])

        # Adding another superposition should leave us flat.
        s.add_state(superposition.HashedSuperposition(4, 5))
        self.assertEqual(sorted(s.getstates()), [1, 2, 3, 4, 5])
