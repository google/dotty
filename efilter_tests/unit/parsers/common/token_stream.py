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

from efilter_tests import testlib

from efilter import errors

from efilter.parsers.common import grammar
from efilter.parsers.common import tokenizer
from efilter.parsers.common import token_stream


class TokenStreamTest(testlib.EfilterTestCase):
    def testFilters(self):
        t = tokenizer.LazyTokenizer("5 + 5 == foobar and 'hello, world!'")
        ts = token_stream.TokenStream(tokenizer=t)

        self.assertTrue(ts.accept(grammar.literal))
        self.assertFalse(ts.accept(grammar.literal))

        with self.assertRaises(errors.EfilterParseError):
            ts.expect(grammar.literal)

        self.assertTrue(ts.accept(grammar.symbol))

        with self.assertRaises(errors.EfilterParseError):
            ts.reject(grammar.literal)
