# -*- coding: utf-8 -*-

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

"""EFILTER abstract type system.

DEPRECATION NOTICE

IIndexable is no longer used by any parts of EFILTER and user software no
longer needs to implement it for any purpose. Because some applications
do implement IIndexable it continues to be around but will eventually be
removed.

Implementations of IIndexable can be safely removed and do not need to be
replaced with anything.
"""

from efilter import dispatch
from efilter import protocol
from efilter.protocols import hashable

# Declarations:
# pylint: disable=unused-argument


@dispatch.multimethod
def indices(x):
    """DEPRECATED: Return a list of keys to represent 'self' in maps."""
    raise NotImplementedError()


class IIndexable(protocol.Protocol):
    """DEPRECATED: if you're still using this you can safely remove."""
    _required_functions = (indices,)
