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

"""EFILTER abstract type system."""

from efilter import dispatch
from efilter import protocol

# Declarations:
# pylint: disable=unused-argument


@dispatch.multimethod
def apply(applicative, args, kwargs):
    """Return the result of calling 'applicative' with 'args'.

    Host program should implement function whitelisting in this function!
    """
    raise NotImplementedError()


@dispatch.multimethod
def isapplicative(x):
    return isinstance(x, IApplicative)


class IApplicative(protocol.Protocol):
    _required_functions = (apply,)
    _optional_functions = ()
