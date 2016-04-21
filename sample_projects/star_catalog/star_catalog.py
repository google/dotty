#!/usr/bin/env python

# EFILTER sample project - star catalog filter.
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
A sample project that uses EFILTER to analyze a CSV file.
"""

from __future__ import print_function


__author__ = "Adam Sindelar <adamsh@google.com>"

import os


# The API module is the easiest way to use EFILTER - the functions, 'apply',
# 'search' and 'infer', take care of parsing and using the query.
from efilter import api


# This is a CSV file with the HYG star catalog in it. A complete list of fields
# can be found at the astronexus page [1]. Of interest to us are:
#
# - "proper": A common name for the star, such as "Sirius". - "dist": The
# distance in parsecs. - "mag": The star's apparent magnitude.
#
# 1: https://github.com/astronexus/HYG-Database/blob/master/README.md
CATALOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            "..", "..", "sample_data", "hygdata_v3.csv")


# Let's declare a user function for the demo!
def parsec2ly(parsecs):
    """Convert parsecs to light years.

    This is an example of a user-defined function that can be called
    from inside an EFILTER query.
    """
    return parsecs * 3.262


QUERIES = [
    # Basic example query.
    ("Count the lines in the file.", "count(csv(?))"),

    # More complex SELECT query:
    ("Find the first 10 stars with proper names.",
     "SELECT "
     " proper AS Name,"  # Note the 'AS' which works exactly as it does in SQL.
     " cast(mag, float),"  # The CSV file contains strings, but we can cast.
     " parsec2ly(cast(dist, float)) AS ly"  # ...and call functions.
     " FROM csv(?, decode_header:true)"  # Note the keyword argument.
     " WHERE proper LIMIT 10"),

    # EFILTER supports the pseudo-SQL syntax as convenience. The processing
    # is actually accomplished using familiar map/filter/sort functions.
    ("Get 3 proper names exactly 6 characters in length.",
     "map("
     " take(3, filter(csv(?, decode_header:true), count(proper) == 6)),"
     " proper)")
]


def main():
    for description, query in QUERIES:
        print("# %s\n%s" % (description, query))

        # We can find out what the EFILTER query will return by using the type
        # inference system. If it is a repeated value, we can render it in
        # multiple rows.
        result_type = api.infer(query,
                                replacements=[CATALOG_PATH],
                                libs=("stdcore", "stdio"))
        print("# Return type will be %s." % (result_type.__name__,))

        # api.apply will give us the actual result of running the query, which
        # should be of the type we got above.
        results = api.apply(query,
                            replacements=[CATALOG_PATH],
                            allow_io=True,
                            # We provide the top level variables in a 'vars'
                            # argument. To bind 'parsec2ly' to the function of
                            # the same name, we have to also wrap it in the
                            # EFILTER user_func. This prevents EFILTER from
                            # accidentally calling regular Python functions.
                            vars={"parsec2ly": api.user_func(parsec2ly)})

        # Because we don't know the cardinality of the query in 'query' we can
        # use 'getvalues' to always receive an iterator of results. This is just
        # a convenience function.
        for n, result in enumerate(api.getvalues(results)):
            print("%d - %r" % (n + 1, result))

        print("\n\n")


if __name__ == "__main__":
    main()
