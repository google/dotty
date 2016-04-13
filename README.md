# EFILTER Query Language

EFILTER is a general purpose query language designed to be embedded in Python applications and libraries. It supports SQL-like syntax to filter your application's data and provides a convenient way to directly search through the objects your applications manages.

A second use case for EFILTER is to translate queries from one query language to another, such as from SQL to OpenIOC and so on. A basic SQL-like syntax and a POC lisp implementation are included with the language, and others are relatively simple to add.

## Projects using EFILTER:

 - [Rekall](https://github.com/google/rekall)


## Quick examples of integration.

    from efilter import api
    api.apply("5 + 5") # => 10

    # Returns [{"name": "Alice"}, {"name": "Eve"}]
    api.apply("SELECT name FROM users WHERE age > 10",
              vars={"users": ({"age": 10, "name": "Bob"},
                              {"age": 20, "name": "Alice"},
                              {"age": 30, "name": "Eve"}))


### You can also filter custom objects:

    # Step 1: have a custom class.

    class MyUser(object):
        ...

    # Step 2: Implement a protocol (like an interface).

    from efilter.protocols import structured
    structured.IStructured.implement(
        for_type=MyUser,
        implementations: {
            structured.resolve: lambda user, key: getattr(user, key)
        }
    )

    # Step 3: EFILTER can now use my class!
    from efilter import api
    api.apply("SELECT name FROM users WHERE age > 10 ORDER BY age",
              vars={"users": [MyUser(...), MyUser(...)]})


### Don't have SQL injections.

EFILTER supports query templates, which can interpolate unescaped strings safely.

    # Replacements are applied before the query is compiled.
    search_term = dangerous_user_input["name"]
    api.apply("SELECT * FROM users WHERE name = ?",
              vars={"users": [...]},
              replacements=[search_term])

    # We also support keyword replacements.
    api.apply("SELECT * FROM users WHERE name = {name}",
              vars={"users": [...]},
              replacements={"name": search_term})


### Basic IO is supported, including CSV data sets.

    # Builtin IO functions need to be explicitly enabled.
    api.apply("SELECT * FROM csv(users.csv) WHERE name = 'Bob'", allow_io=True)


## Language Reference

Work in progress.


## Protocol documentation

Work in progress.


## Example projects

Several sample projects are provided.

 - examples/star_catalog: filters a large CSV file with nearby star systems
 - examples/tagging: use a custom query format


## License and Copyright

Copyright 2015 Google Inc. All Rights Reserved

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contributors

[Adam Sindelar](https://github.com/the80srobot)
