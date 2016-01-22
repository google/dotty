#!/usr/bin/env python

from efilter_tests import benchmarks
from efilter_tests import benchmark


def get_benchmarks(module):
    for name in dir(module):
        obj = getattr(module, name)
        if (isinstance(obj, type)
                and issubclass(obj, benchmark.EfilterBenchmarkCase)):
            yield obj
        elif (isinstance(obj, type(module))
              and obj.__name__.startswith(module.__name__)):
            for case in get_benchmarks(obj):
                yield case


def main():
    # pylint: disable=superfluous-parens
    print "Running benchmarks..."
    for benchmark_cls in get_benchmarks(benchmarks):
        case = benchmark_cls()
        if case.fixture_name:
            print("%s: %s (read %d lines)" % (
                case.name, case.summary(), case.fixture_len()))
        else:
            print("%s: %s" % (case.name, case.summary()))


if __name__ == "__main__":
    main()
