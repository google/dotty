#!/bin/bash

# Find the top-level dir and change to it:

# Change working dir to one containing this script.
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Recurse up until we get to the top-level.
while [ ! -e "setup.py" ]
do
  cd ..

  if [[ "$(pwd)" == "/" ]]
  then
    echo "Cannot find top level directory."
    exit -1
  fi
done

echo "Working directory is $(pwd)"

echo "Going to run pylint and autopep8 now..."
for f in $( git diff master --name-only | grep ".py"); do
  if [ -e $f ]; then
    echo "Validating and reformatting $f"
    autopep8 --ignore E309,E711 -i -r --max-line-length 80 $f
    pylint --rcfile pylintrc $f
  fi
done

echo "Running unittest discover on efilter_tests..."
# Run the unit test suite.
python -m unittest discover efilter_tests -p "*"

# Run the benchmarks.
PYTHONPATH=./ efilter_tests/run_benchmarks.py
