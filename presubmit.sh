#!/bin/bash

# Find the top-level dir and change to it:

echo "PRESUBMIT: Trying to find working directory..."

# Change working dir to one containing this script.
cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Recurse up until we get to the top-level.
while [ ! -e "setup.py" ]
do
  cd ..

  if [[ "$(pwd)" == "/" ]]
  then
    echo "PRESUBMIT: Cannot find top level directory."
    exit -1
  fi
done

echo "PRESUBMIT: Working directory is $(pwd)"

echo "PRESUBMIT: Going to run pylint and autopep8 now..."
for f in $( git diff master --name-only | grep ".py"); do
  if [ -e $f ]; then
    echo "Validating and reformatting $f"
    autopep8 --ignore E309,E301,E711 -i -r --max-line-length 80 $f
    pylint --rcfile pylintrc $f
  fi
done


echo "PRESUBMIT: Running EFILTER tests..."
tox -- python -m unittest discover efilter_tests -p "*"

echo "PRESUBMIT: Running end-to-end and sample code tests..."
tox -- python -m unittest discover sample_projects -p "*_test*"

echo "PRESUBMIT: Cleaning up..."
rm -rf efilter.egg-info/ .cache/
rm -rf .tox
find . -iname "*.pyc" -delete
find . -iname __pycache__ -delete
