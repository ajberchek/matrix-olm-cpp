#!/bin/bash

files="$@"
if [ -n "${files}" ]; then
  echo Found and fixed errors within the following files:
  for f in ${files}; do
      if [ `clang-format "$f" | diff -q "$f" - | wc -l` != 0 ]; then
        echo "$f"
        echo "-----------------"
        clang-format "$f" | diff -y "$f" -
        fi
  done
  exit 1
fi

