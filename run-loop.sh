#!/bin/bash
cd "$(dirname $0)"
while true; do
  bash run.sh || exit $?
done
