#!/bin/sh
set -e
if [ "$1" != "--skip-build" ]; then
  finch build -t generate-bundles scripts
fi
finch run --rm -v "$(pwd)":/app generate-bundles
