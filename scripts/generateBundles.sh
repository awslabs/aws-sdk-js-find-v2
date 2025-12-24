#!/bin/sh
set -e
if [ "$1" != "--skip-build" ]; then
  docker build -t generate-bundles scripts
fi
docker run --rm -v "$(pwd)":/app generate-bundles
