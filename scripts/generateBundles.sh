#!/bin/sh
docker build -t generate-bundles scripts
docker run --rm -v "$(pwd)":/app generate-bundles
