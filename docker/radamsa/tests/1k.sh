#!/bin/sh

set -e

echo "Generating 1k (trivial)"
echo 'x' | $@ --seed 42 -M tmp/meta -n 1000 -o - > /dev/null

echo "OK"
