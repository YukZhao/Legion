#!/bin/sh

set -e

echo "HAL 9000" | $@ --output-template "FOO%fBAR" | grep -q "^FOO.*BAR$"

