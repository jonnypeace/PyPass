#!/bin/bash

# Make sure you’re in your virtualenv first!

# 1) Upgrade pip itself
python3 -m pip install --upgrade pip setuptools wheel

# 2) List outdated in “columns” format, skip the header, pull the first field, and xargs-upgrade
python3 -m pip list --outdated --format=columns \
  | tail -n +3 \
  | awk '{print $1}' \
  | xargs -r -n1 python3 -m pip install --upgrade

