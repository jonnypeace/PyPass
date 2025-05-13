#!/bin/bash

python -m build
shiv -c pypass -o pypass.pyz dist/*.whl --compressed
cp pypass.pyz ~/.bin
