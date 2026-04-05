#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
export DISPLAY="${DISPLAY:-:0}"
python3 dfu_gui.py
