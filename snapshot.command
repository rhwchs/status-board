#!/bin/bash
# Double-click on a Mac: checks every source once and opens the result in your browser.
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "This needs Python 3 (free). Get it at https://www.python.org/downloads/ then double-click this file again."
else
  python3 snapshot.py
fi
echo; read -n 1 -s -r -p "Press any key to close this window."
