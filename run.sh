#!/bin/sh
# DirHunter Linux/macOS 启动器
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
    python3 dirhunter.py "$@"
elif command -v python >/dev/null 2>&1; then
    python dirhunter.py "$@"
else
    echo "[!] python3 not found"
    exit 1
fi
