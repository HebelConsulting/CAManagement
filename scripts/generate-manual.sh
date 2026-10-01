#!/usr/bin/env bash
# Compiles the caconsole manual (manual/manual.typ) with Typst to manual/CAManagement-caconsole-Manual.pdf.
# Compile-only, and permanently so: caconsole is a command-line tool, so there are no screens to capture and
# no reason for this script to grow the capture leg its sibling repositories have.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v typst >/dev/null 2>&1 || { echo "ERROR: typst not found (brew install typst / cargo install typst-cli)."; exit 1; }

echo "==> Compiling the manual…"
typst compile manual/manual.typ manual/CAManagement-caconsole-Manual.pdf \
  --input generated="$(date -u +%F)"
echo "==> manual/CAManagement-caconsole-Manual.pdf"
