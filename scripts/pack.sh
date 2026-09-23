#!/usr/bin/env bash
# Packs the three library NuGet packages AND the caconsole tool package into
# dist/nuget/. Version comes from src/Directory.Build.props.
#
# -p:PackTool=true is what makes the CLI packable at all: PackAsTool cannot carry a
# platform-specific TFM, so the tool is packed for net10.0 alone, and the flag switches the CLI
# project to that single target for this pass. Windows is served by scripts/publish.sh's
# self-contained win-x64 binary, built from net10.0-windows — the only build with the right ABI.
set -euo pipefail
cd "$(dirname "$0")/.."

dotnet pack CAManagement.sln -c Release -o dist/nuget --nologo -v q -p:PackTool=true

echo
echo "==> packages"
ls -lh dist/nuget/*.nupkg | awk '{print $5" "$9}'
