#!/usr/bin/env bash
# Packs the three library NuGet packages (IsPackable projects only) into
# dist/nuget/. Version comes from src/Directory.Build.props.
set -euo pipefail
cd "$(dirname "$0")/.."

dotnet pack CAManagement.sln -c Release -o dist/nuget --nologo -v q

echo
echo "==> packages"
ls -lh dist/nuget/*.nupkg | awk '{print $5" "$9}'
