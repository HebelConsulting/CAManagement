#!/usr/bin/env bash
# Publishes caconsole as a self-contained single-file binary for each supported
# platform into dist/<rid>/. Configuration is pure CLI options (no config
# file). No trimming (reflection-based DI) and no ReadyToRun (keeps cross-OS
# publishing from macOS possible).
set -euo pipefail
cd "$(dirname "$0")/.."

rids=(osx-arm64 osx-x64 linux-x64)

for rid in "${rids[@]}"; do
    echo "==> publishing $rid"
    dotnet publish src/CAManagement.Cli/CAManagement.Cli.csproj \
        -c Release -r "$rid" --self-contained true \
        -p:PublishSingleFile=true -p:DebugType=embedded \
        -o "dist/$rid" --nologo -v q
done

echo
echo "==> results"
for rid in "${rids[@]}"; do
    ls -lh "dist/$rid/caconsole" | awk -v rid="$rid" '{print rid": "$5" "$9}'
done
