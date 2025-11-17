#!/usr/bin/env bash
#
# Simple monitoring for fuzzing progress
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

clear

while true; do
    tput cup 0 0
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   DPDK Fuzzing Monitor - $(date '+%Y-%m-%d %H:%M:%S')    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    for harness in descriptor_chain control_queue multiqueue memory_pressure integration; do
        findings_dir="results/findings_$harness"
        stats_file="$findings_dir/default/fuzzer_stats"

        if [ ! -f "$stats_file" ]; then
            printf "%-20s: Not running\n" "$harness"
            continue
        fi

        # Extract stats
        execs_done=$(grep "execs_done" "$stats_file" | cut -d: -f2 | tr -d ' ' || echo "0")
        execs_per_sec=$(grep "execs_per_sec" "$stats_file" | cut -d: -f2 | tr -d ' ' || echo "0")
        corpus_count=$(grep "corpus_count" "$stats_file" | cut -d: -f2 | tr -d ' ' || echo "0")
        crashes=$(find "$findings_dir/default/crashes" -name 'id:*' -type f 2>/dev/null | wc -l)
        hangs=$(find "$findings_dir/default/hangs" -name 'id:*' -type f 2>/dev/null | wc -l)

        printf "%-20s: %10s execs | %6s/s | corpus:%5s | crashes:%3s | hangs:%3s\n" \
            "$harness" "$execs_done" "$execs_per_sec" "$corpus_count" "$crashes" "$hangs"
    done

    echo ""
    echo "Press Ctrl+C to exit | Refresh: 2s"
    echo "╚═══════════════════════════════════════════════════════════╝"

    sleep 2
done
