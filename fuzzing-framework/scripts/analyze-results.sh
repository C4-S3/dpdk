#!/usr/bin/env bash
#
# Analyze all fuzzing results and generate reports
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   Analyzing Fuzzing Results                              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

cd "$ROOT_DIR"

# Analyze crashes for each harness
for harness in descriptor_chain control_queue multiqueue memory_pressure integration; do
    findings_dir="results/findings_$harness"

    if [ ! -d "$findings_dir" ]; then
        echo "[*] No findings for $harness (not yet run)"
        continue
    fi

    echo "[+] Analyzing $harness..."

    # Check for crashes
    crashes_dir="$findings_dir/default/crashes"
    if [ -d "$crashes_dir" ]; then
        n_crashes=$(find "$crashes_dir" -name 'id:*' -type f | wc -l)
        echo "  Crashes found: $n_crashes"

        if [ $n_crashes -gt 0 ]; then
            # Run deduplication
            python3 analysis/crash_dedup.py "$harness"
        fi
    else
        echo "  No crashes found"
    fi

    # Check for hangs
    hangs_dir="$findings_dir/default/hangs"
    if [ -d "$hangs_dir" ]; then
        n_hangs=$(find "$hangs_dir" -name 'id:*' -type f | wc -l)
        echo "  Hangs found: $n_hangs"
    fi

    # Show fuzzing stats
    stats_file="$findings_dir/default/fuzzer_stats"
    if [ -f "$stats_file" ]; then
        execs_done=$(grep "execs_done" "$stats_file" | cut -d: -f2 | tr -d ' ')
        execs_per_sec=$(grep "execs_per_sec" "$stats_file" | cut -d: -f2 | tr -d ' ')
        corpus_count=$(grep "corpus_count" "$stats_file" | cut -d: -f2 | tr -d ' ')

        echo "  Total executions: $execs_done"
        echo "  Speed: $execs_per_sec exec/s"
        echo "  Corpus size: $corpus_count"
    fi

    echo ""
done

echo "[✓] Analysis complete!"
echo ""
echo "Reports saved in: results/crashes/"
echo ""
