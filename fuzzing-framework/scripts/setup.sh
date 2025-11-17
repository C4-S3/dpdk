#!/usr/bin/env bash
#
# DPDK Fuzzing Infrastructure Setup Script
# One-time environment configuration
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   DPDK Fuzzing Infrastructure - Setup                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Create directory structure
echo "[+] Creating directory structure..."
mkdir -p "$ROOT_DIR"/{results/{crashes,coverage,reports},corpus/{seeds,generated},logs}

for harness in descriptor_chain control_queue multiqueue memory_pressure integration; do
    mkdir -p "$ROOT_DIR/corpus/seeds/$harness"
    mkdir -p "$ROOT_DIR/corpus/generated/$harness"
done

# Build all harnesses
echo "[+] Building fuzzing harnesses..."
cd "$ROOT_DIR"

if command -v afl-clang-fast &>/dev/null; then
    for harness in descriptor_chain control_queue multiqueue memory_pressure integration; do
        echo "  Building $harness..."

        # AFL++ version
        afl-clang-fast -fsanitize=address,undefined -g3 -O2 \
            harnesses/${harness}_fuzzer.c \
            -o harnesses/${harness}_fuzzer_afl \
            2>&1 | tee "logs/${harness}_build_afl.log"

        # Standalone version (for testing)
        gcc -fsanitize=address,undefined -g3 -O0 \
            harnesses/${harness}_fuzzer.c \
            -o harnesses/${harness}_fuzzer \
            2>&1 | tee "logs/${harness}_build_standalone.log"
    done

    echo "[✓] All harnesses built successfully"
else
    echo "[!] AFL++ not found - using GCC only"
    for harness in descriptor_chain control_queue multiqueue memory_pressure integration; do
        gcc -fsanitize=address,undefined -g3 -O0 \
            harnesses/${harness}_fuzzer.c \
            -o harnesses/${harness}_fuzzer
    done
fi

# Generate seed corpus
echo "[+] Generating seed corpus..."
python3 "$ROOT_DIR/scripts/generate_seeds.py"

# System configuration checks
echo "[+] Checking system configuration..."

# Core pattern
if [ -f /proc/sys/kernel/core_pattern ]; then
    CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern)
    if [[ "$CORE_PATTERN" == "|"* ]]; then
        echo "[!] WARNING: Core pattern is piped. For better fuzzing:"
        echo "    sudo sh -c 'echo core >/proc/sys/kernel/core_pattern'"
    fi
fi

# CPU scaling
if command -v cpupower &>/dev/null; then
    GOVERNOR=$(cpupower frequency-info -p 2>/dev/null | grep 'governor' | awk '{print $NF}' || echo "unknown")
    if [ "$GOVERNOR" != "performance" ]; then
        echo "[!] WARNING: CPU governor is '$GOVERNOR'. For best performance:"
        echo "    sudo cpupower frequency-set -g performance"
    fi
fi

# ASLR
if [ -f /proc/sys/kernel/randomize_va_space ]; then
    ASLR=$(cat /proc/sys/kernel/randomize_va_space)
    if [ "$ASLR" -eq 2 ]; then
        echo "[*] ASLR is enabled (good for finding real bugs)"
    fi
fi

echo ""
echo "[✓] Setup complete!"
echo ""
echo "Next steps:"
echo "  1. ./scripts/fuzz-all.sh        # Start all fuzzers"
echo "  2. ./scripts/monitor.sh         # Monitor progress"
echo "  3. ./scripts/analyze-results.sh # Analyze crashes"
echo ""
