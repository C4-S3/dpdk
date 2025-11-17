#!/usr/bin/env bash
#
# Launch all fuzzing harnesses in parallel
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

FUZZ_DURATION=${FUZZ_DURATION:-0}  # 0 = infinite
TIMEOUT=${TIMEOUT:-1000}  # 1 second per execution

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   Starting All Fuzzing Harnesses                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if AFL++ is available
if ! command -v afl-fuzz &>/dev/null; then
    echo "[ERROR] AFL++ not found. Please run inside 'nix develop'"
    exit 1
fi

# Create tmux session for all fuzzers
SESSION="dpdk-fuzzing"

if tmux has-session -t $SESSION 2>/dev/null; then
    echo "[*] Killing existing fuzzing session..."
    tmux kill-session -t $SESSION
fi

echo "[+] Creating new tmux session: $SESSION"
# Create session with a shell in the first window
tmux new-session -d -s $SESSION -n "Fuzzers"

# Small delay to ensure session is ready (helps with Wayland/Sway)
sleep 0.5

# Harness A: Descriptor Chain (Main fuzzer) - pane 0
tmux send-keys -t $SESSION:0.0 "cd $ROOT_DIR" C-m
tmux send-keys -t $SESSION:0.0 "echo '[Harness A] Descriptor Chain Fuzzer'" C-m
tmux send-keys -t $SESSION:0.0 "afl-fuzz -i corpus/seeds/descriptor_chain -o results/findings_descriptor_chain -M fuzzer_descriptor_chain -t ${TIMEOUT}+ -m none -- ./harnesses/descriptor_chain_fuzzer_afl @@" C-m

# Harness B: Control Queue - pane 1
tmux split-window -t $SESSION:0 -v
tmux send-keys -t $SESSION:0.1 "cd $ROOT_DIR && sleep 2" C-m
tmux send-keys -t $SESSION:0.1 "echo '[Harness B] Control Queue Fuzzer'" C-m
tmux send-keys -t $SESSION:0.1 "afl-fuzz -i corpus/seeds/control_queue -o results/findings_control_queue -M fuzzer_control_queue -t ${TIMEOUT}+ -m none -- ./harnesses/control_queue_fuzzer_afl @@" C-m

# Harness C: Multi-Queue - pane 2
tmux split-window -t $SESSION:0.0 -h
tmux send-keys -t $SESSION:0.2 "cd $ROOT_DIR && sleep 4" C-m
tmux send-keys -t $SESSION:0.2 "echo '[Harness C] Multi-Queue Fuzzer'" C-m
tmux send-keys -t $SESSION:0.2 "afl-fuzz -i corpus/seeds/multiqueue -o results/findings_multiqueue -M fuzzer_multiqueue -t ${TIMEOUT}+ -m none -- ./harnesses/multiqueue_fuzzer_afl @@" C-m

# Harness D: Memory Pressure - pane 3
tmux split-window -t $SESSION:0.1 -h
tmux send-keys -t $SESSION:0.3 "cd $ROOT_DIR && sleep 6" C-m
tmux send-keys -t $SESSION:0.3 "echo '[Harness D] Memory Pressure Fuzzer'" C-m
tmux send-keys -t $SESSION:0.3 "afl-fuzz -i corpus/seeds/memory_pressure -o results/findings_memory_pressure -M fuzzer_memory_pressure -t ${TIMEOUT}+ -m none -- ./harnesses/memory_pressure_fuzzer_afl @@" C-m

# Harness E: Integration - separate window
tmux new-window -t $SESSION -n "Harness-E"
tmux send-keys -t $SESSION:1 "cd $ROOT_DIR && sleep 8" C-m
tmux send-keys -t $SESSION:1 "echo '[Harness E] Integration Fuzzer'" C-m
tmux send-keys -t $SESSION:1 "afl-fuzz -i corpus/seeds/integration -o results/findings_integration -M fuzzer_integration -t ${TIMEOUT}+ -m none -- ./harnesses/integration_fuzzer_afl @@" C-m

# Return focus to first window
tmux select-window -t $SESSION:0

echo ""
echo "[✓] All fuzzers launched in tmux session: $SESSION"
echo ""
echo "To view fuzzing progress:"
echo "  tmux attach -t $SESSION"
echo ""
echo "Keyboard shortcuts inside tmux:"
echo "  Ctrl-b + arrow keys    Navigate panes"
echo "  Ctrl-b + d             Detach session"
echo "  Ctrl-b + [             Scroll mode (q to exit)"
echo ""
echo "To stop all fuzzers:"
echo "  tmux kill-session -t $SESSION"
echo ""
echo "Monitor dashboard:"
echo "  ./scripts/monitor.sh"
echo ""
