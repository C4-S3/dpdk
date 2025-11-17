# DPDK Fuzzing Infrastructure Makefile

.PHONY: all clean setup fuzz monitor analyze help

CC ?= gcc
AFL_CC ?= afl-clang-fast
CFLAGS = -g3 -O2 -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS_DEBUG = -g3 -O0 -fsanitize=address,undefined

HARNESSES = descriptor_chain control_queue multiqueue memory_pressure integration
HARNESS_SRCS = $(addprefix harnesses/,$(addsuffix _fuzzer.c,$(HARNESSES)))
HARNESS_BINS = $(addprefix harnesses/,$(addsuffix _fuzzer,$(HARNESSES)))
HARNESS_AFL_BINS = $(addprefix harnesses/,$(addsuffix _fuzzer_afl,$(HARNESSES)))

all: $(HARNESS_BINS) $(HARNESS_AFL_BINS)

# Standalone versions (for testing)
harnesses/%_fuzzer: harnesses/%_fuzzer.c harnesses/common.h
	@echo "[CC] $@"
	$(CC) $(CFLAGS_DEBUG) $< -o $@

# AFL++ versions (for fuzzing)
harnesses/%_fuzzer_afl: harnesses/%_fuzzer.c harnesses/common.h
	@echo "[AFL] $@"
	$(AFL_CC) $(CFLAGS) $< -o $@

setup:
	@echo "Running setup script..."
	@./scripts/setup.sh

fuzz: setup
	@echo "Starting all fuzzers..."
	@./scripts/fuzz-all.sh

monitor:
	@echo "Starting monitor..."
	@./scripts/monitor.sh

analyze:
	@echo "Analyzing results..."
	@./scripts/analyze-results.sh

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(HARNESS_BINS) $(HARNESS_AFL_BINS)
	rm -rf results/findings_*
	rm -rf logs/*.log

help:
	@echo "DPDK Fuzzing Infrastructure - Make Targets"
	@echo ""
	@echo "  make all       - Build all harnesses (AFL++ and standalone)"
	@echo "  make setup     - Run initial setup"
	@echo "  make fuzz      - Start all fuzzers in tmux"
	@echo "  make monitor   - Monitor fuzzing progress"
	@echo "  make analyze   - Analyze crash results"
	@echo "  make clean     - Clean build artifacts and results"
	@echo "  make help      - Show this help"
	@echo ""
