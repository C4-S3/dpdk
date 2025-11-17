{
  description = "DPDK Comprehensive Fuzzing Infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # DPDK with debug symbols and sanitizer support
        dpdk-debug = pkgs.dpdk.overrideAttrs (oldAttrs: {
          mesonFlags = (oldAttrs.mesonFlags or []) ++ [
            "-Dbuildtype=debug"
            "-Db_sanitize=address,undefined"
            "-Db_lundef=false"  # Allow undefined symbols for sanitizers
            "-Ddisable_drivers=crypto/*,compress/*,event/*,baseband/*"  # Focus on vhost
            "-Denable_kmods=false"
            "-Dexamples="
            "-Dtests=true"
          ];

          # Enable maximum debug information
          env = (oldAttrs.env or {}) // {
            CFLAGS = "-g3 -O0 -fno-omit-frame-pointer -fsanitize=address,undefined";
            LDFLAGS = "-fsanitize=address,undefined";
          };
        });

        # AFL++ with all features
        afl-plus-plus = pkgs.aflplusplus.override {
          # Enable all AFL++ features
          stdenv = pkgs.llvmPackages_latest.stdenv;
        };

        # Custom Python environment for analysis scripts
        pythonEnv = pkgs.python311.withPackages (ps: with ps; [
          flask              # Web dashboard
          dash               # Interactive dashboards
          plotly             # Visualization
          pandas             # Data analysis
          numpy              # Numerical computation
          matplotlib         # Plotting
          requests           # HTTP requests
          pyyaml             # YAML parsing
          jinja2             # Template engine
          psutil             # System monitoring
          pygments           # Syntax highlighting
          rich               # Terminal formatting
        ]);

        # Build script for fuzzing harnesses
        buildHarness = name: pkgs.writeShellScriptBin "build-${name}" ''
          #!/usr/bin/env bash
          set -euo pipefail

          echo "[+] Building ${name} harness..."

          # AFL++ instrumented version
          ${afl-plus-plus}/bin/afl-clang-fast \
            -fsanitize=address,undefined \
            -g3 -O2 \
            -fno-omit-frame-pointer \
            -I${dpdk-debug}/include \
            -I../harnesses \
            harnesses/${name}_fuzzer.c \
            -L${dpdk-debug}/lib \
            -ldpdk \
            -o harnesses/${name}_fuzzer_afl

          # libFuzzer version
          ${pkgs.llvmPackages_latest.clang}/bin/clang \
            -fsanitize=fuzzer,address,undefined \
            -g3 -O1 \
            -fno-omit-frame-pointer \
            -I${dpdk-debug}/include \
            -I../harnesses \
            harnesses/${name}_fuzzer.c \
            -L${dpdk-debug}/lib \
            -ldpdk \
            -o harnesses/${name}_fuzzer_libfuzzer

          # Honggfuzz version
          ${pkgs.honggfuzz}/bin/hfuzz-clang \
            -fsanitize=address,undefined \
            -g3 -O2 \
            -fno-omit-frame-pointer \
            -I${dpdk-debug}/include \
            -I../harnesses \
            harnesses/${name}_fuzzer.c \
            -L${dpdk-debug}/lib \
            -ldpdk \
            -o harnesses/${name}_fuzzer_hf

          echo "[✓] Built all versions of ${name} harness"
        '';

      in
      {
        devShells.default = pkgs.mkShell {
          name = "dpdk-fuzzing-env";

          buildInputs = with pkgs; [
            # Core fuzzing tools
            afl-plus-plus           # AFL++ fuzzer
            honggfuzz               # Honggfuzz fuzzer
            llvmPackages_latest.clang  # For libFuzzer
            llvmPackages_latest.llvm   # LLVM tools

            # DPDK and dependencies
            dpdk-debug
            numactl
            libbsd
            libpcap
            zlib
            openssl
            jansson

            # Build tools
            meson
            ninja
            pkg-config
            cmake
            gcc
            gdb

            # Analysis and debugging tools
            valgrind                # Memory error detection
            rr                      # Record & replay debugger
            llvmPackages_latest.libllvm  # For symbolization
            llvmPackages_latest.bintools # addr2line, etc.
            strace                  # System call tracer
            ltrace                  # Library call tracer
            perf-tools              # Performance analysis
            heaptrack               # Heap profiler

            # Coverage tools
            lcov                    # Coverage visualization
            gcovr                   # Coverage reports

            # Python environment for analysis
            pythonEnv

            # Utilities
            parallel                # GNU parallel for multi-core fuzzing
            tmux                    # Terminal multiplexer
            screen                  # Alternative terminal multiplexer
            htop                    # System monitor
            iotop                   # I/O monitor
            nethogs                 # Network monitor
            jq                      # JSON processor
            yq                      # YAML processor
            ripgrep                 # Fast grep
            fd                      # Fast find
            bat                     # Better cat
            eza                     # Better ls
            fzf                     # Fuzzy finder

            # Documentation
            man-pages
            man-pages-posix

            # Optional: Container/VM tools for isolation
            docker
            podman
            qemu

            # Harness build scripts
            (buildHarness "descriptor_chain")
            (buildHarness "control_queue")
            (buildHarness "multiqueue")
            (buildHarness "memory_pressure")
            (buildHarness "integration")
          ];

          shellHook = ''
            #!/usr/bin/env bash

            # Banner
            echo "╔═══════════════════════════════════════════════════════════╗"
            echo "║   DPDK Comprehensive Fuzzing Infrastructure               ║"
            echo "║   Production-Ready Automated Vulnerability Discovery      ║"
            echo "╚═══════════════════════════════════════════════════════════╝"
            echo ""

            # Set up environment variables
            export FUZZING_ROOT="$(pwd)"
            export DPDK_DIR="${dpdk-debug}"
            export PATH="$FUZZING_ROOT/scripts:$PATH"

            # AFL++ configuration
            export AFL_PATH="${afl-plus-plus}/lib/afl"
            export AFL_SKIP_CPUFREQ=1           # Skip CPU freq check
            export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  # Allow running as root
            export AFL_NO_AFFINITY=1            # Don't pin to CPU cores

            # Enable sanitizers
            export ASAN_OPTIONS="detect_leaks=1:symbolize=1:abort_on_error=1:disable_coredump=0:unmap_shadow_on_exit=1"
            export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
            export LSAN_OPTIONS="suppressions=$FUZZING_ROOT/lsan_suppressions.txt"
            export MSAN_OPTIONS="symbolize=1:abort_on_error=1"
            export TSAN_OPTIONS="second_deadlock_stack=1"

            # Symbolization
            export LLVM_SYMBOLIZER_PATH="${pkgs.llvmPackages_latest.bintools}/bin/llvm-symbolizer"

            # Core dump configuration
            export ASAN_OPTIONS="$ASAN_OPTIONS:unmap_shadow_on_exit=1"
            ulimit -c unlimited  # Enable core dumps

            # Python environment
            export PYTHONPATH="$FUZZING_ROOT/analysis:$PYTHONPATH"

            # Create necessary directories
            mkdir -p results/{crashes,coverage,reports}
            mkdir -p corpus/{seeds,generated}
            mkdir -p logs

            # Info
            echo "Environment Variables:"
            echo "  FUZZING_ROOT    = $FUZZING_ROOT"
            echo "  DPDK_DIR        = $DPDK_DIR"
            echo "  AFL_PATH        = $AFL_PATH"
            echo ""

            echo "Available Tools:"
            echo "  Fuzzers:"
            echo "    - afl-fuzz       (AFL++ fuzzer)"
            echo "    - afl-clang-fast (AFL++ compiler)"
            echo "    - honggfuzz      (Honggfuzz fuzzer)"
            echo "    - clang -fsanitize=fuzzer (libFuzzer)"
            echo ""
            echo "  Analysis:"
            echo "    - gdb            (GNU debugger)"
            echo "    - valgrind       (Memory error detector)"
            echo "    - rr             (Record & replay debugger)"
            echo "    - lcov           (Coverage visualization)"
            echo ""
            echo "  Scripts:"
            echo "    - ./scripts/setup.sh           (Initial setup)"
            echo "    - ./scripts/fuzz-all.sh        (Start all fuzzers)"
            echo "    - ./scripts/monitor.sh         (Launch dashboard)"
            echo "    - ./scripts/analyze-results.sh (Analyze crashes)"
            echo ""

            echo "Quick Start:"
            echo "  1. ./scripts/setup.sh              # One-time setup"
            echo "  2. ./scripts/fuzz-all.sh           # Start fuzzing"
            echo "  3. ./scripts/monitor.sh            # Monitor progress"
            echo "  4. ./scripts/analyze-results.sh    # Analyze results"
            echo ""

            # Check system configuration
            if [ -f /proc/sys/kernel/core_pattern ]; then
              CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern)
              if [[ "$CORE_PATTERN" == "|"* ]]; then
                echo "⚠  WARNING: Core pattern is piped to external program."
                echo "   This may interfere with AFL++. Consider:"
                echo "   sudo sh -c 'echo core >/proc/sys/kernel/core_pattern'"
                echo ""
              fi
            fi

            # Check CPU scaling
            if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
              GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
              if [ "$GOVERNOR" != "performance" ]; then
                echo "⚠  WARNING: CPU governor is '$GOVERNOR', not 'performance'."
                echo "   For best fuzzing performance, consider:"
                echo "   sudo cpupower frequency-set -g performance"
                echo ""
              fi
            fi

            echo "✓ Fuzzing environment ready!"
            echo ""
          '';

          # Environment variables for build
          DPDK_DIR = "${dpdk-debug}";
          PKG_CONFIG_PATH = "${dpdk-debug}/lib/pkgconfig";
          LD_LIBRARY_PATH = "${dpdk-debug}/lib";

          # Sanitizer configuration
          hardeningDisable = [ "fortify" ];  # Disable fortify for sanitizers
        };

        # Package outputs
        packages = {
          # DPDK with debug symbols
          dpdk-debug = dpdk-debug;

          # Fuzzing dashboard
          dashboard = pkgs.writeShellScriptBin "fuzzing-dashboard" ''
            #!/usr/bin/env bash
            cd ${self}
            ${pythonEnv}/bin/python monitoring/dashboard.py "$@"
          '';

          # Crash analyzer
          analyze-crashes = pkgs.writeShellScriptBin "analyze-crashes" ''
            #!/usr/bin/env bash
            cd ${self}
            ${pythonEnv}/bin/python analysis/crash_dedup.py "$@"
          '';
        };

        # Apps for easy execution
        apps = {
          dashboard = {
            type = "app";
            program = "${self.packages.${system}.dashboard}/bin/fuzzing-dashboard";
          };

          analyze = {
            type = "app";
            program = "${self.packages.${system}.analyze-crashes}/bin/analyze-crashes";
          };
        };

        # Checks for CI/CD
        checks = {
          # Verify environment builds correctly
          env-check = pkgs.runCommand "env-check" {
            buildInputs = [ afl-plus-plus pkgs.llvmPackages_latest.clang ];
          } ''
            # Verify AFL++ is available
            ${afl-plus-plus}/bin/afl-fuzz -h > /dev/null
            echo "AFL++ OK" > $out

            # Verify libFuzzer is available
            ${pkgs.llvmPackages_latest.clang}/bin/clang -fsanitize=fuzzer -x c - -o /tmp/test_fuzzer <<EOF
            #include <stdint.h>
            #include <stddef.h>
            int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }
            EOF
            echo "libFuzzer OK" >> $out

            # Verify Python environment
            ${pythonEnv}/bin/python -c "import flask, dash, pandas, matplotlib"
            echo "Python OK" >> $out
          '';
        };
      }
    );
}
