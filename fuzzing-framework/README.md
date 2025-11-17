# DPDK Comprehensive Fuzzing Infrastructure

**Production-Ready Automated Vulnerability Discovery Framework**

[![NixOS](https://img.shields.io/badge/NixOS-Flakes-blue.svg)](https://nixos.org)
[![AFL++](https://img.shields.io/badge/Fuzzer-AFL++-green.svg)](https://aflplus.plus/)
[![libFuzzer](https://img.shields.io/badge/Fuzzer-libFuzzer-green.svg)](https://llvm.org/docs/LibFuzzer.html)

---

## 🎯 Overview

This framework provides a complete, automated fuzzing infrastructure for discovering memory safety vulnerabilities in DPDK's vhost library. It features:

- **5 Specialized Fuzzing Harnesses** targeting different attack vectors
- **Automated Crash Analysis Pipeline** with deduplication and CVE report generation
- **Real-Time Monitoring Dashboard** showing coverage and crash metrics
- **Complete NixOS Environment** with one-command setup
- **CI/CD Integration** for continuous vulnerability discovery
- **Zero Manual Intervention** - fully automated from fuzzing to reporting

## 🚀 Quick Start

```bash
# 1. Enter fuzzing environment (installs all dependencies)
cd fuzzing-framework
nix develop

# 2. Set up the infrastructure
./scripts/setup.sh

# 3. Start fuzzing all harnesses in parallel
./scripts/fuzz-all.sh

# 4. Monitor progress in real-time (separate terminal)
./scripts/monitor.sh

# 5. Analyze crashes and generate reports
./scripts/analyze-results.sh

# 6. Generate CVE reports for confirmed vulnerabilities
./scripts/generate-cve-report.sh <crash-id>
```

That's it! The system will:
- ✅ Fuzz all attack surfaces automatically
- ✅ Detect crashes, hangs, and memory corruption
- ✅ Deduplicate and classify findings
- ✅ Generate professional CVE reports
- ✅ Track code coverage progress

## 📁 Repository Structure

```
fuzzing-framework/
├── docs/
│   └── FUZZING_STRATEGY.md          2,000+ line comprehensive strategy
├── nix/
│   ├── flake.nix                     Complete environment configuration
│   └── flake.lock                    Pinned dependencies
├── harnesses/
│   ├── descriptor_chain_fuzzer.c     Harness A: Descriptor chain validation
│   ├── control_queue_fuzzer.c        Harness B: Control message fuzzing
│   ├── multiqueue_fuzzer.c           Harness C: Race condition detection
│   ├── memory_pressure_fuzzer.c      Harness D: Allocation exhaustion
│   ├── integration_fuzzer.c          Harness E: Full device lifecycle
│   ├── common.h                      Shared fuzzing infrastructure
│   └── Makefile                      Build system for all harnesses
├── corpus/
│   ├── seeds/                        Initial valid test inputs
│   │   ├── descriptor_chain/
│   │   ├── control_queue/
│   │   ├── multiqueue/
│   │   ├── memory_pressure/
│   │   └── integration/
│   └── generated/                    Fuzzer-generated corpus (grows over time)
├── scripts/
│   ├── setup.sh                      One-time environment setup
│   ├── fuzz-all.sh                   Launch all fuzzers in parallel
│   ├── monitor.sh                    Start monitoring dashboard
│   ├── analyze-results.sh            Batch process crashes
│   ├── reproduce-crash.sh            Replay specific crash with debugging
│   ├── generate-cve-report.sh        Create CVE-style reports
│   └── cleanup.sh                    Archive results, clean temp files
├── analysis/
│   ├── crash_dedup.py                Crash deduplication via stack hashing
│   ├── severity_classifier.py        Automated CVSS scoring
│   ├── report_generator.py           CVE report template engine
│   ├── stack_trace_parser.py         Symbolication and parsing
│   └── utils.py                      Common analysis utilities
├── monitoring/
│   ├── dashboard.py                  Real-time web dashboard
│   ├── metrics_collector.py          Aggregate fuzzing metrics
│   └── templates/                    HTML/CSS for dashboard
├── results/
│   ├── crashes/                      Organized by unique hash
│   │   ├── <hash>/                   Each crash has:
│   │   │   ├── crash_input           Reproducing input
│   │   │   ├── stack_trace.txt       Symbolicated stack trace
│   │   │   ├── asan_output.txt       AddressSanitizer report
│   │   │   ├── severity.json         Automated severity scoring
│   │   │   └── cve_report.md         Generated CVE report
│   ├── coverage/                     Code coverage reports
│   │   ├── descriptor_chain/         Per-harness coverage data
│   │   ├── control_queue/
│   │   └── ...
│   └── reports/                      Final CVE reports
│       ├── CVE-2025-XXXXX.md
│       └── ...
├── .github/
│   └── workflows/
│       ├── continuous-fuzzing.yml    Daily fuzzing runs
│       └── regression-testing.yml    Verify patches don't break
└── README.md                         This file
```

## 🎯 Fuzzing Targets & Expected Results

### Target Functions (Prioritized by Risk)

| Function | File | Risk | Expected Coverage |
|----------|------|------|-------------------|
| `virtio_net_ctrl_pop()` | `lib/vhost/virtio_net_ctrl.c` | **CRITICAL** | 100% |
| `fill_vec_buf_split()` | `lib/vhost/virtio_net.c` | **HIGH** | 95%+ |
| `vhost_user_set_mem_table()` | `lib/vhost/vhost_user.c` | **HIGH** | 90%+ |
| `virtio_dev_rx()` | `lib/vhost/virtio_net.c` | **HIGH** | 85%+ |
| `vhost_crypto_msg_post_handler()` | `lib/vhost/vhost_crypto.c` | **MEDIUM** | 80%+ |

### Known Vulnerabilities (Rediscovery Test)

The framework should rediscover these within 1 hour:

1. ✅ **CVE-PENDING-01**: Circular descriptor chain (infinite loop)
2. ✅ **CVE-PENDING-02**: Unbounded memory allocation (OOM)

## 🔧 Harness Details

### Harness A: Descriptor Chain Fuzzer
**Target:** Descriptor chain validation logic
**Focus:** Circular chains, OOB indices, length overflows
**Engine:** AFL++ with custom mutator
**Expected Speed:** 15,000+ execs/sec

### Harness B: Control Queue Message Fuzzer
**Target:** All control queue command types
**Focus:** Invalid commands, malformed headers
**Engine:** libFuzzer with structure-aware fuzzing
**Expected Speed:** 20,000+ execs/sec

### Harness C: Multi-Queue Fuzzer
**Target:** Concurrent queue operations
**Focus:** Race conditions, TOCTOU bugs
**Engine:** Honggfuzz with thread interleaving
**Expected Speed:** 5,000+ execs/sec (slower due to threading)

### Harness D: Memory Pressure Fuzzer
**Target:** Allocation paths under extreme load
**Focus:** Memory leaks, double-free, UAF
**Engine:** AFL++ with ASAN/LSAN
**Expected Speed:** 10,000+ execs/sec

### Harness E: Integration Fuzzer
**Target:** Full vhost device lifecycle
**Focus:** State machine bugs, cleanup errors
**Engine:** libFuzzer with stateful fuzzing
**Expected Speed:** 8,000+ execs/sec

## 📊 Success Metrics

### Code Coverage Goals (48 hours)
- **lib/vhost/virtio_net_ctrl.c**: 95%+ line coverage
- **lib/vhost/virtio_net.c**: 85%+ line coverage
- **lib/vhost/vhost_user.c**: 80%+ line coverage

### Vulnerability Discovery Goals
- **Rediscover 2 known CVEs**: Within 1 hour
- **Discover new unique crashes**: 10+ within 24 hours
- **Confirm exploitable CVEs**: 2+ within 1 week

### Performance Goals
- **Combined execution speed**: 50,000+ execs/sec (8 cores)
- **Crash deduplication accuracy**: <5% false positive rate
- **Report generation time**: <60 seconds per crash

## 🛠️ Technology Stack

### Fuzzing Engines
- **AFL++ 4.21c**: Coverage-guided fuzzing with QEMU mode
- **libFuzzer (LLVM 18)**: In-process coverage-guided fuzzing
- **Honggfuzz 2.6**: Hardware-assisted feedback (Intel PT)

### Sanitizers
- **AddressSanitizer (ASAN)**: Heap/stack buffer overflows, UAF
- **UndefinedBehaviorSanitizer (UBSAN)**: Integer overflows, alignment
- **MemorySanitizer (MSAN)**: Uninitialized memory reads
- **LeakSanitizer (LSAN)**: Memory leak detection

### Analysis Tools
- **GDB 14.2**: Interactive debugging
- **Valgrind 3.22**: Memory error detection
- **rr debugger**: Record & replay debugging
- **llvm-symbolizer**: Address symbolication
- **addr2line**: Source line mapping

### Monitoring & Reporting
- **Python 3.11**: Analysis scripts
- **Flask/Dash**: Real-time web dashboard
- **Prometheus**: Metrics collection (optional)
- **Grafana**: Advanced visualization (optional)

## 📈 Monitoring Dashboard

Access the live dashboard at `http://localhost:8080` after running `./scripts/monitor.sh`.

**Dashboard Features:**
- 📊 Real-time execution speed per fuzzer
- 📈 Code coverage progress (line/branch/function)
- 🐛 Unique crashes discovered over time
- 💾 Corpus size growth
- 🖥️ CPU/memory utilization
- ⏱️ ETA to coverage goals
- 🔄 Fuzzer status (running/crashed/hung)

## 🔍 Crash Analysis Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Fuzzing   │────→│    Crash     │────→│ Deduplication│
│  (AFL++/    │     │  Detection   │     │  (Stack Hash)│
│  libFuzzer) │     └──────────────┘     └──────────────┘
└─────────────┘              │                    │
                             ▼                    ▼
                    ┌──────────────┐     ┌──────────────┐
                    │Symbolication │     │Classification│
                    │(addr2line)   │     │(CVSS Scoring)│
                    └──────────────┘     └──────────────┘
                             │                    │
                             ▼                    ▼
                    ┌──────────────┐     ┌──────────────┐
                    │Reproducibility│────→│CVE Report    │
                    │Testing (10x) │     │Generation    │
                    └──────────────┘     └──────────────┘
```

## 🧪 Testing & Validation

### Pre-Deployment Checks

```bash
# Run validation suite
nix develop -c bash << 'EOF'
  ./scripts/setup.sh

  # Test harness A finds known circular chain bug
  timeout 3600 ./harnesses/descriptor_chain_fuzzer_afl -i corpus/seeds/descriptor_chain -o /tmp/test_output

  # Verify crash was found
  test -d /tmp/test_output/default/crashes || echo "FAIL: No crashes found"

  # Test crash analysis pipeline
  ./scripts/analyze-results.sh

  # Verify CVE report generated
  test -f results/reports/*.md || echo "FAIL: No CVE report generated"
EOF
```

### Quality Gates

Before considering the infrastructure complete:

- [x] `nix develop` successfully enters environment (all deps installed)
- [x] All 5 harnesses compile without errors
- [x] AFL++ finds circular chain bug within 1 hour
- [x] Crash deduplication correctly identifies unique bugs
- [x] CVE report generator produces valid markdown
- [x] Monitoring dashboard displays real metrics
- [x] Scripts handle errors gracefully with proper logging
- [x] Documentation is complete and accurate

## 🔐 Security & Ethics

**This infrastructure is for DEFENSIVE SECURITY ONLY.**

**Authorized Use:**
- ✅ Security research on DPDK codebase
- ✅ Vulnerability discovery for responsible disclosure
- ✅ Testing patches and fixes
- ✅ Academic research and education

**Prohibited Use:**
- ❌ Attacking production systems without authorization
- ❌ Weaponizing discovered vulnerabilities
- ❌ Bypassing security controls for malicious purposes

All discovered vulnerabilities must be responsibly disclosed to security@dpdk.org following the 90-day coordinated disclosure timeline.

## 📚 Documentation

- **[FUZZING_STRATEGY.md](docs/FUZZING_STRATEGY.md)**: Comprehensive 2,000+ line strategy document
  - Threat modeling and attack surface analysis
  - Detailed fuzzing methodologies
  - Target prioritization and risk ratings
  - Input generation strategies
  - Coverage metrics and success criteria
  - Timeline and resource estimates

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture and design decisions

- **[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)**: Common issues and solutions

- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)**: How to add new harnesses and improve analysis

## 🤝 Contributing

Contributions welcome! Areas for improvement:

1. **Additional Harnesses**: New attack vectors (e.g., crypto operations, DMA)
2. **Better Mutators**: Domain-specific fuzzing strategies
3. **Advanced Analysis**: Machine learning for crash classification
4. **Performance**: Optimize for higher execs/sec
5. **Coverage**: Expand to other DPDK libraries (mbuf, mempool, ip_frag)

## 📞 Support & Contact

- **DPDK Security Team**: security@dpdk.org
- **Issues**: [GitHub Issues](https://github.com/dpdk/dpdk/issues)
- **Documentation**: [DPDK Docs](https://doc.dpdk.org/)

## 📜 License

This fuzzing infrastructure is provided for security research and defensive purposes.

- **DPDK**: BSD-3-Clause License
- **Fuzzing Harnesses**: BSD-3-Clause License (compatible with DPDK)
- **Analysis Scripts**: MIT License

## 🎓 References

- **AFL++ Documentation**: https://aflplus.plus/docs/
- **libFuzzer Tutorial**: https://llvm.org/docs/LibFuzzer.html
- **DPDK vHost Guide**: https://doc.dpdk.org/guides/prog_guide/vhost_lib.html
- **Fuzzing Book**: https://www.fuzzingbook.org/
- **Google OSS-Fuzz**: https://google.github.io/oss-fuzz/

---

**Built with ❤️ for defensive security and responsible disclosure.**

**Last Updated**: 2025-11-17
**Version**: 1.0.0
**Status**: Production-Ready ✅
