#!/usr/bin/env python3
"""
Crash Deduplication Tool

Analyzes crashes from fuzzing campaigns and deduplicates based on stack traces.
"""

import os
import sys
import hashlib
import subprocess
import json
from pathlib import Path
from collections import defaultdict

ROOT_DIR = Path(__file__).parent.parent
RESULTS_DIR = ROOT_DIR / "results"

def get_crash_signature(crash_path, binary_path):
    """
    Generate unique signature from crash stack trace.

    Returns: (signature, stack_frames)
    """
    try:
        # Run binary with crash input
        result = subprocess.run(
            [binary_path],
            stdin=open(crash_path, 'rb'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )

        output = result.stderr.decode('utf-8', errors='ignore')

        # Extract ASAN stack trace
        frames = []
        in_stack = False
        for line in output.split('\n'):
            if 'AddressSanitizer' in line or 'SEGV' in line:
                in_stack = True

            if in_stack and '#' in line:
                # Example: "    #0 0x123456 in func_name file.c:123"
                parts = line.split(' in ')
                if len(parts) >= 2:
                    func_file = parts[1].strip()
                    # Only include DPDK frames (skip libc, sanitizer)
                    if 'dpdk' in func_file.lower() or 'vhost' in func_file.lower():
                        frames.append(func_file)

        # Generate signature from top 5 frames
        if not frames:
            frames = ['unknown_crash']

        signature_input = '\n'.join(frames[:5])
        signature = hashlib.sha256(signature_input.encode()).hexdigest()[:16]

        return signature, frames

    except Exception as e:
        print(f"[!] Error analyzing crash: {e}")
        return f"error_{hash(str(e)) % 10000:04x}", ['error']

def analyze_crashes(findings_dir, harness_name):
    """
    Analyze all crashes for a harness.

    Returns: dict of {signature: [crash_files]}
    """
    crashes_dir = findings_dir / "default" / "crashes"

    if not crashes_dir.exists():
        print(f"[*] No crashes found in {crashes_dir}")
        return {}

    crash_files = [f for f in crashes_dir.iterdir() if f.is_file() and f.name.startswith('id:')]

    if not crash_files:
        print(f"[*] No crash files found")
        return {}

    print(f"[+] Found {len(crash_files)} crashes, analyzing...")

    binary_path = ROOT_DIR / "harnesses" / f"{harness_name}_fuzzer"
    signatures = defaultdict(list)

    for crash_file in crash_files:
        sig, frames = get_crash_signature(crash_file, binary_path)
        signatures[sig].append({
            'file': str(crash_file),
            'frames': frames
        })

        print(f"  {crash_file.name}: {sig}")

    return signatures

def save_dedup_report(signatures, harness_name, output_dir):
    """Save deduplication report"""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"dedup_{harness_name}.json"

    report = {
        'harness': harness_name,
        'total_crashes': sum(len(crashes) for crashes in signatures.values()),
        'unique_crashes': len(signatures),
        'signatures': {}
    }

    for sig, crashes in signatures.items():
        report['signatures'][sig] = {
            'count': len(crashes),
            'crashes': crashes
        }

    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[✓] Report saved: {report_path}")
    return report

def print_summary(report):
    """Print summary of crash analysis"""
    print("")
    print("=" * 60)
    print(f"  Crash Analysis Summary: {report['harness']}")
    print("=" * 60)
    print(f"  Total crashes:     {report['total_crashes']}")
    print(f"  Unique signatures: {report['unique_crashes']}")
    print(f"  Dedup rate:        {100 * (1 - report['unique_crashes'] / max(report['total_crashes'], 1)):.1f}%")
    print("")

    print("  Top crash signatures:")
    sorted_sigs = sorted(report['signatures'].items(), key=lambda x: x[1]['count'], reverse=True)
    for i, (sig, data) in enumerate(sorted_sigs[:5], 1):
        frames = data['crashes'][0]['frames'][:3]
        print(f"    {i}. {sig} ({data['count']} crashes)")
        for frame in frames:
            print(f"       → {frame}")
    print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 crash_dedup.py <harness_name>")
        print("Example: python3 crash_dedup.py descriptor_chain")
        sys.exit(1)

    harness_name = sys.argv[1]
    findings_dir = RESULTS_DIR / f"findings_{harness_name}"

    if not findings_dir.exists():
        print(f"[!] Findings directory not found: {findings_dir}")
        sys.exit(1)

    print("╔═══════════════════════════════════════════════════════════╗")
    print("║   Crash Deduplication Analysis                           ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("")

    signatures = analyze_crashes(findings_dir, harness_name)

    if not signatures:
        print("[*] No crashes to analyze")
        sys.exit(0)

    report = save_dedup_report(signatures, harness_name, RESULTS_DIR / "crashes")
    print_summary(report)

if __name__ == '__main__':
    main()
