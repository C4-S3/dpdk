#!/usr/bin/env python3
"""
Generate seed corpus for all fuzzing harnesses
"""

import os
import struct
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDS_DIR = os.path.join(ROOT_DIR, "corpus", "seeds")

# VirtIO constants
VRING_DESC_F_NEXT = 1
VRING_DESC_F_WRITE = 2
VRING_DESC_F_INDIRECT = 4

def write_seed(harness, name, data):
    """Write seed file"""
    path = os.path.join(SEEDS_DIR, harness, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    print(f"  Created: {harness}/{name} ({len(data)} bytes)")

def pack_descriptor(addr, length, flags, next_idx):
    """Pack a VirtIO descriptor"""
    return struct.pack('<QIHH', addr, length, flags, next_idx)

def generate_descriptor_chain_seeds():
    """Generate seeds for Harness A: Descriptor Chain"""
    print("[+] Generating Descriptor Chain seeds...")

    # Seed 1: Valid single descriptor
    data = pack_descriptor(0x1000, 100, 0, 0)
    write_seed('descriptor_chain', 'valid_single', data)

    # Seed 2: Valid chain (2 descriptors)
    data = pack_descriptor(0x1000, 100, VRING_DESC_F_NEXT, 1)
    data += pack_descriptor(0x2000, 200, 0, 0)
    write_seed('descriptor_chain', 'valid_chain_2', data)

    # Seed 3: Valid chain (5 descriptors)
    data = b''
    for i in range(5):
        flags = VRING_DESC_F_NEXT if i < 4 else 0
        data += pack_descriptor(0x1000 + i*0x1000, 100, flags, i+1)
    write_seed('descriptor_chain', 'valid_chain_5', data)

    # Seed 4: Circular chain (CVE-PENDING-01)
    data = pack_descriptor(0x1000, 100, VRING_DESC_F_NEXT, 1)
    data += pack_descriptor(0x2000, 100, VRING_DESC_F_NEXT, 0)  # Loop!
    write_seed('descriptor_chain', 'vuln_circular_2', data)

    # Seed 5: Maximum length descriptors (CVE-PENDING-02)
    data = b''
    for i in range(10):
        flags = VRING_DESC_F_NEXT if i < 9 else 0
        data += pack_descriptor(0x1000, 0xFFFFFFFF, flags, i+1)
    write_seed('descriptor_chain', 'vuln_max_length', data)

    # Seed 6: Zero-length descriptor
    data = pack_descriptor(0x1000, 0, 0, 0)
    write_seed('descriptor_chain', 'edge_zero_length', data)

    # Seed 7: NULL address
    data = pack_descriptor(0x0, 100, 0, 0)
    write_seed('descriptor_chain', 'edge_null_addr', data)

    # Seed 8: Out-of-bounds next index
    data = pack_descriptor(0x1000, 100, VRING_DESC_F_NEXT, 300)
    write_seed('descriptor_chain', 'vuln_oob_next', data)

def generate_control_queue_seeds():
    """Generate seeds for Harness B: Control Queue"""
    print("[+] Generating Control Queue seeds...")

    # Control message header: class + cmd
    for cmd_class in range(7):  # VIRTIO_NET_CTRL_* commands
        for cmd in range(3):
            data = struct.pack('BB', cmd_class, cmd)
            data += b'\x00' * 16  # Dummy payload
            write_seed('control_queue', f'cmd_{cmd_class}_{cmd}', data)

def generate_multiqueue_seeds():
    """Generate seeds for Harness C: Multi-Queue"""
    print("[+] Generating Multi-Queue seeds...")

    # Queue operations: queue_id + operation + data
    for n_ops in [2, 4, 8]:
        data = b''
        for i in range(n_ops):
            queue_id = i % 4
            operation = i % 3
            op_data = bytes([i] * 64)
            data += struct.pack('BB', queue_id, operation) + op_data
        write_seed('multiqueue', f'ops_{n_ops}', data)

def generate_memory_pressure_seeds():
    """Generate seeds for Harness D: Memory Pressure"""
    print("[+] Generating Memory Pressure seeds...")

    # Allocation operations: operation + size + index
    for pattern in ['alloc_only', 'free_only', 'mixed']:
        data = b''
        for i in range(20):
            if pattern == 'alloc_only':
                op = 0
            elif pattern == 'free_only':
                op = 1
            else:
                op = i % 3

            size = (i + 1) * 100
            index = i
            data += struct.pack('<BHH', op, size, index)
        write_seed('memory_pressure', pattern, data)

def generate_integration_seeds():
    """Generate seeds for Harness E: Integration"""
    print("[+] Generating Integration seeds...")

    # State transitions: target_state + params
    for n_transitions in [5, 10, 20]:
        data = b''
        for i in range(n_transitions):
            target_state = (i % 6)
            params = bytes([i] * 7)
            data += struct.pack('B', target_state) + params
        write_seed('integration', f'transitions_{n_transitions}', data)

def main():
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║   Generating Seed Corpus                                 ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("")

    generate_descriptor_chain_seeds()
    generate_control_queue_seeds()
    generate_multiqueue_seeds()
    generate_memory_pressure_seeds()
    generate_integration_seeds()

    print("")
    print("[✓] Seed corpus generated successfully!")
    print(f"    Location: {SEEDS_DIR}")

if __name__ == '__main__':
    main()
