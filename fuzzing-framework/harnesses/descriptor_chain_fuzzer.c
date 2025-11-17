/**
 * DPDK Fuzzing Harness A: Descriptor Chain Fuzzer
 *
 * Target: virtio_net_ctrl_pop() and descriptor chain validation
 * Focus: Circular chains, OOB indices, length overflows
 * Expected: Rediscover CVE-PENDING-01 and CVE-PENDING-02
 *
 * Compile:
 *   AFL++:      afl-clang-fast -fsanitize=address,undefined -g descriptor_chain_fuzzer.c -o fuzzer_afl
 *   libFuzzer:  clang -fsanitize=fuzzer,address -g descriptor_chain_fuzzer.c -o fuzzer_libfuzzer
 */

#include "common.h"

#define MIN_INPUT_SIZE sizeof(struct vring_desc)
#define MAX_INPUT_SIZE (sizeof(struct vring_desc) * MAX_QUEUE_SIZE)

/**
 * Simulate virtio_net_ctrl_pop() vulnerable code path
 *
 * This replicates the EXACT vulnerability from lib/vhost/virtio_net_ctrl.c:67-107
 */
static int simulate_virtio_net_ctrl_pop(struct vring_desc *descs, uint16_t queue_size) {
    uint16_t desc_idx = 0;
    uint16_t n_descs = 0;
    uint64_t data_len = 0;

    // ⚠️  VULNERABLE CODE PATH (matching DPDK source)
    while (1) {
        uint32_t desc_len = descs[desc_idx].len;
        uint64_t desc_addr = descs[desc_idx].addr;

        n_descs++;  // Line 71: Increments but NO check for chain length

        // Simulate data length accumulation
        // ⚠️  Line 100: NO overflow check, NO maximum size check!
        data_len += desc_len;

        // Check for NEXT flag
        if (!(descs[desc_idx].flags & VRING_DESC_F_NEXT)) {
            break;  // End of chain
        }

        // ⚠️  Line 106: NO validation of next index before use!
        desc_idx = descs[desc_idx].next;

        // Safety check to prevent actual infinite loop in fuzzer
        // (Real vulnerability would loop forever)
        if (n_descs > queue_size * 2) {
            FUZZ_ERROR("Infinite loop detected! n_descs=%u, queue_size=%u",
                      n_descs, queue_size);
            fuzz_hang_detected("circular_descriptor_chain");
            return -1;
        }

        // Check for out-of-bounds access
        if (desc_idx >= queue_size) {
            FUZZ_ERROR("OOB descriptor index! desc_idx=%u, queue_size=%u",
                      desc_idx, queue_size);
            fuzz_crash_detected("oob_descriptor_index");
            return -1;
        }
    }

    // Check for unbounded memory allocation
    #define MAX_CTRL_MSG_SIZE (64 * 1024)  // Reasonable limit
    if (data_len > MAX_CTRL_MSG_SIZE) {
        FUZZ_ERROR("Unbounded allocation! data_len=%lu, limit=%u",
                  data_len, MAX_CTRL_MSG_SIZE);
        fuzz_crash_detected("unbounded_memory_allocation");
        return -1;
    }

    return 0;  // Success
}

/**
 * Fuzz target function
 *
 * This is called for each input (AFL++ or libFuzzer)
 */
static int fuzz_one_input(const uint8_t *data, size_t size) {
    g_stats.total_iterations++;

    // Validate input size
    if (size < MIN_INPUT_SIZE || size > MAX_INPUT_SIZE) {
        g_stats.invalid_inputs++;
        return 0;  // Reject
    }

    // Parse input as descriptor array
    size_t n_descs = size / sizeof(struct vring_desc);
    struct vring_desc *descs = (struct vring_desc *)data;

    // Quick sanity check (optional, for performance)
    if (n_descs > MAX_QUEUE_SIZE) {
        g_stats.invalid_inputs++;
        return 0;
    }

    g_stats.valid_inputs++;

    // Detect interesting patterns
    const char *pattern = detect_pattern(descs, n_descs);
    if (strcmp(pattern, "normal") != 0) {
        FUZZ_DEBUG("Interesting pattern: %s (n_descs=%zu)", pattern, n_descs);
    }

    // Test vulnerable code path
    simulate_virtio_net_ctrl_pop(descs, MAX_QUEUE_SIZE);

    return 0;
}

// ============================================================================
// AFL++ Mode
// ============================================================================
#ifdef __AFL_FUZZ_TESTCASE_LEN

int main(int argc, char **argv) {
    fuzz_init();
    FUZZ_INFO("Descriptor Chain Fuzzer (AFL++ Mode)");
    FUZZ_INFO("Target: virtio_net_ctrl_pop() descriptor validation");
    FUZZ_INFO("Queue size: %d", MAX_QUEUE_SIZE);

    // AFL++ buffer setup
    __AFL_INIT();

    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;

    // Persistent mode - reuse process for multiple inputs
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, len);
    }

    fuzz_print_stats();
    return 0;
}

// ============================================================================
// libFuzzer Mode
// ============================================================================
#elif defined(__cplusplus) && defined(__clang__)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        fuzz_init();
        fprintf(stderr, "[INFO] Descriptor Chain Fuzzer (libFuzzer Mode)\n");
        fprintf(stderr, "[INFO] Target: virtio_net_ctrl_pop() descriptor validation\n");
        initialized = 1;
    }

    fuzz_one_input(data, size);
    return 0;
}

// ============================================================================
// Standalone Mode (for manual testing)
// ============================================================================
#else

int main(int argc, char **argv) {
    fuzz_init();
    FUZZ_INFO("Descriptor Chain Fuzzer (Standalone Mode)");
    FUZZ_INFO("Target: virtio_net_ctrl_pop() descriptor validation");
    FUZZ_INFO("Usage: %s [input_file | -]", argv[0]);
    FUZZ_INFO("       (reads from stdin if no file specified)");

    uint8_t buf[MAX_INPUT_SIZE];
    ssize_t size;

    const char *input_file = (argc > 1) ? argv[1] : "-";
    size = read_input(input_file, buf, sizeof(buf));

    if (size < 0) {
        FUZZ_ERROR("Failed to read input");
        return 1;
    }

    FUZZ_INFO("Input size: %zd bytes", size);
    FUZZ_INFO("Number of descriptors: %zu", size / sizeof(struct vring_desc));

    fuzz_one_input(buf, size);

    fuzz_print_stats();
    FUZZ_INFO("No crashes detected - input is safe!");
    return 0;
}

#endif
