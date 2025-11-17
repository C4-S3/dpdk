/**
 * DPDK Fuzzing Harness Common Infrastructure
 *
 * Shared structures, utilities, and helper functions for all fuzzing harnesses.
 */

#ifndef DPDK_FUZZING_COMMON_H
#define DPDK_FUZZING_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Fuzzer-specific includes
#ifdef __AFL_FUZZ_TESTCASE_LEN
  // AFL++ persistent mode
  __AFL_FUZZ_INIT();
  #define AFL_LOOP(n) __AFL_LOOP(n)
#else
  #define AFL_LOOP(n) 1
#endif

// VirtIO constants
#define VRING_DESC_F_NEXT       1
#define VRING_DESC_F_WRITE      2
#define VRING_DESC_F_INDIRECT   4

#define MAX_QUEUE_SIZE 256
#define MAX_DESCRIPTOR_LEN 0xFFFFFFFF

// VirtIO descriptor structure
struct vring_desc {
    uint64_t addr;    // Guest physical address
    uint32_t len;     // Length
    uint16_t flags;   // Flags
    uint16_t next;    // Next descriptor index
} __attribute__((packed));

// Control queue structures (virtio-net)
struct virtio_net_ctrl_hdr {
    uint8_t class;
    uint8_t cmd;
} __attribute__((packed));

// Fuzzing statistics
struct fuzz_stats {
    uint64_t total_iterations;
    uint64_t crashes_detected;
    uint64_t hangs_detected;
    uint64_t valid_inputs;
    uint64_t invalid_inputs;
};

// Global stats
static struct fuzz_stats g_stats = {0};

/**
 * Initialize fuzzing environment
 */
static inline void fuzz_init(void) {
    // Disable buffering for immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Set up signal handlers for crash detection
    // (Sanitizers will handle most crashes)

    memset(&g_stats, 0, sizeof(g_stats));
}

/**
 * Read input data from file or stdin
 */
static inline ssize_t read_input(const char *filename, uint8_t *buf, size_t max_size) {
    int fd = STDIN_FILENO;
    ssize_t bytes_read;

    if (filename && strcmp(filename, "-") != 0) {
        fd = open(filename, O_RDONLY);
        if (fd < 0) {
            perror("open");
            return -1;
        }
    }

    bytes_read = read(fd, buf, max_size);

    if (fd != STDIN_FILENO) {
        close(fd);
    }

    return bytes_read;
}

/**
 * Validate descriptor chain structure
 * Returns 1 if valid, 0 if invalid
 */
static inline int validate_descriptor_chain(struct vring_desc *descs,
                                            size_t n_descs,
                                            uint16_t queue_size) {
    if (n_descs == 0 || n_descs > queue_size) {
        return 0;
    }

    uint16_t desc_idx = 0;
    uint16_t count = 0;
    uint8_t visited[MAX_QUEUE_SIZE] = {0};

    while (count < queue_size) {
        // Check bounds
        if (desc_idx >= queue_size) {
            return 0;  // Out of bounds
        }

        // Check for cycles
        if (visited[desc_idx]) {
            return 0;  // Circular chain detected
        }
        visited[desc_idx] = 1;

        count++;

        // Check if chain continues
        if (!(descs[desc_idx].flags & VRING_DESC_F_NEXT)) {
            break;  // End of chain
        }

        desc_idx = descs[desc_idx].next;
    }

    return 1;  // Valid chain
}

/**
 * Calculate total length of descriptor chain
 */
static inline uint64_t calculate_chain_length(struct vring_desc *descs,
                                               uint16_t start_idx,
                                               uint16_t queue_size) {
    uint64_t total_len = 0;
    uint16_t desc_idx = start_idx;
    uint16_t count = 0;

    while (count < queue_size) {
        if (desc_idx >= queue_size) {
            break;
        }

        total_len += descs[desc_idx].len;
        count++;

        if (!(descs[desc_idx].flags & VRING_DESC_F_NEXT)) {
            break;
        }

        desc_idx = descs[desc_idx].next;
    }

    return total_len;
}

/**
 * Detect interesting patterns in input (for reporting)
 */
static inline const char* detect_pattern(struct vring_desc *descs, size_t n_descs) {
    if (n_descs == 0) {
        return "empty";
    }

    // Check for circular chains
    if (n_descs >= 2) {
        if (descs[0].next == 1 && descs[1].next == 0 &&
            (descs[0].flags & VRING_DESC_F_NEXT) &&
            (descs[1].flags & VRING_DESC_F_NEXT)) {
            return "circular_chain";
        }
    }

    // Check for OOB next index
    for (size_t i = 0; i < n_descs; i++) {
        if ((descs[i].flags & VRING_DESC_F_NEXT) && descs[i].next >= MAX_QUEUE_SIZE) {
            return "oob_next_index";
        }
    }

    // Check for overflow lengths
    uint64_t total = 0;
    for (size_t i = 0; i < n_descs; i++) {
        if (descs[i].len == 0xFFFFFFFF) {
            return "max_length";
        }
        total += descs[i].len;
    }

    if (total > 0x100000000ULL) {  // > 4GB
        return "length_overflow";
    }

    // Check for all flags set
    if (descs[0].flags == 0x07) {
        return "all_flags_set";
    }

    return "normal";
}

/**
 * Logging helpers
 */
#define FUZZ_LOG(level, fmt, ...) \
    fprintf(stderr, "[%s] " fmt "\n", level, ##__VA_ARGS__)

#define FUZZ_DEBUG(fmt, ...) \
    FUZZ_LOG("DEBUG", fmt, ##__VA_ARGS__)

#define FUZZ_INFO(fmt, ...) \
    FUZZ_LOG("INFO", fmt, ##__VA_ARGS__)

#define FUZZ_WARN(fmt, ...) \
    FUZZ_LOG("WARN", fmt, ##__VA_ARGS__)

#define FUZZ_ERROR(fmt, ...) \
    FUZZ_LOG("ERROR", fmt, ##__VA_ARGS__)

/**
 * Crash detection (for custom crash handling)
 */
static inline void fuzz_crash_detected(const char *reason) {
    g_stats.crashes_detected++;
    FUZZ_ERROR("CRASH DETECTED: %s", reason);
    FUZZ_ERROR("Total iterations: %lu", g_stats.total_iterations);
    abort();  // Trigger sanitizer report
}

/**
 * Hang detection helper
 */
static inline void fuzz_hang_detected(const char *reason) {
    g_stats.hangs_detected++;
    FUZZ_ERROR("HANG DETECTED: %s", reason);
    FUZZ_ERROR("Total iterations: %lu", g_stats.total_iterations);
    abort();
}

/**
 * Print fuzzing statistics (for standalone mode)
 */
static inline void fuzz_print_stats(void) {
    printf("\n=== Fuzzing Statistics ===\n");
    printf("Total iterations:   %lu\n", g_stats.total_iterations);
    printf("Valid inputs:       %lu (%.2f%%)\n",
           g_stats.valid_inputs,
           g_stats.total_iterations ?
               100.0 * g_stats.valid_inputs / g_stats.total_iterations : 0);
    printf("Invalid inputs:     %lu (%.2f%%)\n",
           g_stats.invalid_inputs,
           g_stats.total_iterations ?
               100.0 * g_stats.invalid_inputs / g_stats.total_iterations : 0);
    printf("Crashes detected:   %lu\n", g_stats.crashes_detected);
    printf("Hangs detected:     %lu\n", g_stats.hangs_detected);
    printf("=========================\n");
}

#endif // DPDK_FUZZING_COMMON_H
