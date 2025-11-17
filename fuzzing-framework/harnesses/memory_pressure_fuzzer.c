/**
 * DPDK Fuzzing Harness D: Memory Pressure Fuzzer
 *
 * Target: Allocation paths under extreme memory load
 * Focus: Memory leaks, double-free, use-after-free
 */

#include "common.h"

#define MAX_ALLOCS 1000

struct alloc_op {
    uint8_t operation;  // 0=alloc, 1=free, 2=realloc
    uint16_t size;
    uint16_t index;
} __attribute__((packed));

static void *g_allocations[MAX_ALLOCS] = {NULL};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    g_stats.total_iterations++;

    if (size < sizeof(struct alloc_op)) {
        g_stats.invalid_inputs++;
        return 0;
    }

    size_t n_ops = size / sizeof(struct alloc_op);
    struct alloc_op *ops = (struct alloc_op *)data;

    for (size_t i = 0; i < n_ops && i < 100; i++) {
        uint16_t idx = ops[i].index % MAX_ALLOCS;
        uint16_t alloc_size = ops[i].size % 65536;

        switch (ops[i].operation % 3) {
            case 0:  // Allocate
                if (!g_allocations[idx]) {
                    g_allocations[idx] = malloc(alloc_size);
                }
                break;

            case 1:  // Free
                if (g_allocations[idx]) {
                    free(g_allocations[idx]);
                    g_allocations[idx] = NULL;
                }
                break;

            case 2:  // Realloc
                g_allocations[idx] = realloc(g_allocations[idx], alloc_size);
                break;
        }
    }

    // Cleanup
    for (int i = 0; i < MAX_ALLOCS; i++) {
        if (g_allocations[i]) {
            free(g_allocations[i]);
            g_allocations[i] = NULL;
        }
    }

    g_stats.valid_inputs++;
    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(void) {
    fuzz_init();
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        fuzz_one_input(buf, __AFL_FUZZ_TESTCASE_LEN);
    }
    return 0;
}
#elif defined(__cplusplus)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_one_input(data, size);
    return 0;
}
#else
int main(int argc, char **argv) {
    fuzz_init();
    uint8_t buf[4096];
    ssize_t size = read_input((argc > 1) ? argv[1] : "-", buf, sizeof(buf));
    if (size > 0) fuzz_one_input(buf, size);
    return 0;
}
#endif
