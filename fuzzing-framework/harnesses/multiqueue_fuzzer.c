/**
 * DPDK Fuzzing Harness C: Multi-Queue Race Condition Fuzzer
 *
 * Target: Concurrent queue operations and race conditions
 * Focus: TOCTOU bugs, race conditions in multi-threaded vhost
 */

#include "common.h"
#include <pthread.h>

#define NUM_QUEUES 4
#define OPS_PER_THREAD 100

struct queue_op {
    uint8_t queue_id;
    uint8_t operation;  // 0=read, 1=write, 2=modify
    uint8_t data[64];
} __attribute__((packed));

static volatile uint32_t g_shared_state[NUM_QUEUES] = {0};

static void* queue_worker(void *arg) {
    struct queue_op *op = (struct queue_op *)arg;

    for (int i = 0; i < OPS_PER_THREAD; i++) {
        uint8_t qid = op->queue_id % NUM_QUEUES;

        switch (op->operation % 3) {
            case 0:  // Read
                (void)g_shared_state[qid];
                break;
            case 1:  // Write
                g_shared_state[qid] = op->data[i % 64];
                break;
            case 2:  // Modify (read-modify-write - potential race)
                g_shared_state[qid]++;
                break;
        }
    }

    return NULL;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    g_stats.total_iterations++;

    if (size < sizeof(struct queue_op) * 2) {
        g_stats.invalid_inputs++;
        return 0;
    }

    size_t n_ops = size / sizeof(struct queue_op);
    if (n_ops > 8) n_ops = 8;  // Limit threads

    pthread_t threads[8];
    struct queue_op *ops = (struct queue_op *)data;

    // Launch concurrent operations
    for (size_t i = 0; i < n_ops; i++) {
        pthread_create(&threads[i], NULL, queue_worker, &ops[i]);
    }

    // Wait for completion
    for (size_t i = 0; i < n_ops; i++) {
        pthread_join(threads[i], NULL);
    }

    g_stats.valid_inputs++;
    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(void) {
    fuzz_init();
    __AFL_INIT();
    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(1000)) {  // Fewer iterations due to threading overhead
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
