/**
 * DPDK Fuzzing Harness E: Integration Fuzzer
 *
 * Target: Full vhost device lifecycle (stateful fuzzing)
 * Focus: State machine bugs, initialization/cleanup errors, state transitions
 */

#include "common.h"

// vHost device states
typedef enum {
    STATE_INIT = 0,
    STATE_FEATURES_SET,
    STATE_MEM_TABLE_SET,
    STATE_VRING_CONFIGURED,
    STATE_RUNNING,
    STATE_STOPPED
} vhost_state_t;

struct vhost_device {
    vhost_state_t state;
    uint64_t features;
    uint32_t n_mem_regions;
    uint16_t n_queues;
};

struct state_transition {
    uint8_t target_state;
    uint8_t param[7];
} __attribute__((packed));

static struct vhost_device g_device = {STATE_INIT};

static int transition_state(uint8_t target, const uint8_t *param) {
    vhost_state_t new_state = (vhost_state_t)(target % 6);

    // Check for invalid state transitions
    switch (g_device.state) {
        case STATE_INIT:
            if (new_state != STATE_FEATURES_SET) {
                return -1;  // Invalid transition
            }
            break;

        case STATE_FEATURES_SET:
            if (new_state != STATE_MEM_TABLE_SET) {
                return -1;
            }
            g_device.features = *(uint64_t*)param;
            break;

        case STATE_MEM_TABLE_SET:
            if (new_state != STATE_VRING_CONFIGURED) {
                return -1;
            }
            g_device.n_mem_regions = param[0];
            break;

        case STATE_VRING_CONFIGURED:
            if (new_state != STATE_RUNNING && new_state != STATE_STOPPED) {
                return -1;
            }
            g_device.n_queues = *(uint16_t*)param;
            break;

        case STATE_RUNNING:
            // Can transition to STOPPED or stay RUNNING
            break;

        case STATE_STOPPED:
            // Can transition to INIT (reset) or RUNNING
            if (new_state == STATE_INIT) {
                memset(&g_device, 0, sizeof(g_device));
            }
            break;
    }

    g_device.state = new_state;
    return 0;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    g_stats.total_iterations++;

    if (size < sizeof(struct state_transition)) {
        g_stats.invalid_inputs++;
        return 0;
    }

    // Reset device
    memset(&g_device, 0, sizeof(g_device));

    // Apply state transitions
    size_t n_transitions = size / sizeof(struct state_transition);
    struct state_transition *transitions = (struct state_transition *)data;

    for (size_t i = 0; i < n_transitions && i < 100; i++) {
        transition_state(transitions[i].target_state, transitions[i].param);
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
