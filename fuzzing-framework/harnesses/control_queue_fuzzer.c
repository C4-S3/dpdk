/**
 * DPDK Fuzzing Harness B: Control Queue Message Fuzzer
 *
 * Target: All control queue command types and message handling
 * Focus: Invalid commands, malformed headers, state machine bugs
 */

#include "common.h"

// virtio-net control queue commands
#define VIRTIO_NET_CTRL_RX              0
#define VIRTIO_NET_CTRL_MAC             1
#define VIRTIO_NET_CTRL_VLAN            2
#define VIRTIO_NET_CTRL_ANNOUNCE        3
#define VIRTIO_NET_CTRL_MQ              4
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS  5
#define VIRTIO_NET_CTRL_MTU             6

static int process_ctrl_msg(uint8_t class, uint8_t cmd, const uint8_t *data, size_t data_len) {
    // Simulate control message processing with various command types
    switch (class) {
        case VIRTIO_NET_CTRL_RX:
            // RX mode commands
            if (data_len < 1) return -1;
            break;

        case VIRTIO_NET_CTRL_MAC:
            // MAC table commands
            if (data_len < 8) return -1;  // Need at least MAC count + 1 MAC
            break;

        case VIRTIO_NET_CTRL_VLAN:
            // VLAN commands
            if (data_len < 2) return -1;  // Need VLAN ID
            break;

        case VIRTIO_NET_CTRL_MQ:
            // Multi-queue commands
            if (data_len < 2) return -1;  // Need queue pair count
            break;

        default:
            // Unknown command class
            return -1;
    }

    return 0;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    g_stats.total_iterations++;

    if (size < sizeof(struct virtio_net_ctrl_hdr)) {
        g_stats.invalid_inputs++;
        return 0;
    }

    struct virtio_net_ctrl_hdr *hdr = (struct virtio_net_ctrl_hdr *)data;
    const uint8_t *msg_data = data + sizeof(*hdr);
    size_t msg_len = size - sizeof(*hdr);

    g_stats.valid_inputs++;

    process_ctrl_msg(hdr->class, hdr->cmd, msg_data, msg_len);

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
