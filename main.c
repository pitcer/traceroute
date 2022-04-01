/*
 * Piotr Dobiech 316625
 */

#include "icmp.h"
#include "ip_address.h"
#include "utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static_assert(TURNS <= MAX_TURNS);
static_assert(PACKETS_IN_TURN <= MAX_PACKETS_IN_TURN);

typedef struct sockaddr_in InetSocketAddress;
typedef struct sockaddr SocketAddress;

typedef struct {
    uint32_t socket_descriptor;
    union {
        InetSocketAddress* inet_recipient;
        SocketAddress* recipient;
    };

} TracerouteContext;

#define MICROS_IN_SECOND 1000000

static inline void set_ttl(
    const TracerouteContext* context, const uint8_t* ttl) {
    setsockopt(
        context->socket_descriptor, IPPROTO_IP, IP_TTL, ttl, sizeof(uint8_t));
}

static inline ssize_t receive_packet(const TracerouteContext* context,
    uint8_t* buffer, InetSocketAddress* sender) {
    socklen_t socket_length;
    return recvfrom(context->socket_descriptor, buffer, IP_MAXPACKET,
        MSG_DONTWAIT, (struct sockaddr*)sender, &socket_length);
}

static inline ssize_t send_packet(
    const TracerouteContext* context, IcmpHeader* buffer) {
    return sendto(context->socket_descriptor, buffer, sizeof(*buffer), 0,
        context->recipient, sizeof(*context->inet_recipient));
}

static inline bool send_echo_packets(
    const TracerouteContext* context, EchoDatagram datagram) {
    for (uint8_t index = 0; index < PACKETS_IN_TURN; index++) {
        IcmpHeader header;
        datagram.transparent.turn_packet_index = index;
        fill_icmp_echo_header(&header, &datagram);

        const ssize_t result = send_packet(context, &header);
        if (result < 0) {
            return false;
        }
    }
    return true;
}

static void print_turn_info(const uint8_t received_packets,
    uint32_t senders_addresses[PACKETS_IN_TURN],
    const uint32_t elapsed_time_sum) {
    if (received_packets == 0) {
        println("*");
    } else if (received_packets < 3) {
        print_different_addresses(senders_addresses, received_packets);
        println("???");
    } else {
        assert(received_packets == 3);

        print_different_addresses(senders_addresses, received_packets);

        const uint32_t average_elapsed_time
            = elapsed_time_sum / received_packets;
        const uint32_t millis = average_elapsed_time / 1000;
        const uint32_t micros = average_elapsed_time % 1000;
        println("%3" PRIu32 ".%.3" PRIu32 " ms ", millis, micros);
    }
}

int main(int argc, char const* argv[]) {
    if (argc != 2) {
        eprintln("Usage: traceroute <target IP address>");
        return EXIT_FAILURE;
    }

    const char* target_address = argv[1];
    if (!validate_address(target_address)) {
        eprintln("Invalid target IP address: %s", target_address);
        return EXIT_FAILURE;
    }

    const int socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_descriptor < 0) {
        eprintln("Socket error: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    fd_set select_descriptors;
    FD_ZERO(&select_descriptors);
    FD_SET(socket_descriptor, &select_descriptors);

    InetSocketAddress recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    inet_pton(AF_INET, target_address, &recipient.sin_addr);
    const uint32_t receipient_address = recipient.sin_addr.s_addr;

    const TracerouteContext context = { .socket_descriptor = socket_descriptor,
        .inet_recipient = &recipient };

    const pid_t process_id = getpid();

    bool reached_target = false;

    for (uint8_t ttl = 1; ttl <= TURNS && !reached_target; ttl++) {
        printf("%2." PRIu32 ". ", ttl);

        set_ttl(&context, &ttl);

        EchoDatagram datagram = { .transparent.process_id = process_id,
            .transparent.turn_index = ttl,
            .transparent.turn_packet_index = 0 };
        if (!send_echo_packets(&context, datagram)) {
            eprintln("sendto error: %s", strerror(errno));
            return EXIT_FAILURE;
        }

        struct timeval time;
        time.tv_sec = 1;
        time.tv_usec = 0;

        uint8_t packets_received = 0;
        uint32_t senders_addresses[PACKETS_IN_TURN];
        uint32_t elapsed_time_sum = 0;

        while (packets_received < PACKETS_IN_TURN) {
            int ready = select(
                socket_descriptor + 1, &select_descriptors, NULL, NULL, &time);
            if (ready < 0) {
                eprintln("Select error: %s", strerror(errno));
                return EXIT_FAILURE;
            } else if (ready == 0) {
                break;
            } else { // ready > 0
                assert(ready == 1);

                elapsed_time_sum += MICROS_IN_SECOND - time.tv_usec;

                InetSocketAddress sender;
                uint8_t buffer[IP_MAXPACKET];

                const ssize_t packet_length
                    = receive_packet(&context, buffer, &sender);
                if (packet_length < 0) {
                    eprintln("recvfrom error: %s", strerror(errno));
                    return EXIT_FAILURE;
                }

                const uint32_t sender_address = sender.sin_addr.s_addr;
                senders_addresses[packets_received] = sender_address;

                IcmpHeader* icmp_header = extract_icmp_header(buffer);

                const uint8_t response_type = icmp_header->icmp_type;
                if (response_type == ICMP_TIME_EXCEEDED) {
                    icmp_header = extract_sent_icmp_header(icmp_header);
                }

                const EchoDatagram datagram
                    = (EchoDatagram)icmp_header->icmp_void;
                if (datagram.transparent.process_id != process_id
                    || datagram.transparent.turn_index != ttl) {
                    continue;
                }

                if (response_type == ICMP_ECHOREPLY
                    && receipient_address == sender_address) {
                    reached_target = true;
                }

                packets_received++;
            }
        }

        print_turn_info(packets_received, senders_addresses, elapsed_time_sum);
    }

    if (!reached_target) {
        eprintln("Target not reached after %" PRIu8 " turns.", TURNS);
        return EXIT_FAILURE;
    }

    close(socket_descriptor);
    return EXIT_SUCCESS;
}
