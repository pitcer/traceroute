#pragma once

#include "config.h"
#include <inttypes.h>
#include <netinet/ip_icmp.h>

// 2^22 -- man 5 proc
#define MAX_PID 4194304

// 2^6
#define MAX_TURNS 64

// 2^4
#define MAX_PACKETS_IN_TURN 16

typedef struct icmp IcmpHeader;

typedef union {
    struct {
        uint32_t process_id : 22;
        uint32_t turn_index : 6;
        uint32_t turn_packet_index : 4;
    } transparent;
    uint32_t opaque;
} EchoDatagram;

void fill_icmp_echo_header(IcmpHeader* header, const EchoDatagram* datagram);

IcmpHeader* extract_icmp_header(uint8_t* packet);

IcmpHeader* extract_sent_icmp_header(IcmpHeader* icmp_header);
