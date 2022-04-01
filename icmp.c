#include "icmp.h"

#include <assert.h>
#include <netinet/ip_icmp.h>

static inline uint16_t compute_icmp_checksum(const uint16_t* buff, int length) {
    uint32_t sum;
    const uint16_t* ptr = buff;
    assert(length % 2 == 0);
    for (sum = 0; length > 0; length -= 2) {
        sum += *ptr++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t)(~(sum + (sum >> 16)));
}

inline void fill_icmp_echo_header(
    IcmpHeader* header, const EchoDatagram* datagram) {
    header->icmp_type = ICMP_ECHO;
    header->icmp_code = 0;
    header->icmp_void = datagram->opaque;
    header->icmp_cksum = 0;
    header->icmp_cksum
        = compute_icmp_checksum((uint16_t*)header, sizeof(*header));
}

inline IcmpHeader* extract_icmp_header(uint8_t* packet) {
    struct ip* ip_header = (struct ip*)packet;
    const size_t ip_header_length = 4 * ip_header->ip_hl;
    uint8_t* icmp_packet = packet + ip_header_length;
    return (IcmpHeader*)icmp_packet;
}

inline IcmpHeader* extract_sent_icmp_header(IcmpHeader* icmp_header) {
    assert(icmp_header->icmp_type == ICMP_TIME_EXCEEDED);

    uint8_t* icmp_packet = (uint8_t*)icmp_header;
    // Przesuwamy się o 4 bajty nagłówka i 4 nieużywane bajty.
    // http://networksorcery.com/enp/protocol/icmp/msg11.htm
    uint8_t* sent_packet = icmp_packet + 4 + 4;
    IcmpHeader* sent_icmp_header = extract_icmp_header(sent_packet);

    assert(sent_icmp_header->icmp_type == ICMP_ECHO);

    return sent_icmp_header;
}
