/*
 * Piotr Dobiech 316625
 */

#pragma once

#include "config.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>

// 3 + 1 + 3 + 1 + 3 + 1 + 3
#define MAX_IP_ADDRESS_LENGTH 15

typedef struct sockaddr_in InetSocketAddress;
typedef struct sockaddr SocketAddress;

bool validate_address(const char* address);

int ip_string_to_bytes(const char* string_address, InetSocketAddress* address);

void print_adddress(uint32_t address);

bool is_unique_address(uint32_t address, uint32_t addresses[PACKETS_IN_TURN],
    uint8_t start, uint8_t end);

void print_different_addresses(
    uint32_t addresses[PACKETS_IN_TURN], const uint8_t addresses_length);
