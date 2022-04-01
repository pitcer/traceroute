#pragma once

#include "config.h"
#include <inttypes.h>
#include <stdbool.h>

// 3 + 1 + 3 + 1 + 3 + 1 + 3
#define MAX_IP_ADDRESS_LENGTH 15

bool validate_address(const char* address);

void print_adddress(uint32_t address);

bool is_unique_address(uint32_t address, uint32_t addresses[PACKETS_IN_TURN],
    uint8_t start, uint8_t end);

void print_different_addresses(
    uint32_t addresses[PACKETS_IN_TURN], const uint8_t addresses_length);
