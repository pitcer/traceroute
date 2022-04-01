#include "ip_address.h"

#include "config.h"
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

static inline bool is_numeric(const char character) {
    return character >= '0' && character <= '9';
}

bool validate_address(const char* address) {
    char current = *address++;
    uint8_t length = 0;
    uint8_t sections = 0;
    uint8_t section_length = 0;
    uint32_t section_byte = 0;

    while (true) {
        length++;
        if (is_numeric(current)) {
            section_length++;
            section_byte *= 10;
            section_byte += current - '0';

            if (section_length > 3) {
                return false;
            }
        } else if (current == '.' || current == '\0') {
            if (section_length == 0 || section_byte > 255) {
                return false;
            }

            sections++;
            section_byte = 0;
            section_length = 0;

            if (current == '\0') {
                break;
            }
        } else { // character other than allowed ones
            return false;
        }
        current = *address++;
    }

    if (sections != 4 || length > MAX_IP_ADDRESS_LENGTH) {
        return false;
    }

    return true;
}

inline void print_adddress(uint32_t address) {
    char address_string[MAX_IP_ADDRESS_LENGTH + 1];
    inet_ntop(AF_INET, &address, address_string, sizeof(address_string));
    printf("%15s ", address_string);
}

bool is_unique_address(uint32_t address, uint32_t addresses[PACKETS_IN_TURN],
    uint8_t start, uint8_t end) {
    for (; start < end; start++) {
        const uint32_t other_address = addresses[start];
        if (address == other_address) {
            return false;
        }
    }
    return true;
}

void print_different_addresses(
    uint32_t addresses[PACKETS_IN_TURN], const uint8_t addresses_length) {
    assert(addresses_length > 0);

    for (uint8_t index = 0; index < addresses_length; index++) {
        const uint32_t address = addresses[index];
        if (is_unique_address(
                address, addresses, index + 1, addresses_length)) {
            print_adddress(address);
        }
    }
}
