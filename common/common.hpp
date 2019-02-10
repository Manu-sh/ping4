#pragma once

#include <cstdint>
#include <cstdio>

// internet checksum is endian independent
static inline uint16_t cksum16(const uint8_t *src, int length) noexcept {

	const uint16_t *w = (uint16_t *)src;
	uint32_t sum = 0;
	int i;

	for (i = length; i > 1; i -= sizeof(uint16_t))
		sum += *w++;

	if (i == 1) sum += *(uint8_t *)w;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)~sum;
}

// instead of adding one to the end, the checksum value is added. 
// If the result is composed of all 1, the package is valid.
static inline bool cksum16(uint16_t cksum, const uint8_t *src, int length) noexcept {
	return ((uint16_t)~cksum16(src, length)) + cksum == 0xffff;
}