#pragma once
#include "common.hpp"
#include <cstdint>
#include <cstring>

extern "C" {
	#include <unistd.h>
	#include <netinet/ip.h>
	#include <netinet/ip_icmp.h>
	#include <linux/if_ether.h>
}

// an eth frame allow for 46-1500 octets as payload
#define MIN_PACKET 46
#define MAX_PACKET ETH_DATA_LEN

template<const uint16_t _PAYLOAD_SIZE>
struct ICMPV4: icmphdr {

	static_assert(sizeof(struct iphdr) + sizeof(icmphdr) + _PAYLOAD_SIZE < MAX_PACKET, "packet too big, fragmentation risk");
	static constexpr uint16_t PAYLOAD_SIZE = _PAYLOAD_SIZE;

	ICMPV4(): icmphdr{} {}

	// always call as last
	ICMPV4 & set_checksum() {
		this->checksum = 0;
		this->checksum = cksum16((uint8_t *)this, sizeof(*this));
		return *this;
	}

	bool is_valid() {
		uint16_t checksum = this->checksum;
		this->checksum = 0; // checksum is calculate with this field at zero
		bool isValid = cksum16(checksum, (const uint8_t *)this, sizeof(*this));
		this->checksum = checksum;
		return isValid;
	}

	ICMPV4 & set_id(uint16_t id) { return this->un.echo.id = htons(id), *this; }
	ICMPV4 & set_sequence(uint16_t seq) { return this->un.echo.sequence = htons(seq), *this; }
	ICMPV4 & set_type(uint8_t type) { return this->type = type, *this; }
	ICMPV4 & set_code(uint8_t code) { return this->code = code, *this; }

	uint16_t get_id() const { return ntohs(this->un.echo.id); }
	uint16_t get_sequence() const { return ntohs(this->un.echo.sequence); }
	uint8_t  get_type() const { return this->type; }
	uint8_t  get_code() const { return this->code; }

	uint8_t m_payload[PAYLOAD_SIZE];	
};