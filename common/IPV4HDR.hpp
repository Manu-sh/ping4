#pragma once

#include <cstdint>
#include <string>

#ifndef _BSD_SOURCE
	#define _BSD_SOURCE
#endif

extern "C" {
	#include <netinet/ip.h>
	#include <arpa/inet.h>
}

struct IPV4HDR: iphdr {

	// this field is expressed as 32bit word so bytes = ihl*4
	uint8_t get_header_length() const { return this->ihl << 2; }
	uint16_t get_total_length() const { return ntohs(this->tot_len); }
	uint8_t get_time_to_alive() const { return this->ttl; }
	uint16_t get_identification() const { return ntohs(this->id); }
	uint8_t get_protocol() const { return this->protocol; }

	// TODO fragmentation offset
	// TODO checksum (usually computed by kernel so its unnecessary)
	// TODO type of service (tos) deprecated now know as
	// Differentiated Services Code Point (DSCP)

	std::string src_host() const {
		return std::string(inet_ntoa( *((struct in_addr *)(void *)(&this->saddr)) ));
	}

	std::string dst_host() const {
		return std::string(inet_ntoa( *((struct in_addr *)(void *)(&this->daddr)) ));
	}

};