#include "common/IPV4HDR.hpp"
#include "common/ICMPV4.hpp"

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <csignal>

#include <stdexcept>
#include <vector>
#include <string>
#include <utility>
#include <string_view>
#include <chrono>

#include <iostream>

extern "C" {
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
}

#define ANSI_GREEN "\033[38;5;10m"
#define ANSI_RED   "\033[38;5;9m"
#define ANSI_RESET "\033[0m"

using ping_time = std::chrono::time_point<std::chrono::steady_clock>;
using PINGV4 = ICMPV4<sizeof(ping_time)>;

static inline float elapsed_ms(ping_time start) {
	return (float)std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - start).count();
}

static inline PINGV4 ping(uint16_t id) {

	PINGV4 pkg;
	static uint16_t seq;

	*((ping_time *)pkg.m_payload) = std::chrono::steady_clock::now();
	return pkg.set_type(ICMP_ECHO).set_id(id).set_sequence(++seq).set_checksum();
}

static inline void pong(const void *data, size_t length, uint16_t id) {

	const struct IPV4HDR ip = *(IPV4HDR *)data;
	if (length < sizeof(IPV4HDR) + sizeof(PINGV4))
		return;

	const int icmphdr_len = length - ip.get_header_length(); // avoid to malicious iphdr (icmphdr + payload)
 	if (icmphdr_len < (int)sizeof(PINGV4))
		return;

	PINGV4 &pkg = *(PINGV4 *)((uint8_t *)(data) + ip.get_header_length());
	if (ip.get_protocol() != IPPROTO_ICMP || pkg.get_type() != ICMP_ECHOREPLY || pkg.get_id() != id)
		return;

	const auto &src = ip.src_host();
	printf("%s%d bytes from: %s ttl=%d id=%d, seq=%d time=%.2fms" ANSI_RESET "\n", 
		pkg.is_valid() ? ANSI_GREEN : ANSI_RED,
		icmphdr_len, src.c_str(), ip.get_time_to_alive(), 
		pkg.get_id(), pkg.get_sequence(), elapsed_ms( *((ping_time *)(pkg.m_payload)) )
	);
}

static inline std::vector<std::pair<std::string, struct sockaddr_in>> hostres_v4(const std::string_view &hostname) {

	std::vector<std::pair<std::string, struct sockaddr_in>> vct;
	struct addrinfo iaddr, *result;
	memset(&iaddr, 0, sizeof(iaddr));

	iaddr.ai_family   = AF_INET; /* IPv4 only */
	iaddr.ai_socktype = SOCK_RAW;
	iaddr.ai_protocol = IPPROTO_ICMP;

	if (int ret = getaddrinfo(hostname.data(), NULL, &iaddr, &result); ret != 0)
		throw std::runtime_error(std::string("getaddrinfo(): ") + gai_strerror(ret));

	for (decltype(auto) rp = result; rp != NULL; rp = rp->ai_next) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
		vct.emplace_back(std::make_pair(inet_ntoa(ipv4->sin_addr), *ipv4));
	}

	freeaddrinfo(result);

	if (vct.empty()) throw std::runtime_error("can't resolve host: " + std::string(hostname));
	return vct;
}

using namespace std;
int main(int argc, const char *argv[]) try {

	static int raw_sk;
	const static uint16_t pkg_id = (uint16_t)getpid();
	const static auto &die = []([[maybe_unused]] int sig = 0) {
		cout << ANSI_RESET << endl; // cout << "\n\n[" << getpid() << "] terminated" << endl;
		close(raw_sk);
		exit(0);
	};

	auto vct = hostres_v4(argc > 1 ? argv[1] : "google.com");
	char buf[MAX_PACKET]; // linux use COW so shouldn't matter if this is placed here (but im not totally sure)

	// TODO set user id
	if ((raw_sk = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		return 1;
	}

	signal(SIGINT, die);
	switch (fork()) {
		case 0:
			for (;; sleep(1)) {
				PINGV4 pkg = ping(pkg_id);
				sendto(raw_sk, &pkg, sizeof(pkg), 0, (struct sockaddr *)&vct[0].second, sizeof(struct sockaddr_in));
			}
			break;

		default:
			for (int bytes;;sleep(1)) {
				if ((bytes = recvfrom(raw_sk, &buf, sizeof(buf), 0, NULL, 0)) > 0)
					pong(buf, bytes, pkg_id);
			}
	}

	die();

} catch (exception &ex) {
	cerr << ex.what() << endl;
}
