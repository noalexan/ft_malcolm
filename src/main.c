#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#define BUFFER_SIZE ETH_FRAME_LEN

enum {
	SUCCESS,
	ARGUMENT_FAILURE,
	INVALID_IP_FAILURE,
	INVALID_MAC_FAILURE,
	SOCKET_FAILURE,
	GETIFADDRS_FAILURE,
	RECVFROM_FAILURE,
	SENDTO_FAILURE,
};

void bzero(void *s, size_t n) {
	while (n--) * (char *) s++ = 0;
}

bool is_valid_ip(char const * const ip) {
	int i = 0;
	for (int j = 0; j < 4; j++) {
		while (ip[i] && '0' <= ip[i] && ip[i] <= '9') i++;
		if (j != 3 && ip[i++] != '.') return false;
	}
	if (ip[i]) return false;
	return true;
}

bool is_valid_mac(char const * const mac) {
	int i = 0;
	for (int j = 0; j < 6; j++) {
		while (mac[i] && (
				('0' <= mac[i] && mac[i] <= '9') ||
				('a' <= mac[i] && mac[i] <= 'f'))) i++;
		if (j != 5 && mac[i++] != ':') return false;
	}
	if (mac[i]) return false;
	return true;
}

void parseMacAddress(char const * const source_mac, char * const mac) {
	char base[] = "0123456789abcdef";
	char * a = strtok((char *) source_mac, ":");

	bzero(mac, 6);

	for (int i = 0; i < 6; i++) {
		mac[i] += (strchr(base, a[0]) - base) * 16;
		mac[i] += (strchr(base, a[1]) - base);
		a = strtok(NULL, ":");
	}
}

int main(int argc, char **argv) {

	if (argc != 5) {
		printf("Usage: %s <source ip> <source mac address> <target ip> <target mac address>\n", argv[0]);
		return ARGUMENT_FAILURE;
	}

	for (int i = 0; i < 2; i++) {
		if (!is_valid_ip(argv[2 * i + 1])) {
			printf("Invalid IP address: %s\n", argv[2 * i + 1]);
			return INVALID_IP_FAILURE;
		}
		if (!is_valid_mac(argv[2 * i + 2])) {
			printf("Invalid MAC address: %s\n", argv[2 * i + 2]);
			return INVALID_MAC_FAILURE;
		}
	}

	char const * const source_ip  = argv[1];
	char const * const source_mac = argv[2];
	char const * const target_ip  = argv[3];
	char const * const target_mac = argv[4];

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock == -1) {
		perror("socket");
		return SOCKET_FAILURE;
	}

	struct ifaddrs * addresses, * address;
	char interface[100];

	if (getifaddrs(&addresses) == -1) {
		perror("getifaddrs");
		return GETIFADDRS_FAILURE;
	}

	for (address = addresses; address != NULL; address = address->ifa_next) {
		if (address->ifa_addr == NULL) continue;
		if (address->ifa_addr->sa_family != AF_PACKET) continue;
		if (strcmp(address->ifa_name, "lo") == 0) continue;
		strcpy(interface, address->ifa_name);
		break;
	}

	freeifaddrs(addresses);
	printf("Interface: %s\n", interface);

	ssize_t bytes_read;
	struct sockaddr saddr;
	socklen_t saddr_len = sizeof(saddr);
	char buffer[BUFFER_SIZE];


	printf("Waiting for ARP request (from %s to %s)...\n", target_ip, source_ip);

	while (true) {

		// Request

		bytes_read = recvfrom(sock, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);

		if (bytes_read == -1) {
			perror("recvfrom");
			return RECVFROM_FAILURE;
		}

		bzero(buffer + bytes_read, BUFFER_SIZE - bytes_read);

		struct ether_header const * const eth = (struct ether_header *) buffer;
		struct arphdr const * const arp = (struct arphdr *) (buffer + sizeof(struct ether_header));

		if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;
		if (ntohs(arp->ar_op) != ARPOP_REQUEST) continue;

		char _source_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, buffer + sizeof(struct ether_header) + sizeof(struct arphdr) + 6, _source_ip, INET_ADDRSTRLEN);
		if (strcmp(target_ip, _source_ip) != 0) continue;

		char _source_mac[18];
		ether_ntoa_r((struct ether_addr *) (buffer + sizeof(struct ether_header) + 8), _source_mac);
		if (strcmp(target_mac, _source_mac) != 0) continue;

		char _target_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, buffer + sizeof(struct ether_header) + sizeof(struct arphdr) + 16, _target_ip, INET_ADDRSTRLEN);
		if (strcmp(source_ip, _target_ip) != 0) continue;

		printf("ARP request received\n");

		// Response

		char reply[BUFFER_SIZE];
		struct ether_header * const eth_reply = (struct ether_header *) reply;
		struct arphdr * const arp_reply = (struct arphdr *) (reply + sizeof(struct ether_header));

		bzero(reply, BUFFER_SIZE);

		eth_reply->ether_type = htons(ETHERTYPE_ARP);
		memcpy(eth_reply->ether_dhost, eth->ether_shost, ETH_ALEN);
		memcpy(eth_reply->ether_shost, eth->ether_dhost, ETH_ALEN);

		arp_reply->ar_hrd = htons(ARPHRD_ETHER);
		arp_reply->ar_pro = htons(ETHERTYPE_IP);
		arp_reply->ar_hln = ETH_ALEN;
		arp_reply->ar_pln = 4;
		arp_reply->ar_op  = htons(ARPOP_REPLY);

		socklen_t saddr_ll_len = sizeof(struct sockaddr_ll);
		struct sockaddr_ll saddr_ll;
		bzero(&saddr_ll, saddr_ll_len);

		saddr_ll.sll_family = AF_PACKET;
		saddr_ll.sll_ifindex = if_nametoindex(interface);
		saddr_ll.sll_protocol = htons(ETH_P_ALL);

		if (ntohs(eth_reply->ether_type) != ETHERTYPE_ARP) continue;
		if (ntohs(arp_reply->ar_op) != ARPOP_REPLY) continue;

		char mac[6];
		parseMacAddress(source_mac, mac);

		memcpy(reply + sizeof(struct ether_header) + sizeof(struct arphdr) + 6, buffer + sizeof(struct ether_header) + sizeof(struct arphdr) + 16, 4);
		memcpy(reply + sizeof(struct ether_header) + sizeof(struct arphdr) + 16, buffer + sizeof(struct ether_header) + sizeof(struct arphdr) + 6, 4);
		memcpy(reply + sizeof(struct ether_header) + 8, mac, ETH_ALEN);
		memcpy(reply + sizeof(struct ether_header) + 18, buffer + sizeof(struct ether_header) + 8, ETH_ALEN);

		ssize_t bytes_sent = sendto(sock, reply, sizeof(struct ether_header) + sizeof(struct arphdr) + 20, 0, (struct sockaddr *) &saddr_ll, saddr_ll_len);

		if (bytes_sent == -1) {
			perror("sendto");
			return SENDTO_FAILURE;
		}

		printf("ARP response sent\n");

		break;

	}

	close(sock);
	return 0;
}
