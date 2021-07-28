#include "custom.h"

int get_source_info(const char *dev, uint8_t* mac_addr, char* ip_addr)
{
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Failed to get interface MAC address - socket() failed - %m\n");
		return -1;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);


	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Failed to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		return -1;
	}

	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);


	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		printf("Failed to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
		close(sockfd);
		return -1;
	}

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr, sizeof(struct sockaddr));

	close(sockfd);

	return 0;
}


int config_packet(EthArpPacket* packet, Mac eth_dmac, Mac eth_smac, uint16_t arp_op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{

	(*packet).eth_.dmac_ = eth_dmac;
	(*packet).eth_.smac_ = eth_smac;
	(*packet).eth_.type_ = htons(EthHdr::Arp);

	(*packet).arp_.hrd_ = htons(ArpHdr::ETHER);
	(*packet).arp_.pro_ = htons(EthHdr::Ip4);
	(*packet).arp_.hln_ = Mac::SIZE;
	(*packet).arp_.pln_ = Ip::SIZE;
	(*packet).arp_.op_ = arp_op;
	(*packet).arp_.smac_ = arp_smac;
	(*packet).arp_.sip_ = arp_sip;
	(*packet).arp_.tmac_ = arp_tmac;
	(*packet).arp_.tip_ = arp_tip;

	return 0;
}

int get_mac_adress(pcap_t* handle, Mac* mac_addr, Mac eth_dmac, Mac eth_smac, uint16_t arp_op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
	EthArpPacket arp_request;

	config_packet(&arp_request, eth_dmac, eth_smac, arp_op, arp_smac, arp_sip, arp_tmac, arp_tip);
	
	int send_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_request), sizeof(EthArpPacket));
	if (send_res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(handle));
		return -1;
	}

	struct pcap_pkthdr *header;
	const u_char *packet;

	while (true)
	{
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

		EthArpPacket* reply_packet_from_sender = (EthArpPacket *)(packet);
		if (reply_packet_from_sender->eth_.type() != EthHdr::Arp || reply_packet_from_sender->arp_.op() != ArpHdr::Reply)
			continue;

		*mac_addr = reply_packet_from_sender->arp_.smac();
		return 0;
	}
}