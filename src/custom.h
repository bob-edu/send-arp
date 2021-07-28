#pragma once

#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define MAC_ALEN 6

int get_source_info(const char*, uint8_t*, char*);
int config_packet(EthArpPacket*, Mac, Mac, uint16_t, Mac, Ip, Mac, Ip);
int get_mac_adress(pcap_t*, Mac*, Mac, Mac, uint16_t, Mac, Ip, Mac, Ip);