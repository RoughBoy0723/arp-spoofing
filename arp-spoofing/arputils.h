#ifndef ARP_UTILS_H
#define ARP_UTILS_H

#include <pcap.h>
#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include <libnet.h>
#include <map>
#include <sstream>
#include <vector>

void usage();
void formatMacAddress(char* mac);
void formatMacAddress(std::string& mac);
void get_MAC_IP_Address(const char* iface, uint8_t* mac, uint8_t* ip);
void get_mac_address(pcap_t* handle, char* my_mac, char* my_ip, char* sender_ip, char* mac);
void send_attack_ARP(pcap_t* handle, char* my_mac, char* sender_mac, char* target_ip, char* sender_ip);
void check_IP_get_MAC(pcap_t* handle, char* sender_ip, char* target_ip, char* sender_mac, char* target_mac);
void relay_packets(pcap_t* handle);
void padMacAddress(uint8_t* mac, char* formattedMac);


#endif
