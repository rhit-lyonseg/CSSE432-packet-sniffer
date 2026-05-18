/* sniffer.c

    Description: This is a packet sniffer that captures ethernet packets,
                 parses them, and displays their contents.

    Authors: Ellis Lyons, Mark Hankins

    Date Modified: 05/13/2026

    References: https://kernel-internals.org/net/packet-socket/
                https://en.wikipedia.org/wiki/IPv4
                https://en.wikipedia.org/wiki/IPv6
                https://en.wikipedia.org/wiki/Address_Resolution_Protocol
                https://en.wikipedia.org/wiki/Transmission_Control_Protocol
                https://en.wikipedia.org/wiki/User_Datagram_Protocol
                https://en.wikipedia.org/wiki/EtherType
                https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
                https://en.wikipedia.org/wiki/IPv4#DSCP
                https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
                https://en.wikipedia.org/wiki/Domain_Name_System
                https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "sniffer.h"

struct ethernet_header parse_ethernet(uint8_t *packet)
{
    struct ethernet_header header;

    memcpy(header.dest_mac, packet, 6);
    memcpy(header.src_mac, packet+6, 6);
    header.ether_type = ((uint16_t)packet[12] << 8) | packet[13];

    return header;
}

struct ipv4_header parse_ipv4(uint8_t *packet)
{
    struct ipv4_header header;

    header.version = packet[0] >> 4;
    header.ihl = packet[0] & 0x0F;
    header.tos = packet[1];
    header.total_len = ((uint16_t)packet[2] << 8) | packet[3];
    header.id = ((uint16_t)packet[4] << 8) | packet[5];
    header.flags = packet[6] >> 5;
    header.fragment_offset = ((uint16_t)(packet[6] & 0x1F) << 8) | packet[7];
    header.ttl = packet[8];
    header.protocol = packet[9];
    header.checksum = ((uint16_t)packet[10] << 8) | packet[11];
    memcpy(header.src_ip, packet+12, 4);
    memcpy(header.dest_ip, packet+16, 4);

    return header;
}

struct ipv6_header parse_ipv6(uint8_t *packet)
{
    struct ipv6_header header;

    header.version = packet[0] >> 4;
    header.traffic_class = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    header.flow_label = ((uint32_t)(packet[1] & 0x0F) << 16) | ((uint32_t)packet[2] << 8) | (uint32_t)packet[3];
    header.payload_length = ((uint16_t)packet[4] << 8) | packet[5];
    header.next_header = packet[6];
    header.hop_limit = packet[7];
    memcpy(header.src_ip, packet+8, 16);
    memcpy(header.dest_ip, packet+24, 16);

    return header;
}

struct arp_header parse_arp(uint8_t *packet)
{
    struct arp_header header;

    header.hw_type = ((uint16_t)packet[0] << 8) | packet[1];
    header.proto_type = ((uint16_t)packet[2] << 8) | packet[3];
    header.hw_length = packet[4];
    header.proto_length = packet[5];
    header.operation = ((uint16_t)packet[6] << 8) | packet[7];
    memcpy(header.sender_mac, packet+8, 6);
    memcpy(header.sender_ip, packet+14, 4);
    memcpy(header.target_mac, packet+18, 6);
    memcpy(header.target_ip, packet+24, 4);

    return header;
}

struct udp_header parse_udp(uint8_t *packet)
{
    struct udp_header header;

    header.src_port = ((uint16_t)packet[0] << 8) | packet[1];
    header.dest_port = ((uint16_t)packet[2] << 8) | packet[3];
    header.length = ((uint16_t)packet[4] << 8) | packet[5];
    header.checksum = ((uint16_t)packet[6] << 8) | packet[7];   

    return header;
}

struct tcp_header parse_tcp(uint8_t *packet)
{
    struct tcp_header header;

    header.src_port = ((uint16_t)packet[0] << 8) | packet[1];
    header.dest_port = ((uint16_t)packet[2] << 8) | packet[3];
    header.seq_num = ((uint32_t)packet[4] << 24) | ((uint32_t)packet[5] << 16) | ((uint32_t)packet[6] << 8) | packet[7];
    header.ack_num = ((uint32_t)packet[8] << 24) | ((uint32_t)packet[9] << 16) | ((uint32_t)packet[10] << 8) | packet[11];
    header.data_offset = packet[12] >> 4;
    header.flags = packet[13];
    header.window = ((uint16_t)packet[14] << 8) | packet[15];
    header.checksum = ((uint16_t)packet[16] << 8) | packet[17];
    header.urg_ptr = ((uint16_t)packet[18] << 8) | packet[19];

    return header;
}

struct dns_header parse_dns(uint8_t *packet)
{
    struct dns_header header;

    header.transaction_id = ((uint16_t)packet[0] << 8) | packet[1];
    header.flags          = ((uint16_t)packet[2] << 8) | packet[3];
    header.num_questions  = ((uint16_t)packet[4] << 8) | packet[5];
    header.num_answers    = ((uint16_t)packet[6] << 8) | packet[7];
    header.num_auth_rr    = ((uint16_t)packet[8] << 8) | packet[9];
    header.num_add_rr     = ((uint16_t)packet[10] << 8) | packet[11];

    return header;
}

void print_ethernet(struct ethernet_header header)
{
    printf("\t[ETHERNET]\n");
    printf("\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.src_mac[0], header.src_mac[1],
                                                                header.src_mac[2], header.src_mac[3],
                                                                header.src_mac[4], header.src_mac[5]);
    printf("\t\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.dest_mac[0], header.dest_mac[1],
                                                                header.dest_mac[2], header.dest_mac[3],
                                                                header.dest_mac[4], header.dest_mac[5]);
    
    printf("\t\tEther Type: ");
    if (header.ether_type == ETHER_TYPE_IPV4) {
        printf("IPv4\n");
    } else if (header.ether_type == ETHER_TYPE_IPV6) {
        printf("IPv6\n");
    } else if (header.ether_type == ETHER_TYPE_ARP) {
        printf("ARP\n");
    }
}

void print_ipv4(struct ipv4_header header)
{
    printf("\t[IPv4]\n");
    printf("\t\tVersion: %d\n", header.version);
    printf("\t\tInternet Header Length: %d bytes\n", header.ihl * 4);

    /* DSCP */
    uint8_t dscp = header.tos >> 2;
    printf("\t\tDSCP: %d ", dscp);
    if (dscp == DSCP_BEST_EFFORT) {
        printf("(Best Effort)\n");
    } else {
        printf("(Unknown)\n");
    }

    /* ECN */
    uint8_t ecn = header.tos & 0x03;
    printf("\t\tECN: %d ", ecn);
    if (ecn == ECN_NOT_ECT) {
        printf("(Not ECN Capable)\n");
    } else if (ecn == ECN_ECT0) {
        printf("(ECN Capable)\n");
    } else if (ecn == ECN_ECT1) {
        printf("(ECN Capable)\n");
    } else if (ecn == ECN_CE) {
        printf("(Congestion Experienced)\n");
    }

    printf("\t\tTotal Length: %d\n", header.total_len);
    printf("\t\tID: 0x%04x\n", header.id);

    /* Flags */
    printf("\t\tFlags: 0x%02x ", header.flags);
    if (header.flags & IPV4_FLAG_DF) {
        printf("(DF) ");
    }
    if (header.flags & IPV4_FLAG_MF) {
        printf("(MF) ");
    }
    printf("\n");

    printf("\t\tFragment Offset: %d\n", header.fragment_offset);
    printf("\t\tTime to Live: %d\n", header.ttl);

    /* Protocol */
    printf("\t\tProtocol: ");
    if (header.protocol == IP_PROTO_TCP) {
        printf("TCP\n");
    } else if (header.protocol == IP_PROTO_UDP) {
        printf("UDP\n");
    } else if (header.protocol == IP_PROTO_ICMP) {
        printf("ICMP\n");
    } else if (header.protocol == IP_PROTO_IGMP) {
        printf("IGMP\n");
    } else if (header.protocol == IP_PROTO_ENCAP) {
        printf("ENCAP\n");
    } else if (header.protocol == IP_PROTO_OSPF) {
        printf("OSPF\n");
    } else if (header.protocol == IP_PROTO_SCTP) {
        printf("SCTP\n");
    } else {
        printf("0x%02x (Unknown)\n", header.protocol);
    }

    printf("\t\tChecksum: 0x%04x\n", header.checksum);
    printf("\t\tSource IP: %d.%d.%d.%d\n", header.src_ip[0], header.src_ip[1],
                                            header.src_ip[2], header.src_ip[3]);
    printf("\t\tDestination IP: %d.%d.%d.%d\n", header.dest_ip[0], header.dest_ip[1],
                                                 header.dest_ip[2], header.dest_ip[3]);
}

void print_ipv6(struct ipv6_header header)
{
    printf("\t[IPv6]\n");
    printf("\t\tVersion: %d\n", header.version);
    printf("\t\tTraffic Class: 0x%02x\n", header.traffic_class);
    printf("\t\tFlow Label: 0x%05x\n", header.flow_label);
    printf("\t\tPayload Length: %d\n", header.payload_length);

    /* Next Header */
    printf("\t\tNext Header: ");
    if (header.next_header == IP_PROTO_TCP) {
        printf("TCP\n");
    } else if (header.next_header == IP_PROTO_UDP) {
        printf("UDP\n");
    } else if (header.next_header == IP_PROTO_ICMPv6) {
        printf("ICMPv6\n");
    } else {
        printf("0x%02x (Unknown)\n", header.next_header);
    }

    printf("\t\tHop Limit: %d\n", header.hop_limit);
    printf("\t\tSource IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           header.src_ip[0], header.src_ip[1], header.src_ip[2], header.src_ip[3],
           header.src_ip[4], header.src_ip[5], header.src_ip[6], header.src_ip[7],
           header.src_ip[8], header.src_ip[9], header.src_ip[10], header.src_ip[11],
           header.src_ip[12], header.src_ip[13], header.src_ip[14], header.src_ip[15]);
    printf("\t\tDestination IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           header.dest_ip[0], header.dest_ip[1], header.dest_ip[2], header.dest_ip[3],
           header.dest_ip[4], header.dest_ip[5], header.dest_ip[6], header.dest_ip[7],
           header.dest_ip[8], header.dest_ip[9], header.dest_ip[10], header.dest_ip[11],
           header.dest_ip[12], header.dest_ip[13], header.dest_ip[14], header.dest_ip[15]);
}

void print_arp(struct arp_header header)
{
    printf("\t[ARP]\n");

    /* HW Type */
    printf("\t\tHardware Type: ");
    if (header.hw_type == ARP_HW_ETHERNET) {
        printf("Ethernet\n");
    } else if (header.hw_type == ARP_HW_IEEE802) {
        printf("IEEE 802\n");
    } else {
        printf("0x%04x (Unknown)\n", header.hw_type);
    }

    /* Protocol Type */
    printf("\t\tProtocol Type: ");
    if (header.proto_type == ETHER_TYPE_IPV4) {
        printf("IPv4\n");
    } else if (header.proto_type == ETHER_TYPE_IPV6) {
        printf("IPv6\n");
    } else if (header.proto_type == ETHER_TYPE_ARP) {
        printf("ARP\n");
    } else {
        printf("0x%04x (Unknown)\n", header.proto_type);
    }

    printf("\t\tHardware Address Length: %d\n", header.hw_length);
    printf("\t\tProtocol Address Length: %d\n", header.proto_length);

    /* Operation */
    printf("\t\tOperation: ");
    if (header.operation == ARP_OP_REQUEST) {
        printf("Request\n");
    } else if (header.operation == ARP_OP_REPLY) {
        printf("Reply\n");
    } else {
        printf("0x%04x (Unknown)\n", header.operation);
    }

    printf("\t\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.sender_mac[0], header.sender_mac[1],
                                                               header.sender_mac[2], header.sender_mac[3],
                                                               header.sender_mac[4], header.sender_mac[5]);
    printf("\t\tSender IP: %d.%d.%d.%d\n", header.sender_ip[0], header.sender_ip[1],
                                            header.sender_ip[2], header.sender_ip[3]);
    printf("\t\tTarget MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.target_mac[0], header.target_mac[1],
                                                               header.target_mac[2], header.target_mac[3],
                                                               header.target_mac[4], header.target_mac[5]);
    printf("\t\tTarget IP: %d.%d.%d.%d\n", header.target_ip[0], header.target_ip[1],
                                            header.target_ip[2], header.target_ip[3]);
}

void print_tcp(struct tcp_header header)
{
    printf("\t[TCP]\n");
    printf("\t\tSource Port: %d\n", header.src_port);
    printf("\t\tDestination Port: %d\n", header.dest_port);
    printf("\t\tSequence Number: %u\n", header.seq_num);
    printf("\t\tAcknowledgment Number: %u\n", header.ack_num);
    printf("\t\tData Offset: %d bytes\n", header.data_offset * 4);
    printf("\t\tFlags: 0x%02x ", header.flags);
    if (header.flags & TCP_FIN) {
        printf("(FIN) ");
    }
    if (header.flags & TCP_SYN) {
        printf("(SYN) ");
    }
    if (header.flags & TCP_RST) {
        printf("(RST) ");
    }
    if (header.flags & TCP_PSH) {
        printf("(PSH) ");
    }
    if (header.flags & TCP_ACK) {
        printf("(ACK) ");
    }
    if (header.flags & TCP_URG) {
        printf("(URG) ");
    }
    if (header.flags & TCP_ECE) {
        printf("(ECE) ");
    }
    if (header.flags & TCP_CWR) {
        printf("(CWR) ");
    }
    printf("\n");
    printf("\t\tWindow Size: %d\n", header.window);
    printf("\t\tChecksum: 0x%04x\n", header.checksum);
    printf("\t\tUrgent Pointer: %d\n", header.urg_ptr);
}

void print_udp(struct udp_header header)
{
    printf("\t[UDP]\n");
    printf("\t\tSource Port: %d\n", header.src_port);
    printf("\t\tDestination Port: %d\n", header.dest_port);
    printf("\t\tLength: %d bytes\n", header.length);
    printf("\t\tChecksum: 0x%04x\n", header.checksum);
}

void print_dns(struct dns_header header)
{
    printf("\t[DNS]\n");
    printf("\t\tTransaction ID: 0x%04x\n", header.transaction_id);

    /* Type */
    printf("\t\tType: ");
    if (header.flags & DNS_FLAG_QR) {
        printf("Response\n");
    } else {
        printf("Query\n");
    }

    /* Opcode */
    uint8_t opcode = (header.flags >> 11) & 0x0F;
    printf("\t\tOpcode: 0x%02x ", opcode);
    if (opcode == DNS_OPCODE_QUERY) {
        printf("(Query)\n");
    } else if (opcode == DNS_OPCODE_IQUERY) {
        printf("(Inverse Query)\n");
    } else if (opcode == DNS_OPCODE_STATUS) {
        printf("(Status)\n");
    } else if (opcode == DNS_OPCODE_NOTIFY) {
        printf("(Notify)\n");
    } else if (opcode == DNS_OPCODE_UPDATE) {
        printf("(Update)\n");
    } else if (opcode == DNS_OPCODE_DSO) {
        printf("(DNS Stateful Operations)\n");
    } else {
        printf("(Unassigned)\n");
    }

    /* Authoritative Answer */
    printf("\t\tAuthoritative Answer: ");
    if (header.flags & DNS_FLAG_AA) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Truncated */
    printf("\t\tTruncated: ");
    if (header.flags & DNS_FLAG_TC) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Recursion Desired */
    printf("\t\tRecursion Desired: ");
    if (header.flags & DNS_FLAG_RD) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Recursion Available */
    printf("\t\tRecursion Available: ");
    if (header.flags & DNS_FLAG_RA) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Authentic Data */
    printf("\t\tAuthentic Data: ");
    if (header.flags & DNS_FLAG_AD) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Checking Disabled */
    printf("\t\tChecking Disabled: ");
    if (header.flags & DNS_FLAG_CD) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }

    /* Response Code */
    uint8_t rcode = header.flags & 0x000F;
    printf("\t\tResponse Code: 0x%02x ", rcode);
    if (rcode == DNS_RCODE_NOERROR) {
        printf("(NOERROR - No Error)\n");
    } else if (rcode == DNS_RCODE_FORMERR) {
        printf("(FORMERR - Format Error)\n");
    } else if (rcode == DNS_RCODE_SERVFAIL) {
        printf("(SERVFAIL - Server Failure)\n");
    } else if (rcode == DNS_RCODE_NXDOMAIN) {
        printf("(NXDOMAIN - Non-Existent Domain)\n");
    } else if (rcode == DNS_RCODE_NOTIMP) {
        printf("(NOTIMP - Not Implemented)\n");
    } else if (rcode == DNS_RCODE_REFUSED) {
        printf("(REFUSED - Query Refused)\n");
    } else if (rcode == DNS_RCODE_YXDOMAIN) {
        printf("(YXDOMAIN - Name Exists when it should not)\n");
    } else if (rcode == DNS_RCODE_YXRRSET) {
        printf("(YXRRSET - RR Set Exists when it should not)\n");
    } else if (rcode == DNS_RCODE_NXRRSET) {
        printf("(NXRRSET - RR Set that should exist does not)\n");
    } else if (rcode == DNS_RCODE_NOTAUTH) {
        printf("(NOTAUTH - Server Not Authoritative for zone)\n");
    } else if (rcode == DNS_RCODE_NOTZONE) {
        printf("(NOTZONE - Name not contained in zone)\n");
    } else if (rcode == DNS_RCODE_DSOTYPENI) {
        printf("(DSOTYPENI - DSO-TYPE Not Implemented)\n");
    } else if (rcode == DNS_RCODE_BADVERS) {
        printf("(BADVERS - Bad OPT Version)\n");
    } else if (rcode == DNS_RCODE_BADKEY) {
        printf("(BADKEY - Key not recognized)\n");
    } else if (rcode == DNS_RCODE_BADTIME) {
        printf("(BADTIME - Signature out of time window)\n");
    } else if (rcode == DNS_RCODE_BADMODE) {
        printf("(BADMODE - Bad TKEY Mode)\n");
    } else if (rcode == DNS_RCODE_BADNAME) {
        printf("(BADNAME - Duplicate key name)\n");
    } else if (rcode == DNS_RCODE_BADALG) {
        printf("(BADALG - Algorithm not supported)\n");
    } else if (rcode == DNS_RCODE_BADTRUNC) {
        printf("(BADTRUNC - Bad Truncation)\n");
    } else if (rcode == DNS_RCODE_BADCOOKIE) {
        printf("(BADCOOKIE - Bad/missing Server Cookie)\n");
    } else {
        printf("(Unknown)\n");
    }

    printf("\t\tNumber of Questions: %d\n", header.num_questions);
    printf("\t\tNumber of Answers: %d\n", header.num_answers);
    printf("\t\tNumber of Authority Records: %d\n", header.num_auth_rr);
    printf("\t\tNumber of Additional Records: %d\n", header.num_add_rr);
}

int main(int argc, char** argv)
{
    /* SOCK_RAW: receive raw Ethernet frames with headers */
    /* ETH_P_ALL: capture all protocols */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* Bind to a specific interface: */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = if_nametoindex("eth0"),
    };
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    // /* Set promiscuous mode: receive all frames, even non-unicast: */
    // struct packet_mreq mreq = {
    //     .mr_ifindex = if_nametoindex("eth0"),
    //     .mr_type    = PACKET_MR_PROMISC,
    // };
    // setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    uint8_t buf[65536];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    long long packet_cnt = 0;
    while (1) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&src_addr, &addr_len);
        
        // skip packets not from eth0
        if (src_addr.sll_ifindex != if_nametoindex("eth0"))
            continue;

        packet_cnt++;

        /* buf[0..13]: Ethernet header
        buf[0..5]:  destination MAC
        buf[6..11]: source MAC
        buf[12..13]: EtherType (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
        buf[14..n-1]: payload */

        printf("---------------------- PACKET #%lld ----------------------\n\n", packet_cnt);

        struct ethernet_header eth_header;
        eth_header = parse_ethernet(buf);

        print_ethernet(eth_header);

        /* IPv4 */
        if (eth_header.ether_type == ETHER_TYPE_IPV4) {
            struct ipv4_header ipv4_header;
            ipv4_header = parse_ipv4(buf+14);
            print_ipv4(ipv4_header);

            int ip_len = ipv4_header.ihl * 4;
            if (ipv4_header.protocol == IP_PROTO_TCP) {
                struct tcp_header tcp_header;
                tcp_header = parse_tcp(buf+14+ip_len);
                print_tcp(tcp_header);
            } else if (ipv4_header.protocol == IP_PROTO_UDP) {
                struct udp_header udp_header;
                udp_header = parse_udp(buf+14+ip_len);
                print_udp(udp_header);

                if (udp_header.src_port == DNS_PORT || udp_header.dest_port == DNS_PORT) {
                    struct dns_header dns_header;
                    dns_header = parse_dns(buf+14+ip_len+8);
                    print_dns(dns_header);
                }
            }
        }
        /* IPv6 */
        else if (eth_header.ether_type == ETHER_TYPE_IPV6) {
            struct ipv6_header ipv6_header;
            ipv6_header = parse_ipv6(buf+14);
            print_ipv6(ipv6_header);

            if (ipv6_header.next_header == IP_PROTO_TCP) {
                struct tcp_header tcp_header;
                tcp_header = parse_tcp(buf+14+40);
                print_tcp(tcp_header);
            } else if (ipv6_header.next_header == IP_PROTO_UDP) {
                struct udp_header udp_header;
                udp_header = parse_udp(buf+14+40);
                print_udp(udp_header);

                if (udp_header.src_port == DNS_PORT || udp_header.dest_port == DNS_PORT) {
                    struct dns_header dns_header;
                    dns_header = parse_dns(buf+14+40+8);
                    print_dns(dns_header);
                }
            }
        }
        /* ARP */
        else if (eth_header.ether_type == ETHER_TYPE_ARP) {
            struct arp_header arp_header;
            arp_header = parse_arp(buf+14);
            print_arp(arp_header);
        }

        printf("-------------------------------------------------------\n\n");
    }
}