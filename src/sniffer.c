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
#include <signal.h>
#include "sniffer.h"

volatile int running = 1;

void handle_sigint(int sig)
{
    running = 0;
}

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

void print_ethernet(FILE *f, struct ethernet_header header)
{
    fprintf(f, "\t[ETHERNET]\n");
    fprintf(f, "\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.src_mac[0], header.src_mac[1],
                                                                header.src_mac[2], header.src_mac[3],
                                                                header.src_mac[4], header.src_mac[5]);
    fprintf(f, "\t\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.dest_mac[0], header.dest_mac[1],
                                                                header.dest_mac[2], header.dest_mac[3],
                                                                header.dest_mac[4], header.dest_mac[5]);
    
    fprintf(f, "\t\tEther Type: ");
    if (header.ether_type == ETHER_TYPE_IPV4) {
        fprintf(f, "IPv4\n");
    } else if (header.ether_type == ETHER_TYPE_IPV6) {
        fprintf(f, "IPv6\n");
    } else if (header.ether_type == ETHER_TYPE_ARP) {
        fprintf(f, "ARP\n");
    }
}

void print_ipv4(FILE *f, struct ipv4_header header)
{
    fprintf(f, "\t[IPv4]\n");
    fprintf(f, "\t\tVersion: %d\n", header.version);
    fprintf(f, "\t\tInternet Header Length: %d bytes\n", header.ihl * 4);

    /* DSCP */
    uint8_t dscp = header.tos >> 2;
    fprintf(f, "\t\tDSCP: %d ", dscp);
    if (dscp == DSCP_BEST_EFFORT) {
        fprintf(f, "(Best Effort)\n");
    } else {
        fprintf(f, "(Unknown)\n");
    }

    /* ECN */
    uint8_t ecn = header.tos & 0x03;
    fprintf(f, "\t\tECN: %d ", ecn);
    if (ecn == ECN_NOT_ECT) {
        fprintf(f, "(Not ECN Capable)\n");
    } else if (ecn == ECN_ECT0) {
        fprintf(f, "(ECN Capable)\n");
    } else if (ecn == ECN_ECT1) {
        fprintf(f, "(ECN Capable)\n");
    } else if (ecn == ECN_CE) {
        fprintf(f, "(Congestion Experienced)\n");
    }

    fprintf(f, "\t\tTotal Length: %d\n", header.total_len);
    fprintf(f, "\t\tID: 0x%04x\n", header.id);

    /* Flags */
    fprintf(f, "\t\tFlags: 0x%02x ", header.flags);
    if (header.flags & IPV4_FLAG_DF) {
        fprintf(f, "(DF) ");
    }
    if (header.flags & IPV4_FLAG_MF) {
        fprintf(f, "(MF) ");
    }
    fprintf(f, "\n");

    fprintf(f, "\t\tFragment Offset: %d\n", header.fragment_offset);
    fprintf(f, "\t\tTime to Live: %d\n", header.ttl);

    /* Protocol */
    fprintf(f, "\t\tProtocol: ");
    if (header.protocol == IP_PROTO_TCP) {
        fprintf(f, "TCP\n");
    } else if (header.protocol == IP_PROTO_UDP) {
        fprintf(f, "UDP\n");
    } else if (header.protocol == IP_PROTO_ICMP) {
        fprintf(f, "ICMP\n");
    } else if (header.protocol == IP_PROTO_IGMP) {
        fprintf(f, "IGMP\n");
    } else if (header.protocol == IP_PROTO_ENCAP) {
        fprintf(f, "ENCAP\n");
    } else if (header.protocol == IP_PROTO_OSPF) {
        fprintf(f, "OSPF\n");
    } else if (header.protocol == IP_PROTO_SCTP) {
        fprintf(f, "SCTP\n");
    } else {
        fprintf(f, "0x%02x (Unknown)\n", header.protocol);
    }

    fprintf(f, "\t\tChecksum: 0x%04x\n", header.checksum);
    fprintf(f, "\t\tSource IP: %d.%d.%d.%d\n", header.src_ip[0], header.src_ip[1],
                                            header.src_ip[2], header.src_ip[3]);
    fprintf(f, "\t\tDestination IP: %d.%d.%d.%d\n", header.dest_ip[0], header.dest_ip[1],
                                                 header.dest_ip[2], header.dest_ip[3]);
}

void print_ipv6(FILE *f, struct ipv6_header header)
{
    fprintf(f, "\t[IPv6]\n");
    fprintf(f, "\t\tVersion: %d\n", header.version);
    fprintf(f, "\t\tTraffic Class: 0x%02x\n", header.traffic_class);
    fprintf(f, "\t\tFlow Label: 0x%05x\n", header.flow_label);
    fprintf(f, "\t\tPayload Length: %d\n", header.payload_length);

    /* Next Header */
    fprintf(f, "\t\tNext Header: ");
    if (header.next_header == IP_PROTO_TCP) {
        fprintf(f, "TCP\n");
    } else if (header.next_header == IP_PROTO_UDP) {
        fprintf(f, "UDP\n");
    } else if (header.next_header == IP_PROTO_ICMPv6) {
        fprintf(f, "ICMPv6\n");
    } else {
        fprintf(f, "0x%02x (Unknown)\n", header.next_header);
    }

    fprintf(f, "\t\tHop Limit: %d\n", header.hop_limit);
    fprintf(f, "\t\tSource IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           header.src_ip[0], header.src_ip[1], header.src_ip[2], header.src_ip[3],
           header.src_ip[4], header.src_ip[5], header.src_ip[6], header.src_ip[7],
           header.src_ip[8], header.src_ip[9], header.src_ip[10], header.src_ip[11],
           header.src_ip[12], header.src_ip[13], header.src_ip[14], header.src_ip[15]);
    fprintf(f, "\t\tDestination IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           header.dest_ip[0], header.dest_ip[1], header.dest_ip[2], header.dest_ip[3],
           header.dest_ip[4], header.dest_ip[5], header.dest_ip[6], header.dest_ip[7],
           header.dest_ip[8], header.dest_ip[9], header.dest_ip[10], header.dest_ip[11],
           header.dest_ip[12], header.dest_ip[13], header.dest_ip[14], header.dest_ip[15]);
}

void print_arp(FILE *f, struct arp_header header)
{
    fprintf(f, "\t[ARP]\n");

    /* HW Type */
    fprintf(f, "\t\tHardware Type: ");
    if (header.hw_type == ARP_HW_ETHERNET) {
        fprintf(f, "Ethernet\n");
    } else if (header.hw_type == ARP_HW_IEEE802) {
        fprintf(f, "IEEE 802\n");
    } else {
        fprintf(f, "0x%04x (Unknown)\n", header.hw_type);
    }

    /* Protocol Type */
    fprintf(f, "\t\tProtocol Type: ");
    if (header.proto_type == ETHER_TYPE_IPV4) {
        fprintf(f, "IPv4\n");
    } else if (header.proto_type == ETHER_TYPE_IPV6) {
        fprintf(f, "IPv6\n");
    } else if (header.proto_type == ETHER_TYPE_ARP) {
        fprintf(f, "ARP\n");
    } else {
        fprintf(f, "0x%04x (Unknown)\n", header.proto_type);
    }

    fprintf(f, "\t\tHardware Address Length: %d\n", header.hw_length);
    fprintf(f, "\t\tProtocol Address Length: %d\n", header.proto_length);

    /* Operation */
    fprintf(f, "\t\tOperation: ");
    if (header.operation == ARP_OP_REQUEST) {
        fprintf(f, "Request\n");
    } else if (header.operation == ARP_OP_REPLY) {
        fprintf(f, "Reply\n");
    } else {
        fprintf(f, "0x%04x (Unknown)\n", header.operation);
    }

    fprintf(f, "\t\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.sender_mac[0], header.sender_mac[1],
                                                               header.sender_mac[2], header.sender_mac[3],
                                                               header.sender_mac[4], header.sender_mac[5]);
    fprintf(f, "\t\tSender IP: %d.%d.%d.%d\n", header.sender_ip[0], header.sender_ip[1],
                                            header.sender_ip[2], header.sender_ip[3]);
    fprintf(f, "\t\tTarget MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", header.target_mac[0], header.target_mac[1],
                                                               header.target_mac[2], header.target_mac[3],
                                                               header.target_mac[4], header.target_mac[5]);
    fprintf(f, "\t\tTarget IP: %d.%d.%d.%d\n", header.target_ip[0], header.target_ip[1],
                                            header.target_ip[2], header.target_ip[3]);
}

void print_tcp(FILE *f, struct tcp_header header)
{
    fprintf(f, "\t[TCP]\n");
    fprintf(f, "\t\tSource Port: %d\n", header.src_port);
    fprintf(f, "\t\tDestination Port: %d\n", header.dest_port);
    fprintf(f, "\t\tSequence Number: %u\n", header.seq_num);
    fprintf(f, "\t\tAcknowledgment Number: %u\n", header.ack_num);
    fprintf(f, "\t\tData Offset: %d bytes\n", header.data_offset * 4);
    fprintf(f, "\t\tFlags: 0x%02x ", header.flags);
    if (header.flags & TCP_FIN) {
        fprintf(f, "(FIN) ");
    }
    if (header.flags & TCP_SYN) {
        fprintf(f, "(SYN) ");
    }
    if (header.flags & TCP_RST) {
        fprintf(f, "(RST) ");
    }
    if (header.flags & TCP_PSH) {
        fprintf(f, "(PSH) ");
    }
    if (header.flags & TCP_ACK) {
        fprintf(f, "(ACK) ");
    }
    if (header.flags & TCP_URG) {
        fprintf(f, "(URG) ");
    }
    if (header.flags & TCP_ECE) {
        fprintf(f, "(ECE) ");
    }
    if (header.flags & TCP_CWR) {
        fprintf(f, "(CWR) ");
    }
    fprintf(f, "\n");
    fprintf(f, "\t\tWindow Size: %d\n", header.window);
    fprintf(f, "\t\tChecksum: 0x%04x\n", header.checksum);
    fprintf(f, "\t\tUrgent Pointer: %d\n", header.urg_ptr);
}

void print_udp(FILE *f, struct udp_header header)
{
    fprintf(f, "\t[UDP]\n");
    fprintf(f, "\t\tSource Port: %d\n", header.src_port);
    fprintf(f, "\t\tDestination Port: %d\n", header.dest_port);
    fprintf(f, "\t\tLength: %d bytes\n", header.length);
    fprintf(f, "\t\tChecksum: 0x%04x\n", header.checksum);
}

void print_dns(FILE *f, struct dns_header header)
{
    fprintf(f, "\t[DNS]\n");
    fprintf(f, "\t\tTransaction ID: 0x%04x\n", header.transaction_id);

    /* Type */
    fprintf(f, "\t\tType: ");
    if (header.flags & DNS_FLAG_QR) {
        fprintf(f, "Response\n");
    } else {
        fprintf(f, "Query\n");
    }

    /* Opcode */
    uint8_t opcode = (header.flags >> 11) & 0x0F;
    fprintf(f, "\t\tOpcode: 0x%02x ", opcode);
    if (opcode == DNS_OPCODE_QUERY) {
        fprintf(f, "(Query)\n");
    } else if (opcode == DNS_OPCODE_IQUERY) {
        fprintf(f, "(Inverse Query)\n");
    } else if (opcode == DNS_OPCODE_STATUS) {
        fprintf(f, "(Status)\n");
    } else if (opcode == DNS_OPCODE_NOTIFY) {
        fprintf(f, "(Notify)\n");
    } else if (opcode == DNS_OPCODE_UPDATE) {
        fprintf(f, "(Update)\n");
    } else if (opcode == DNS_OPCODE_DSO) {
        fprintf(f, "(DNS Stateful Operations)\n");
    } else {
        fprintf(f, "(Unassigned)\n");
    }

    /* Authoritative Answer */
    fprintf(f, "\t\tAuthoritative Answer: ");
    if (header.flags & DNS_FLAG_AA) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Truncated */
    fprintf(f, "\t\tTruncated: ");
    if (header.flags & DNS_FLAG_TC) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Recursion Desired */
    fprintf(f, "\t\tRecursion Desired: ");
    if (header.flags & DNS_FLAG_RD) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Recursion Available */
    fprintf(f, "\t\tRecursion Available: ");
    if (header.flags & DNS_FLAG_RA) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Authentic Data */
    fprintf(f, "\t\tAuthentic Data: ");
    if (header.flags & DNS_FLAG_AD) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Checking Disabled */
    fprintf(f, "\t\tChecking Disabled: ");
    if (header.flags & DNS_FLAG_CD) {
        fprintf(f, "Yes\n");
    } else {
        fprintf(f, "No\n");
    }

    /* Response Code */
    uint8_t rcode = header.flags & 0x000F;
    fprintf(f, "\t\tResponse Code: 0x%02x ", rcode);
    if (rcode == DNS_RCODE_NOERROR) {
        fprintf(f, "(NOERROR - No Error)\n");
    } else if (rcode == DNS_RCODE_FORMERR) {
        fprintf(f, "(FORMERR - Format Error)\n");
    } else if (rcode == DNS_RCODE_SERVFAIL) {
        fprintf(f, "(SERVFAIL - Server Failure)\n");
    } else if (rcode == DNS_RCODE_NXDOMAIN) {
        fprintf(f, "(NXDOMAIN - Non-Existent Domain)\n");
    } else if (rcode == DNS_RCODE_NOTIMP) {
        fprintf(f, "(NOTIMP - Not Implemented)\n");
    } else if (rcode == DNS_RCODE_REFUSED) {
        fprintf(f, "(REFUSED - Query Refused)\n");
    } else if (rcode == DNS_RCODE_YXDOMAIN) {
        fprintf(f, "(YXDOMAIN - Name Exists when it should not)\n");
    } else if (rcode == DNS_RCODE_YXRRSET) {
        fprintf(f, "(YXRRSET - RR Set Exists when it should not)\n");
    } else if (rcode == DNS_RCODE_NXRRSET) {
        fprintf(f, "(NXRRSET - RR Set that should exist does not)\n");
    } else if (rcode == DNS_RCODE_NOTAUTH) {
        fprintf(f, "(NOTAUTH - Server Not Authoritative for zone)\n");
    } else if (rcode == DNS_RCODE_NOTZONE) {
        fprintf(f, "(NOTZONE - Name not contained in zone)\n");
    } else if (rcode == DNS_RCODE_DSOTYPENI) {
        fprintf(f, "(DSOTYPENI - DSO-TYPE Not Implemented)\n");
    } else if (rcode == DNS_RCODE_BADVERS) {
        fprintf(f, "(BADVERS - Bad OPT Version)\n");
    } else if (rcode == DNS_RCODE_BADKEY) {
        fprintf(f, "(BADKEY - Key not recognized)\n");
    } else if (rcode == DNS_RCODE_BADTIME) {
        fprintf(f, "(BADTIME - Signature out of time window)\n");
    } else if (rcode == DNS_RCODE_BADMODE) {
        fprintf(f, "(BADMODE - Bad TKEY Mode)\n");
    } else if (rcode == DNS_RCODE_BADNAME) {
        fprintf(f, "(BADNAME - Duplicate key name)\n");
    } else if (rcode == DNS_RCODE_BADALG) {
        fprintf(f, "(BADALG - Algorithm not supported)\n");
    } else if (rcode == DNS_RCODE_BADTRUNC) {
        fprintf(f, "(BADTRUNC - Bad Truncation)\n");
    } else if (rcode == DNS_RCODE_BADCOOKIE) {
        fprintf(f, "(BADCOOKIE - Bad/missing Server Cookie)\n");
    } else {
        fprintf(f, "(Unknown)\n");
    }

    fprintf(f, "\t\tNumber of Questions: %d\n", header.num_questions);
    fprintf(f, "\t\tNumber of Answers: %d\n", header.num_answers);
    fprintf(f, "\t\tNumber of Authority Records: %d\n", header.num_auth_rr);
    fprintf(f, "\t\tNumber of Additional Records: %d\n", header.num_add_rr);
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

    /* add timeout for recv */
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // /* Set promiscuous mode: receive all frames, even non-unicast: */
    // struct packet_mreq mreq = {
    //     .mr_ifindex = if_nametoindex("eth0"),
    //     .mr_type    = PACKET_MR_PROMISC,
    // };
    // setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    uint8_t buf[65536];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    /* open output file */
    FILE *f = fopen("sniffer-output.txt", "w");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    printf("Packet sniffer is running. Press Ctrl+C to exit.\n");

    signal(SIGINT, handle_sigint);
    long long packet_cnt = 0;
    while (running) {
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

        fprintf(f, "---------------------- PACKET #%lld ----------------------\n\n", packet_cnt);

        struct ethernet_header eth_header;
        eth_header = parse_ethernet(buf);

        print_ethernet(f, eth_header);

        /* IPv4 */
        if (eth_header.ether_type == ETHER_TYPE_IPV4) {
            struct ipv4_header ipv4_header;
            ipv4_header = parse_ipv4(buf+14);
            print_ipv4(f, ipv4_header);

            int ip_len = ipv4_header.ihl * 4;
            if (ipv4_header.protocol == IP_PROTO_TCP) {
                struct tcp_header tcp_header;
                tcp_header = parse_tcp(buf+14+ip_len);
                print_tcp(f, tcp_header);
            } else if (ipv4_header.protocol == IP_PROTO_UDP) {
                struct udp_header udp_header;
                udp_header = parse_udp(buf+14+ip_len);
                print_udp(f, udp_header);

                if (udp_header.src_port == DNS_PORT || udp_header.dest_port == DNS_PORT) {
                    struct dns_header dns_header;
                    dns_header = parse_dns(buf+14+ip_len+8);
                    print_dns(f, dns_header);
                }
            }
        }
        /* IPv6 */
        else if (eth_header.ether_type == ETHER_TYPE_IPV6) {
            struct ipv6_header ipv6_header;
            ipv6_header = parse_ipv6(buf+14);
            print_ipv6(f, ipv6_header);

            if (ipv6_header.next_header == IP_PROTO_TCP) {
                struct tcp_header tcp_header;
                tcp_header = parse_tcp(buf+14+40);
                print_tcp(f, tcp_header);
            } else if (ipv6_header.next_header == IP_PROTO_UDP) {
                struct udp_header udp_header;
                udp_header = parse_udp(buf+14+40);
                print_udp(f, udp_header);

                if (udp_header.src_port == DNS_PORT || udp_header.dest_port == DNS_PORT) {
                    struct dns_header dns_header;
                    dns_header = parse_dns(buf+14+40+8);
                    print_dns(f, dns_header);
                }
            }
        }
        /* ARP */
        else if (eth_header.ether_type == ETHER_TYPE_ARP) {
            struct arp_header arp_header;
            arp_header = parse_arp(buf+14);
            print_arp(f, arp_header);
        }

        fprintf(f, "-------------------------------------------------------\n\n");
    }
    printf("\nPacket sniffer finished. Sniffed %lld packets.\n", packet_cnt);

    fclose(f);
    return 0;
}