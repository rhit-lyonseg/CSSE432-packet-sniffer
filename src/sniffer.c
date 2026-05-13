/* sniffer.c

    Description: This is a packet sniffer that captures raw packets,
                 parses them, and displays their contents.

    Authors: Ellis Lyons, Mark Hankins

    Date Modified: 05/07/2026

    References: https://kernel-internals.org/net/packet-socket/
                https://en.wikipedia.org/wiki/IPv4
                https://en.wikipedia.org/wiki/IPv6
                https://en.wikipedia.org/wiki/Address_Resolution_Protocol
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "sniffer.h"

struct ipv4_header parse_ipv4(uint8_t *packet) {
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

    /* Set promiscuous mode: receive all frames, even non-unicast: */
    struct packet_mreq mreq = {
        .mr_ifindex = if_nametoindex("eth0"),
        .mr_type    = PACKET_MR_PROMISC,
    };
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    uint8_t buf[65536];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                            (struct sockaddr *)&src_addr, &addr_len);
        
        // skip packets not from eth0
        if (src_addr.sll_ifindex != if_nametoindex("eth0"))
            continue;

        /* buf[0..13]: Ethernet header
        buf[0..5]:  destination MAC
        buf[6..11]: source MAC
        buf[12..13]: EtherType (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
        buf[14..n-1]: payload */

        struct ethernet_header eth_header;
        memcpy(eth_header.dest_mac, buf, 6);
        memcpy(eth_header.src_mac, buf+6, 6);
        eth_header.ether_type = (buf[12] << 8) + buf[13];

        printf("src: %02x:%02x:%02x:%02x:%02x:%02x → "
            "dst: %02x:%02x:%02x:%02x:%02x:%02x "
            "proto: 0x%04x\n",
            eth_header.src_mac[0], eth_header.src_mac[1],
            eth_header.src_mac[2], eth_header.src_mac[3],
            eth_header.src_mac[4], eth_header.src_mac[5],
            eth_header.dest_mac[0], eth_header.dest_mac[1],
            eth_header.dest_mac[2], eth_header.dest_mac[3],
            eth_header.dest_mac[4], eth_header.dest_mac[5],
            eth_header.ether_type);

        /* IPv4 */
        if (eth_header.ether_type == ETHER_TYPE_IPV4) {
            struct ipv4_header header;
            header = parse_ipv4(buf+14);
        }
        /* IPv6 */
        else if (eth_header.ether_type == ETHER_TYPE_IPV6) {
            struct ipv6_header header;
            header = parse_ipv6(buf+14);
        }
        /* ARP */
        else if (eth_header.ether_type == ETHER_TYPE_ARP) {
            struct arp_header header;
            header = parse_arp(buf+14);
        }
    }
}