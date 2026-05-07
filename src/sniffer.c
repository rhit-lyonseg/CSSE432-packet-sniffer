/* sniffer.c

    Description: This is a packet sniffer that captures raw packets,
                 parses them, and displays their contents.

    Authors: Ellis Lyons, Mark Hankins

    Date Modified: 04/30/2026

    References: https://kernel-internals.org/net/packet-socket/
*/

#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>


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

        struct ethhdr *eth = (struct ethhdr *)buf;
        printf("src: %02x:%02x:%02x:%02x:%02x:%02x → "
            "dst: %02x:%02x:%02x:%02x:%02x:%02x "
            "proto: 0x%04x\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5],
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
            ntohs(eth->h_proto));
    }
}