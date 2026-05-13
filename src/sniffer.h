#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>

#define ETHER_TYPE_IPV4  0x0800
#define ETHER_TYPE_ARP   0x0806
#define ETHER_TYPE_IPV6  0x86DD

#define IP_PROTO_ICMP   1
#define IP_PROTO_IGMP   2
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ENCAP  41
#define IP_PROTO_ICMPv6 58
#define IP_PROTO_OSPF   89
#define IP_PROTO_SCTP   132

#define DSCP_BEST_EFFORT    0

#define ECN_NOT_ECT  0
#define ECN_ECT1     1
#define ECN_ECT0     2
#define ECN_CE       3

#define IPV4_FLAG_MF  0x01
#define IPV4_FLAG_DF  0x02

#define ARP_HW_ETHERNET     1
#define ARP_HW_IEEE802      6

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

struct ethernet_header {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

struct ipv4_header {
    uint8_t  version;
    uint8_t  ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint8_t  flags;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dest_ip[4];
};

struct ipv6_header {
    uint8_t  version;
    uint8_t  traffic_class;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dest_ip[16];
};

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_length;
    uint8_t  proto_length;
    uint16_t operation;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

struct ethernet_header parse_ethernet(uint8_t *packet);
struct ipv4_header parse_ipv4(uint8_t *packet);
struct ipv6_header parse_ipv6(uint8_t *packet);
struct arp_header parse_arp(uint8_t *packet);
struct udp_header parse_udp(uint8_t *packet);
struct tcp_header parse_tcp(uint8_t *packet);

void print_ethernet(struct ethernet_header header);
void print_ipv4(struct ipv4_header header);
void print_ipv6(struct ipv6_header header);
void print_arp(struct arp_header header);
void print_udp(struct udp_header header);
void print_tcp(struct tcp_header header);

#endif /* SNIFFER_H */