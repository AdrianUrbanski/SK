#ifndef ICMP_SEND_H
#define ICMP_SEND_H
#include <netinet/ip_icmp.h>

ssize_t send_packet (int sockfd, struct icmp header, char* ip_addr);

#endif
