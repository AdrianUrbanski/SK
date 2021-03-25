#ifndef ICMP_SEND_H
#define ICMP_SEND_H
#include <netinet/ip_icmp.h>

ssize_t send_packet (int sockfd, int seq, char* ip_addr);

#endif
