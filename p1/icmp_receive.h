#ifndef ICMP_RECEIVE_H
#define ICMP_RECEIVE_H

#include <stdlib.h>

ssize_t recv_packet (int sockfd, u_int8_t* buffer, char* sender_ip_str, u_int8_t sender_ip_len);

#endif
