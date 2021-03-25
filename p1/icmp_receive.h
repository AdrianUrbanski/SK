#ifndef ICMP_RECEIVE_H
#define ICMP_RECEIVE_H

#include <stdlib.h>

ssize_t recv_packet (int sockfd, u_int8_t* buffer);

#endif
