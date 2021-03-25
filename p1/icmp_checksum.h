#ifndef ICMP_CHECKSUM_H
#define ICMP_CHECKSUM_H

#include <stdlib.h>
#include <stdint.h>

u_int16_t compute_icmp_checksum (const void *buff, int length);

#endif
