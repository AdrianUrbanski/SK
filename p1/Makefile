# Usage:
#
#

CC = gcc

CFLAGS = -Wall -Wextra -std=gnu17

SRCS := icmp_receive.c
BINS := icmp_receive

traceroute:
	${CC} ${CFLAGS} -c icmp_checksum.c icmp_receive.c icmp_send.c traceroute.c
	${CC} ${CFLAGS} -o traceroute traceroute.o icmp_send.o icmp_receive.o icmp_checksum.o

clean:
	@echo "Cleaning up..."
	rm -rvf traceroute *.o
