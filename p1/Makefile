# Usage:
#
#

.PHONY = all clean

CC = gcc	# compiler to use

LINKERFLAG = -lm

SRCS := icmp_receive.c
BINS := icmp_receive

all: icmp_receive

icmp_receive: icmp_receive.o
	@echo "Checking..."
	${CC} ${LINKERFLAG} icmp_receive.o -o icmp_receive

icmp_receive.o: icmp_receive.c
	@echo "Creating object..."
	${CC} -c icmp_receive.c

clean:
	@echo "Cleaning up..."
	rm -rvf icmp_receive.o icmp_receive
