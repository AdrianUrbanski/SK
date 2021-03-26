#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>

#include "icmp_receive.h"
#include "icmp_send.h"

#define VERBOSE false

typedef struct Packets {
	char sender_ip[20];
	suseconds_t elapsed;
	bool received;
} Packet;

void print_as_bytes (unsigned char* buff, ssize_t length);
int recv_packets(int sockfd, int id, int ttl, Packet* packets);
int send_packets(int sockdf, int ttl, char* target_ip, Packet* packets);
double usec_to_msec(suseconds_t usec);
void process_packet(int ttl, int id, int usec_elapsed, char* sender_ip, u_int8_t* buffer, Packet* packets);

int main(){
	char target_ip[20] = "8.8.8.8";
	char sender_ip[20] = "0.0.0.0";
	Packet packets[3];
	
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}
	
	u_int16_t	id = getpid();


	int ttl = 0;
	while ( strcmp(target_ip, sender_ip) && ttl < 30){
		++ttl;
		if (setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
			fprintf(stderr, "setsockopt error: %s\n", strerror(errno)); 
			return EXIT_FAILURE;
		}

		printf("TTL: %d\n", ttl);

		if (send_packets(sockfd, ttl, target_ip, packets) == EXIT_FAILURE)
			return EXIT_FAILURE;

		if (recv_packets(sockfd, id, ttl, packets) == EXIT_FAILURE)
			return EXIT_FAILURE;

		for (int i=0; i<3; i++)
			if(packets[i].received == true)
				printf("IP: %s, time: %lfms\n",
						packets[i].sender_ip,
						usec_to_msec(packets[i].elapsed));
	}

	return EXIT_SUCCESS;
}

void print_as_bytes (unsigned char* buff, ssize_t length) {
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);	
}

double usec_to_msec(suseconds_t usec){
	return (double) usec/1000;
}

int send_packets(int sockfd, int ttl, char* target_ip, Packet* packets){
	for (int i=0; i<3; ++i){
		ssize_t bytes_sent = send_packet( sockfd, 3*(ttl-1)+i, target_ip );
		if (bytes_sent == EXIT_FAILURE)
			return EXIT_FAILURE;
		packets[i].received = false;
		if (VERBOSE)
			printf("Sent %ld bytes to %s\n", bytes_sent, target_ip);
	}
	return EXIT_SUCCESS;
}

int recv_packets(int sockfd, int id, int ttl, Packet* packets){
	fd_set descriptors;
	FD_ZERO(&descriptors);
	FD_SET(sockfd, &descriptors);

	struct timeval tv; tv.tv_sec=1; tv.tv_usec = 0;
	struct timeval t0, t1;
	gettimeofday(&t0, NULL);

	char sender_ip[20];
	int ready;
	while ( (ready = select(sockfd+1, &descriptors, NULL, NULL, &tv)) ) {
		u_int8_t 	buffer[IP_MAXPACKET];

		gettimeofday(&t1, NULL);
		int usec_elapsed = (1000000 * (t1.tv_sec - t0.tv_sec) + t1.tv_usec - t0.tv_usec);
		ssize_t packet_len = recv_packet(sockfd, buffer, sender_ip, sizeof(sender_ip));
		if (packet_len == EXIT_FAILURE)
			return EXIT_FAILURE;

		process_packet(ttl, id, usec_elapsed, sender_ip, buffer, packets);

		if (VERBOSE){
			printf("Received IP packet with ICMP content from: %s\n", sender_ip);
			printf("Packet length: %ld\n", packet_len);
		}

		tv.tv_sec = 0;
		tv.tv_usec = 1000000 - usec_elapsed;

	}
	if (ready < 0) {
		fprintf(stderr, "select error: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void process_packet(int ttl, int id, int usec_elapsed, char* sender_ip, u_int8_t* buffer, Packet* packets){
	struct ip* 	ip_header = (struct ip*) buffer;
	ssize_t		ip_header_len = 4 * ip_header->ip_hl;
	struct icmp*	icmp_header = (struct icmp*) (buffer + ip_header_len);

	if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED){
		ip_header_len += 8;
		ip_header = (struct ip*) buffer;
		ip_header_len += 4 * ip_header->ip_hl;
		icmp_header = (struct icmp*) (buffer + ip_header_len);
	}
	u_int16_t recv_id = ntohs(icmp_header->icmp_hun.ih_idseq.icd_id);
	u_int16_t recv_seq = ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq);
	if (recv_id == id && recv_seq/3 == ttl-1) {
		packets[recv_seq%3].received = true;
		strcpy(packets[recv_seq%3].sender_ip, sender_ip);
		packets[recv_seq%3].elapsed = usec_elapsed;
	}
	if (VERBOSE) {
		printf("ICMP id:   %u\n", recv_id);
		printf("ICMP seq:  %u\n", recv_seq);
		printf("Time elapsed: %lfms\n", usec_to_msec(usec_elapsed));
		printf("\n");
	}
}
