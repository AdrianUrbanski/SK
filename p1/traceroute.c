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

#include "icmp_receive.h"
#include "icmp_send.h"

void print_as_bytes (unsigned char* buff, ssize_t length) {
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);	
}

int main(){
	char target_ip[20] = "8.8.8.8";
	bool verbose = true;
	
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}
	

	char 		sender_ip[20] = "0.0.0.0";
	u_int16_t	id = getpid();

	fd_set descriptors;
	FD_ZERO(&descriptors);
	struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
	int ready;

	int ttl = 0;
	while ( strcmp(target_ip, sender_ip) && ttl < 30){
		++ttl;
		if (setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
			fprintf(stderr, "setsockopt error: %s\n", strerror(errno)); 
			return EXIT_FAILURE;
		}
		FD_SET(sockfd, &descriptors);

		if(verbose)
			printf("TTL: %d\n", ttl);
		for (int i=0; i<3; ++i){
			ssize_t bytes_sent = send_packet( sockfd, 3*(ttl-1)+i, target_ip );
			if (verbose)
				printf("Sent %ld bytes to %s\n", bytes_sent, target_ip);
		}

		while ( (ready = select(sockfd+1, &descriptors, NULL, NULL, &tv)) ) {
			u_int8_t 	buffer[IP_MAXPACKET];

			ssize_t packet_len = recv_packet(sockfd, buffer, sender_ip, sizeof(sender_ip));

			if (verbose){
				printf("Received IP packet with ICMP content from: %s\n", sender_ip);
				printf("Packet length: %ld\n", packet_len);
			}


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
			if (verbose) {
				printf("ICMP id:   %u\n", recv_id);
				printf("ICMP seq:  %u\n", recv_seq);
				printf("\n\n");
			}
		}
		if (ready < 0) {
			fprintf(stderr, "select error: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
