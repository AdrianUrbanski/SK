#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <regex.h>

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

int main(int argc, char* argv[]){
	if( argc != 2 ){
		fprintf(stderr, "traceroute expects exactly one argument - host ip");
		return EXIT_FAILURE;
	}
	regex_t ip_regex;
	static const char REGEX[] = "^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[ ]*$";
	if(regcomp(&ip_regex, REGEX, REG_EXTENDED)){
		fprintf(stderr, "regex compilation error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}
	int match_result = regexec(&ip_regex, argv[1], 0, NULL, 0);
	if (match_result == REG_NOMATCH){
		fprintf(stderr, "argument must be host ip");
		return EXIT_FAILURE;
	}
	else if (match_result != 0){
		fprintf(stderr, "regex match error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

	char target_ip[20];
	strcpy(target_ip, argv[1]);

	Packet packets[3];
	strcpy(packets[0].sender_ip, "0.0.0.0");
	
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}
	
	u_int16_t	id = getpid();


	int ttl = 0;
	while ( strcmp(target_ip, packets[0].sender_ip) && ttl < 30){
		++ttl;
		if (setsockopt (sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
			fprintf(stderr, "setsockopt error: %s\n", strerror(errno)); 
			return EXIT_FAILURE;
		}

		if (send_packets(sockfd, ttl, target_ip, packets) == EXIT_FAILURE)
			return EXIT_FAILURE;

		if (recv_packets(sockfd, id, ttl, packets) == EXIT_FAILURE)
			return EXIT_FAILURE;

		printf("%d. ", ttl);

		bool received_all = true;
		bool received_any = false;
		suseconds_t time = 0;
		for (int i=0; i<3; i++){
			if(packets[i].received){
				received_any = true;
				bool already_received = false;
				for (int j=0; j<i; j++)
					if (!strcmp(packets[j].sender_ip, packets[i].sender_ip))
						already_received = true;
				if (!already_received)
					printf("%s ", packets[i].sender_ip);
				time += packets[i].elapsed;
			}
			else
				received_all = false;
		}
		if (!received_any)
			printf("*\n");
		else if (received_all)
			printf("%.2lfms\n", usec_to_msec(time/3));
		else
			printf("???\n");
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

		bool received_all = true;
		for (int i=0; i<3; i++)
			if (!packets[i].received)
				received_all = false;
		if (received_all)
			return EXIT_SUCCESS;

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

	if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED) {
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
