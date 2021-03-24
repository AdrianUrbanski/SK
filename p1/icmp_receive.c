#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>


void print_as_bytes (unsigned char* buff, ssize_t length) {
	for (ssize_t i = 0; i < length; i++, buff++)
		printf ("%.2x ", *buff);	
}

ssize_t recv_packet (int sockfd, u_int8_t* buffer) {
	struct sockaddr_in 	sender;	
	socklen_t 		sender_len = sizeof(sender);

	ssize_t packet_len = recvfrom (sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr*)&sender, &sender_len);
	if (packet_len < 0) {
		fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

	char sender_ip_str[20]; 
	inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));

	printf ("Received IP packet with ICMP content from: %s\n", sender_ip_str);

	return packet_len;
}

int main() {
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

	fd_set descriptors;
	FD_ZERO(&descriptors);
	FD_SET(sockfd, &descriptors);
	struct timeval tv; tv.tv_sec = 3; tv.tv_usec = 0;
	int ready;

	while ( (ready = select(sockfd+1, &descriptors, NULL, NULL, &tv)) ) {
		u_int8_t 		buffer[IP_MAXPACKET];

		ssize_t packet_len = recv_packet(sockfd, buffer);

		struct ip* 			ip_header = (struct ip*) buffer;
		ssize_t				ip_header_len = 4 * ip_header->ip_hl;

		printf ("IP header: "); 
		print_as_bytes (buffer, ip_header_len);
		printf("\n");

		printf ("IP data:   ");
		print_as_bytes (buffer + ip_header_len, packet_len - ip_header_len);
		printf("\n\n");
	}
	if (ready < 0) {
		fprintf(stderr, "select error: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
