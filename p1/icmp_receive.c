#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

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
