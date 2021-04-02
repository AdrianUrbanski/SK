#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "icmp_checksum.h"

struct icmp create_header (u_int16_t seq) {
	struct icmp header;
	header.icmp_type = ICMP_ECHO;
	header.icmp_code = 0;
	header.icmp_hun.ih_idseq.icd_id = htons(getpid());
	header.icmp_hun.ih_idseq.icd_seq = htons(seq);
	header.icmp_cksum = 0;
	// dlaczego tu nie htons?
	header.icmp_cksum = compute_icmp_checksum((u_int16_t*) &header, sizeof(header));
	
	return header;
}


ssize_t send_packet (int sockfd, u_int16_t seq, char* ip_addr) {

	struct icmp header = create_header(seq);

	struct sockaddr_in	recipient;
	socklen_t		recipient_len = sizeof(recipient);
	bzero (&recipient, recipient_len);
	recipient.sin_family = AF_INET;
	inet_pton(AF_INET, ip_addr, &recipient.sin_addr);

	ssize_t bytes_sent = sendto (
			sockfd,
			&header,
			sizeof(header),
			0,
			(struct sockaddr*)&recipient,
			recipient_len
		);
	if (bytes_sent < 0) {
		fprintf(stderr, "sendto error: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	return bytes_sent;
}
