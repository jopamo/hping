/*
 * $smu-mark$
 * $name: listen.c$
 * $author: Salvatore Sanfilippo <antirez@invece.org>$
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 9$   // incremented
 */

/* $Id: listen.c,v 1.3 2025/07/17 10:55:00 user Exp $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "hping2.h"   /* hping2.h includes hcmp.h */
#include "globals.h"

/* write exactly count bytes or return -1 on failure */
static int safe_write(int fd, const void *buf, size_t count)
{
	const unsigned char *p = buf;

	while (count) {
		ssize_t n = write(fd, p, count);
		if (n < 0) {
			if (errno == EINTR)
				continue; /* interrupted by signal, retry */
			return -1;     /* real error */
		}
		p     += n;
		count -= n;
	}
	return 0;
}

void listenmain(void)
{
	int size, ip_size;
	int stdoutFD = fileno(stdout);
	char packet[IP_MAX_SIZE + linkhdr_size];
	char *p, *ip_packet;
	struct myiphdr ip;
	__u16 id;
	static __u16 exp_id; /* expected id */

	exp_id = 1;

	for (;;) {
		size = read_packet(packet, IP_MAX_SIZE + linkhdr_size);
		if (size == 0)
			continue;
		if (size == -1)
			exit(1);

		/* Skip truncated packets */
		if (size < linkhdr_size + IPHDR_SIZE)
			continue;
		ip_packet = packet + linkhdr_size;

		/* copy the ip header so it is aligned */
		memcpy(&ip, ip_packet, sizeof(ip));
		id      = ntohs(ip.id);
		ip_size = ntohs(ip.tot_len);
		if (size - linkhdr_size > ip_size)
			size = ip_size;
		else
			size -= linkhdr_size;

		if ((p = memstr(ip_packet, sign, size))) {
			if (opt_verbose)
				fprintf(stderr, "packet %d received\n", id);

			if (opt_safe) {
				if (id == exp_id)
					exp_id++;
				else {
					if (opt_verbose)
						fprintf(stderr, "packet not in sequence (id %d) received\n", id);
					send_hcmp(HCMP_RESTART, exp_id);
					if (opt_verbose)
						fprintf(stderr, "HCMP restart from %d sent\n", exp_id);
					continue; /* discard this packet */
				}
			}

			p += strlen(sign);
			if (safe_write(stdoutFD, p, size - (p - ip_packet)) == -1) {
				perror("hping2: write failed");
				exit(1);
			}
		}
	}
}
