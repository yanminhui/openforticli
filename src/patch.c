#include "patch.h"
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#if defined(HAVE_OATH)
#   include <liboath/oath.h>
#endif // HAVE_OATH

#if defined(HAVE_OATH)

static int _patch_totp_generate(const char *base32_secret, char *output_otp)
{
	int rc;
	char *secret;
	size_t secretlen = 0;
	time_t now;

	rc = oath_base32_decode(base32_secret, strlen(base32_secret),
	                        &secret, &secretlen);
	if (rc != OATH_OK) {
		log_error("base32 decoding failed: %s\n", oath_strerror(rc));
		return rc;
	}

	now = time(NULL);
	rc = oath_totp_generate2(secret,
	                         secretlen,
	                         now,
	                         OATH_TOTP_DEFAULT_TIME_STEP_SIZE,
	                         0,
	                         6,
	                         0,
	                         output_otp);
	if (rc != OATH_OK)
		log_error("generating one-time password failed: %s\n", oath_strerror(rc));
	else
		log_debug("OTP: %s\n", output_otp);
	free(secret);
	return rc;
}

int patch_totp_generate(const char *base32_secret, char *output_otp)
{
	int rc;

	rc = oath_init();
	if (rc != OATH_OK) {
		log_error("liboath initialization failed: %s\n", oath_strerror(rc));
		return rc;
	}

	rc = _patch_totp_generate(base32_secret, output_otp);
	oath_done();
	return rc;
}

#else

int patch_totp_generate(const char *base32_secret, char *output_otp)
{
	log_error("Current version compiled without liboath, Don't set --otp-secret.\n");
	return -1;
}

#endif // HAVE_OATH

#define DATA_SIZE 32

typedef struct tag_icmp_header {
	u_int8_t type;
	u_int8_t code;
	u_int16_t check_sum;
	u_int16_t id;
	u_int16_t seq;
} icmp_header;

typedef struct tag_iphdr {
	u_int8_t ip_head_verlen;
	u_int8_t ip_tos;
	unsigned short ip_length;
	unsigned short ip_id;
	unsigned short ip_flags;
	u_int8_t ip_ttl;
	u_int8_t ip_protacol;
	unsigned short ip_checksum;
	int ip_source;
	int ip_destination;
} ip_header;

static unsigned short generation_checksum(unsigned short *buf, int size)
{
	unsigned long cksum = 0;

	while (size > 1) {
		cksum += *buf++;
		size -= sizeof(unsigned short);
	}

	if (size)
		cksum += *buf++;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

static double get_time_interval(struct timeval *start, struct timeval *end)
{
	double interval;
	struct timeval tp;

	tp.tv_sec = end->tv_sec - start->tv_sec;
	tp.tv_usec = end->tv_usec - start->tv_usec;
	if (tp.tv_usec < 0) {
		tp.tv_sec -= 1;
		tp.tv_usec += 1000000;
	}

	interval = tp.tv_sec * 1000 + tp.tv_usec * 0.001;
	return interval;
}

double ping_host_ip(const char *domain)
{
	double expired_ms = -1.0;
	in_addr_t dest_ip;
	struct hostent *p_hostent = NULL;
	int client_fd;
	struct timeval timeout;
	int size = 50 * 1024;
	struct sockaddr_in dest_socket_addr;
	icmp_header *icmp_head;
	char *icmp;
	int i;

	int count = 8;
	double expired_ms_array[8];
	int expired_ms_size = 0;

	struct timeval start;
	struct timeval end;
	struct sockaddr_in from;
	socklen_t from_packet_len;
	long read_length;
	char recv_buf[1024];

	ip_header *recv_ip_header = NULL;
	int ip_ttl = 0;
	icmp_header *recv_icmp_header = NULL;

	if (!domain) {
		log_error("ping host ip's domain is NULL!\n");
		return expired_ms;
	}

	dest_ip = inet_addr(domain);
	if (dest_ip == INADDR_NONE) {
		p_hostent = gethostbyname(domain);
		if (p_hostent)
			dest_ip = (*(in_addr_t *)p_hostent->h_addr);
	}

	client_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (client_fd == -1) {
		log_error("socket error: %s!\n", strerror(errno));
		return expired_ms;
	}

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
	               &timeout, sizeof(struct timeval))) {
		log_error("setsocketopt SO_RCVTIMEO error!\n");
		return expired_ms;
	}
	if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
	               &timeout, sizeof(struct timeval))) {
		log_error("setsockopt SO_SNDTIMEO error!\n");
		return expired_ms;
	}

	dest_socket_addr.sin_family = AF_INET;
	dest_socket_addr.sin_addr.s_addr = dest_ip;
	dest_socket_addr.sin_port = htons(0);
	memset(dest_socket_addr.sin_zero, 0, sizeof(dest_socket_addr.sin_zero));

	icmp = (char *)malloc(sizeof(icmp_header) + DATA_SIZE);
	memset(icmp, 0, sizeof(icmp_header) + DATA_SIZE);

	icmp_head = (icmp_header *)icmp;
	icmp_head->type = 8;
	icmp_head->code = 0;
	icmp_head->id = 1;

	log_debug("PING %s (%s).\n", domain, inet_ntoa(*((struct in_addr *)&dest_ip)));

	for (i = 0; i < count; i++) {
		icmp_head->seq = htons(i);
		icmp_head->check_sum = 0;
		icmp_head->check_sum = generation_checksum((unsigned short *)icmp,
		                       sizeof(icmp_header) + DATA_SIZE);
		gettimeofday(&start, NULL);
		if (sendto(client_fd, icmp, sizeof(icmp_header) + DATA_SIZE, 0,
		           (struct sockaddr *)&dest_socket_addr,
		           sizeof(dest_socket_addr)) == -1) {
			log_debug("sendto: Network is unreachable\n");
			continue;
		}

		from_packet_len = sizeof(from);
		memset(recv_buf, 0, sizeof(recv_buf));
		read_length = recvfrom(client_fd, recv_buf, 1024, 0,
		                       (struct sockaddr *)&from, &from_packet_len);
		if (read_length == -1) {
			log_error("receive data error!\n");
			continue;
		}
		gettimeofday(&end, NULL);

		recv_ip_header = (ip_header *)recv_buf;
		ip_ttl = (int)recv_ip_header->ip_ttl;
		recv_icmp_header = (icmp_header *)(recv_buf +
		                                   (recv_ip_header->ip_head_verlen
		                                    & 0x0F) * 4);
		if (recv_icmp_header->type != 0) {
			log_error("error type %d received, error code %d \n",
			          recv_icmp_header->type, recv_icmp_header->code);
			continue;
		}
		if (recv_icmp_header->id != icmp_head->id) {
			log_error("some else's packet\n");
			continue;
		}
		if ((sizeof(ip_header) + sizeof(icmp_header) + DATA_SIZE) <=
		    read_length) {
			expired_ms = get_time_interval(&start, &end);
			log_debug("%ld bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
			          read_length, domain, inet_ntoa(from.sin_addr),
			          recv_icmp_header->seq / 256, ip_ttl, expired_ms);
			expired_ms_array[expired_ms_size++] = expired_ms;
		}
	}

	if (icmp) {
		free(icmp);
		icmp = NULL;
	}
	if (client_fd != -1)
		close(client_fd);

	if (expired_ms_size == 0)
		return expired_ms;
	for (i = 0; i < expired_ms_size - 1; ++i)
		expired_ms += expired_ms_array[i];
	return expired_ms / expired_ms_size;
}

void preferred_host(char *hosts, char *output_host, size_t num)
{
	char *pch;
	double expired_ms;
	double output_host_expired_ms = -1.0;

	if (!hosts) {
		log_error("preferred host's hosts is NULL!\n");
		return;
	}
	if (!output_host) {
		log_error("preferred host's output_host is NULL!\n");
		return;
	}

	for (pch = strtok(hosts, ";"); pch; pch = strtok(NULL, ";")) {
		expired_ms = ping_host_ip(pch);
		if (expired_ms < 0) {
			log_debug("ping %s error!\n", pch);
			continue;
		}
		log_debug("ping %s round-trip avg = %.2f ms\n", pch, expired_ms);

		if ((output_host_expired_ms < 0) ||
		    (expired_ms < output_host_expired_ms)) {
			output_host_expired_ms = expired_ms;
			output_host = strncpy(output_host, pch, num);
		}
	}
	log_debug("preferred host %s round-trip avg = %.2f ms\n", output_host,
	          output_host_expired_ms);
}
