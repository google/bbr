/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * API to read and write raw packets implemented using pcap.
 */

#include "packet_socket.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef USE_LIBPCAP

#if defined(__FreeBSD__)
#include <pcap/pcap.h>
#elif defined(__OpenBSD__) || defined(__NetBSD__)
#include <pcap.h>
#endif

#include "assert.h"
#include "ethernet.h"
#include "logging.h"

struct packet_socket {
	char *name;	/* malloc-allocated copy of interface name */

	pcap_t *pcap;	/* handle for sending, sniffing timestamped packets */
	char pcap_error[PCAP_ERRBUF_SIZE];	/* for libpcap errors */
	int pcap_offset;  /* offset of packet data in pcap buffer */
};

#if defined(__OpenBSD__)
#include <net/bpf.h>
/* Convert a bpf_timeval to microseconds. */
static inline s64 bpf_timeval_to_usecs(const struct bpf_timeval *tv)
{
	return ((s64)tv->tv_sec) * 1000000LL + (s64)tv->tv_usec;
}
#endif /* defined(__OpenBSD__) */

/* Call pcap_perror() and then exit with a failure status code. */
extern void die_pcap_perror(pcap_t *pcap, char *message)
{
	pcap_perror(pcap, message);

	exit(EXIT_FAILURE);
}

static void packet_socket_setup(struct packet_socket *psock)
{
	int data_link = -1, bpf_fd = -1, val = -1;

	DEBUGP("calling pcap_create() with %s\n", psock->name);
	psock->pcap = pcap_create(psock->name, psock->pcap_error);
	if (psock->pcap == NULL)
		die_pcap_perror(psock->pcap, "pcap_create");

	if (pcap_set_snaplen(psock->pcap, PACKET_READ_BYTES) != 0)
		die_pcap_perror(psock->pcap, "pcap_set_snaplen");

	if (pcap_activate(psock->pcap) != 0)
		die_pcap_perror(psock->pcap,
				"pcap_activate "
				"(OpenBSD: another process (tcpdump?) "
				"using bpf0?)");

	bpf_fd = pcap_get_selectable_fd(psock->pcap);
	if (bpf_fd < 0)
		die_pcap_perror(psock->pcap, "pcap_get_selectable_fd");

	/* By default libpcap with BPF waits until a read buffer fills
	 * up before returning any packets. We use BIOCIMMEDIATE to
	 * force the BPF device to return the first packet
	 * immediately.
	 */
	val = 1;
	if (ioctl(bpf_fd, BIOCIMMEDIATE, &val) < 0)
		die_perror("ioctl BIOCIMMEDIATE on bpf fd");

	/* Find data link type. */
	data_link = pcap_datalink(psock->pcap);
	DEBUGP("data_link: %d\n", data_link);

	/* Based on the data_link type, calculate the offset of the
	 * packet data in the buffer.
	 */
	switch (data_link) {
	case DLT_EN10MB:
		psock->pcap_offset = 0;
		break;
	case DLT_LOOP:
	case DLT_NULL:
		psock->pcap_offset = 4;
		break;
	case DLT_SLIP:
	case DLT_RAW:
		psock->pcap_offset = 0;
		break;
	default:
		die("Unknown data_link type %d\n", data_link);
		break;
	}
}

/* Add a filter so we only sniff packets we want. */
void packet_socket_set_filter(struct packet_socket *psock,
			      const struct ether_addr *client_ether_addr,
			      const struct ip_address *client_live_ip)
{
	const u8 *client_ether = client_ether_addr->ether_addr_octet;
	struct bpf_program bpf_code;
	char *filter_str = NULL;
	char client_live_ip_string[ADDR_STR_LEN];

	ip_to_string(client_live_ip, client_live_ip_string);

	asprintf(&filter_str,
		 "ether src %02x:%02x:%02x:%02x:%02x:%02x and %s src %s",
		 client_ether[0],
		 client_ether[1],
		 client_ether[2],
		 client_ether[3],
		 client_ether[4],
		 client_ether[5],
		 client_live_ip->address_family == AF_INET6 ? "ip6" : "ip",
		 client_live_ip_string);

	DEBUGP("setting BPF filter: %s\n", filter_str);

	if (pcap_compile(psock->pcap, &bpf_code, filter_str, 1, 0) != 0)
		die_pcap_perror(psock->pcap, "pcap_compile");

	if (pcap_setfilter(psock->pcap, &bpf_code) != 0)
		die_pcap_perror(psock->pcap, "pcap_setfilter");

	pcap_freecode(&bpf_code);
	free(filter_str);
}

struct packet_socket *packet_socket_new(const char *device_name)
{
	struct packet_socket *psock = calloc(1, sizeof(struct packet_socket));

	psock->name = strdup(device_name);

	packet_socket_setup(psock);

	return psock;
}

void packet_socket_free(struct packet_socket *psock)
{
	if (psock->name != NULL)
		free(psock->name);

	pcap_close(psock->pcap);

	memset(psock, 0, sizeof(*psock));	/* paranoia to catch bugs*/
	free(psock);
}

int packet_socket_writev(struct packet_socket *psock,
			 const struct iovec *iov, int iovcnt)
{
	/* Copy the ethernet header and IP datagram into a single buffer,
	 * since that's all the pcap API supports. TODO: optimize this.
	 */

	u8 *buf = NULL, *p = NULL;
	int len = 0, i = 0;

	/* Calculate how much space we need. */
	for (i = 0; i < iovcnt; ++i)
		len += iov[i].iov_len;

	buf = malloc(len);

	/* Copy into the linear buffer. */
	p = buf;
	for (i = 0; i < iovcnt; ++i) {
		memcpy(p, iov[i].iov_base, iov[i].iov_len);
		p += iov[i].iov_len;
	}

	DEBUGP("calling pcap_inject with %d bytes\n", len);

	if (pcap_inject(psock->pcap, buf, len) != len)
		die_pcap_perror(psock->pcap, "pcap_inject");

	free(buf);
	return STATUS_OK;
}

int packet_socket_receive(struct packet_socket *psock,
			  enum direction_t direction,
			  struct packet *packet, int *in_bytes)
{
	int status = 0;
	struct pcap_pkthdr *pkt_header = NULL;
	const u8 *pkt_data = NULL;

	DEBUGP("calling pcap_next_ex()\n");

	/* Something about the way we're doing BIOCIMMEDIATE
	 * causes libpcap to return 0 if there's no packet
	 * yet, which forces us to spin in this loop until
	 * there's a packet available.  If, on the other hand,
	 * we hack libpcap itself to enable its internal
	 * BIOCIMMEDIATE code path that it currently only uses
	 * for AIX, then we don't have to spin
	 * here. TODO(ncardwell): fix this.
	 */
	while (1) {
		status = pcap_next_ex(psock->pcap, &pkt_header,
				      &pkt_data);
		if (status == 1)
			break;		/* got a packet */
		else if (status == 0)
			return STATUS_ERR;	/* no packet yet */
		else if (status == -1)
			die_pcap_perror(psock->pcap, "pcap_next_ex");
		else if (status == -2)
			die("pcap_next_ex: EOF in save file?!\n");
		else
			die("pcap_next_ex: status: %d\n", status);
	}

	DEBUGP("time: %u . %u\n",
	       (u32)pkt_header->ts.tv_sec,
	       (u32)pkt_header->ts.tv_usec);

#if defined(__FreeBSD__) || defined(__NetBSD__)
	packet->time_usecs = timeval_to_usecs(&pkt_header->ts);
#elif defined(__OpenBSD__)
	packet->time_usecs = bpf_timeval_to_usecs(&pkt_header->ts);
#else
	packet->time_usecs = implement_me("implement me for your platform");
#endif  /* defined(__OpenBSD__) */

	DEBUGP("time_usecs= %llu\n", packet->time_usecs);

	DEBUGP("pcap_next_ex: caplen:%u len:%u offset:%d\n",
	       pkt_header->caplen, pkt_header->len, psock->pcap_offset);

	if (DEBUG_LOGGING) {
		/* Dump a hex dump of packet sniffed by pcap. */
		char *hex = NULL;
		hex_dump(pkt_data, pkt_header->caplen, &hex);
		DEBUGP("pkt from pcap:\n%s\n", hex);
		free(hex);
	}

	if (pkt_header->caplen != pkt_header->len) {
		die("libpcap unable to capture full packet: "
		    "caplen %u != len %u\n",
		    pkt_header->caplen, pkt_header->len);
	}
	assert(pkt_header->len <= packet->buffer_bytes);

	assert(pkt_header->len > psock->pcap_offset);
	*in_bytes = pkt_header->len - psock->pcap_offset;
	memcpy(packet->buffer, pkt_data + psock->pcap_offset, *in_bytes);

	return STATUS_OK;
}

#endif  /* USE_LIBPCAP */
