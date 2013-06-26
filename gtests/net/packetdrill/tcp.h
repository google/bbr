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
 * Our own TCP header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 *
 * We cannot include the kernel's linux/tcp.h because this tool tries
 * to compile and work for basically any Linux/BSD kernel version. So
 * we declare our own version of various TCP-related definitions here.
 */

#ifndef __TCP_HEADERS_H__
#define __TCP_HEADERS_H__

#include "types.h"

#include <netinet/tcp.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define SOL_TCP IPPROTO_TCP
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#ifdef linux

/* TCP socket options used by Linux kernels under test but not in
 * standard Linux header files.
 */
#define SO_REUSEPORT             15

/* TCP socket options used by Linux kernels under test but not in
 * standard Linux header files.
 */
#define TCP_COOKIE_TRANSACTIONS  15  /* TCP Cookie Transactions */
#define TCP_THIN_LINEAR_TIMEOUTS 16  /* Use linear timeouts for thin streams */
#define TCP_THIN_DUPACK          17  /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT         18  /* How long to retry losses */
#define TCP_FASTOPEN             23  /* TCP Fast Open: data in SYN */

/* TODO: remove these when netinet/tcp.h has them */
#ifndef TCPI_OPT_ECN_SEEN
#define TCPI_OPT_ECN_SEEN	16 /* received at least one packet with ECT */
#endif
#ifndef TCPI_OPT_SYN_DATA
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
#endif

/* New TCP flags for sendto(2)/sendmsg(2). */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN             0x20000000  /* TCP Fast Open: data in SYN */
#endif

#endif  /* linux */

/* TCP option numbers and lengths. */
#define TCPOPT_EOL		0
#define TCPOPT_NOP		1
#define TCPOPT_MAXSEG		2
#define TCPOLEN_MAXSEG		4
#define TCPOPT_WINDOW		3
#define TCPOLEN_WINDOW		3
#define TCPOPT_SACK_PERMITTED	4
#define TCPOLEN_SACK_PERMITTED	2
#define TCPOPT_SACK		5
#define TCPOPT_TIMESTAMP	8
#define TCPOLEN_TIMESTAMP	10
#define TCPOPT_EXP		254	/* Experimental */

/* A portable TCP header definition (Linux and *BSD use different names). */
struct tcp {
	__be16	src_port;
	__be16	dst_port;
	__be32	seq;
	__be32	ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	__u16	res1:2,
		res2:2,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	__u16	doff:4,
		res2:2,
		res1:2,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#  else
#   error "Adjust your defines"
#  endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

#ifdef linux

/* Data returned by the TCP_INFO socket option. */
struct _tcp_info {
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale:4, tcpi_rcv_wscale:4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

#endif  /* linux */

#if defined(__FreeBSD__)

/* Data returned by the TCP_INFO socket option on FreeBSD. */
struct _tcp_info {
	u_int8_t	tcpi_state;
	u_int8_t	__tcpi_ca_state;
	u_int8_t	__tcpi_retransmits;
	u_int8_t	__tcpi_probes;
	u_int8_t	__tcpi_backoff;
	u_int8_t	tcpi_options;
	u_int8_t	tcpi_snd_wscale:4,
		tcpi_rcv_wscale:4;

	u_int32_t	tcpi_rto;
	u_int32_t	__tcpi_ato;
	u_int32_t	tcpi_snd_mss;
	u_int32_t	tcpi_rcv_mss;

	u_int32_t	__tcpi_unacked;
	u_int32_t	__tcpi_sacked;
	u_int32_t	__tcpi_lost;
	u_int32_t	__tcpi_retrans;
	u_int32_t	__tcpi_fackets;

	u_int32_t	__tcpi_last_data_sent;
	u_int32_t	__tcpi_last_ack_sent;
	u_int32_t	tcpi_last_data_recv;
	u_int32_t	__tcpi_last_ack_recv;

	u_int32_t	__tcpi_pmtu;
	u_int32_t	__tcpi_rcv_ssthresh;
	u_int32_t	tcpi_rtt;
	u_int32_t	tcpi_rttvar;
	u_int32_t	tcpi_snd_ssthresh;
	u_int32_t	tcpi_snd_cwnd;
	u_int32_t	__tcpi_advmss;
	u_int32_t	__tcpi_reordering;

	u_int32_t	__tcpi_rcv_rtt;
	u_int32_t	tcpi_rcv_space;

	/* FreeBSD extensions to tcp_info. */
	u_int32_t	tcpi_snd_wnd;
	u_int32_t	tcpi_snd_bwnd;
	u_int32_t	tcpi_snd_nxt;
	u_int32_t	tcpi_rcv_nxt;
	u_int32_t	tcpi_toe_tid;
	u_int32_t	tcpi_snd_rexmitpack;
	u_int32_t	tcpi_rcv_ooopack;
	u_int32_t	tcpi_snd_zerowin;

	/* Padding to grow without breaking ABI. */
	u_int32_t	__tcpi_pad[26];		/* Padding. */
};

#endif  /* __FreeBSD__ */


#endif /* __TCP_HEADERS_H__ */
