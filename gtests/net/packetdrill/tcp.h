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
#define TCP_TIMESTAMP            24
#define TCP_NOTSENT_LOWAT        25  /* limit unsent bytes in write queue */
#define TCP_CC_INFO              26  /* Get Congestion Control (optional) info */
#define TCP_SAVE_SYN             27  /* Record SYN headers for new connections */
#define TCP_SAVED_SYN            28  /* Get SYN headers recorded for connection */
#define TCP_REPAIR_WINDOW        29  /* Get/set window parameters */
#define TCP_FASTOPEN_CONNECT     30  /* Attempt FastOpen with connect */

#ifndef TCP_INQ
#define TCP_INQ			 36
#define TCP_CM_INQ		 TCP_INQ
#endif

#define TCP_TX_DELAY		 37

/* TODO: remove these when netinet/tcp.h has them */
#ifndef TCPI_OPT_ECN_SEEN
#define TCPI_OPT_ECN_SEEN	16 /* received at least one packet with ECT */
#endif
#ifndef TCPI_OPT_SYN_DATA
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
#endif

#endif  /* linux */

/* New TCP flags for sendto(2)/sendmsg(2). */
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN             0x20000000  /* TCP Fast Open: data in SYN */
#endif

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY		0x4000000
#endif

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
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOLEN_MD5SIG		18
#define TCPOLEN_MD5_BASE	2
#define TCPOPT_FASTOPEN		34
#define TCPOPT_EXP		254	/* Experimental */

#define TCP_MD5_DIGEST_LEN	16	/* bytes in RFC2385 TCP MD5 digest */

/* A portable TCP header definition (Linux and *BSD use different names). */
struct tcp {
	__be16	src_port;
	__be16	dst_port;
	__be32	seq;
	__be32	ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	__u16	ae:1,
		res1:3,
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
		res1:3,
		ae:1,
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
	__u8	tcpi_delivery_rate_app_limited:1;

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

	__u64	tcpi_pacing_rate;
	__u64	tcpi_max_pacing_rate;
	__u64	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	__u64	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	__u32	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
	__u32	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

	__u32	tcpi_notsent_bytes;
	__u32	tcpi_min_rtt;
	__u32	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
	__u32	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */
	__u64   tcpi_delivery_rate;

	__u64	tcpi_busy_time;      /* Time (usec) busy sending data */
	__u64	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	__u64	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	__u32	tcpi_delivered;
	__u32	tcpi_delivered_ce;

	__u64	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	__u64	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
	__u32	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
	__u32	tcpi_reord_seen;     /* reordering events seen */
};

/* netlink attributes types for SCM_TIMESTAMPING_OPT_STATS */
enum {
	_TCP_NLA_PAD,
	_TCP_NLA_BUSY,		/* Time (usec) busy sending data */
	_TCP_NLA_RWND_LIMITED,	/* Time (usec) limited by receive window */
	_TCP_NLA_SNDBUF_LIMITED,/* Time (usec) limited by send buffer */
	_TCP_NLA_DATA_SEGS_OUT,	/* Data pkts sent including retransmission */
	_TCP_NLA_TOTAL_RETRANS,	/* Data pkts retransmitted */
	_TCP_NLA_PACING_RATE,	/* Pacing rate in bytes per second */
	_TCP_NLA_DELIVERY_RATE,	/* Delivery rate in bytes per second */
	_TCP_NLA_SND_CWND,	/* Sending congestion window */
	_TCP_NLA_REORDERING,	/* Reordering metric */
	_TCP_NLA_MIN_RTT,	/* minimum RTT */
	_TCP_NLA_RECUR_RETRANS,	/* Recurring retransmits for the current pkt */
	_TCP_NLA_DELIVERY_RATE_APP_LMT, /* delivery rate application limited ? */
	_TCP_NLA_SNDQ_SIZE,      /* Data pending in send queue */
	_TCP_NLA_CA_STATE,       /* ca_state of socket */
	_TCP_NLA_SND_SSTHRESH,   /* Slow start size threshold */
	_TCP_NLA_DELIVERED,      /* Data pkts delivered incl. out-of-order */
	_TCP_NLA_DELIVERED_CE,   /* Like above but only ones w/ CE marks */
	_TCP_NLA_BYTES_SENT,	/* Data bytes sent including retransmission */
	_TCP_NLA_BYTES_RETRANS,	/* Data bytes retransmitted */
	_TCP_NLA_DSACK_DUPS,	/* DSACK blocks received */
	_TCP_NLA_REORD_SEEN,	/* reordering events seen */
	_TCP_NLA_SRTT,		/* smoothed RTT in usecs */
};

/* TCP ca_state */
enum {
	_TCP_CA_Open,
	_TCP_CA_Disorder,
	_TCP_CA_CWR,
	_TCP_CA_Recovery,
	_TCP_CA_Loss,
};

#define TCP_INFINITE_SSTHRESH	0x7fffffff

enum {
	_SK_MEMINFO_RMEM_ALLOC,
	_SK_MEMINFO_RCVBUF,
	_SK_MEMINFO_WMEM_ALLOC,
	_SK_MEMINFO_SNDBUF,
	_SK_MEMINFO_FWD_ALLOC,
	_SK_MEMINFO_WMEM_QUEUED,
	_SK_MEMINFO_OPTMEM,
	_SK_MEMINFO_BACKLOG,
	_SK_MEMINFO_DROPS,

	_SK_MEMINFO_VARS,
};

/* INET_DIAG_VEGASINFO */

struct _tcpvegas_info {
	__u32	tcpv_enabled;
	__u32	tcpv_rttcnt;
	__u32	tcpv_rtt;
	__u32	tcpv_minrtt;
};

/* INET_DIAG_DCTCPINFO */

struct _tcp_dctcp_info {
	__u16	dctcp_enabled;
	__u16	dctcp_ce_state;
	__u32	dctcp_alpha;
	__u32	dctcp_ab_ecn;
	__u32	dctcp_ab_tot;
};

/* INET_DIAG_BBRINFO */

struct _tcp_bbr_info {
	/* u64 bw: max-filtered BW (app throughput) estimate in Byte per sec: */
	__u32	bbr_bw_lo;		/* lower 32 bits of bw */
	__u32	bbr_bw_hi;		/* upper 32 bits of bw */
	__u32	bbr_min_rtt;		/* min-filtered RTT in uSec */
	__u32	bbr_pacing_gain;	/* pacing gain shifted left 8 bits */
	__u32	bbr_cwnd_gain;		/* cwnd gain shifted left 8 bits */
};

union _tcp_cc_info {
	struct _tcpvegas_info	vegas;
	struct _tcp_dctcp_info	dctcp;
	struct _tcp_bbr_info	bbr;
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
