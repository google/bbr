/*
 * Copyright 2018 Google Inc.
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
 * Our own header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 *
 * We cannot just include the kernel's headers because this tool tries
 * to compile and work for basically any Linux/BSD kernel version. So
 * we declare our own version of various network-related definitions here.
 */

#ifndef __UAPI_LINUX_H__
#define __UAPI_LINUX_H__

#include "types.h"

#include <netinet/tcp.h>

#ifdef linux

/* From Linux include/uapi/asm-generic/socket.h: */

#define SO_MAX_PACING_RATE      47

#define SO_BPF_EXTENSIONS	48

#define SO_INCOMING_CPU		49

#define SO_ATTACH_BPF		50
#define SO_DETACH_BPF		SO_DETACH_FILTER

#define SO_ATTACH_REUSEPORT_CBPF	51
#define SO_ATTACH_REUSEPORT_EBPF	52

#define SO_CNX_ADVICE		53

#define SCM_TIMESTAMPING_OPT_STATS	54

#define SO_MEMINFO		55

#define SO_INCOMING_NAPI_ID	56

#define SO_COOKIE		57

#define SCM_TIMESTAMPING_PKTINFO	58

#define SO_PEERGROUPS		59

#define SO_ZEROCOPY		60

/* From Linux include/uapi/linux/errqueue.h: */

struct sock_extended_err {
	__u32	ee_errno;
	__u8	ee_origin;
	__u8	ee_type;
	__u8	ee_code;
	__u8	ee_pad;
	__u32   ee_info;
	__u32   ee_data;
};

#define SO_EE_ORIGIN_NONE	0
#define SO_EE_ORIGIN_LOCAL	1
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3
#define SO_EE_ORIGIN_TXSTATUS	4
#define SO_EE_ORIGIN_ZEROCOPY	5
#define SO_EE_ORIGIN_TIMESTAMPING SO_EE_ORIGIN_TXSTATUS

#define SO_EE_CODE_ZEROCOPY_COPIED	1

struct scm_timestamping {
	struct timespec ts[3];
};

enum {
	SCM_TSTAMP_SND,		/* driver passed skb to NIC, or HW */
	SCM_TSTAMP_SCHED,	/* data entered the packet scheduler */
	SCM_TSTAMP_ACK,		/* data acknowledged by peer */
};

/* From Linux include/uapi/linux/net_tstamp.h: */

/* SO_TIMESTAMPING gets an integer bit field comprised of these values */
enum {
	SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
	SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
	SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
	SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
	SOF_TIMESTAMPING_SOFTWARE = (1<<4),
	SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
	SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
	SOF_TIMESTAMPING_OPT_ID = (1<<7),
	SOF_TIMESTAMPING_TX_SCHED = (1<<8),
	SOF_TIMESTAMPING_TX_ACK = (1<<9),
	SOF_TIMESTAMPING_OPT_CMSG = (1<<10),
	SOF_TIMESTAMPING_OPT_TSONLY = (1<<11),
	SOF_TIMESTAMPING_OPT_STATS = (1<<12),
	SOF_TIMESTAMPING_OPT_PKTINFO = (1<<13),
	SOF_TIMESTAMPING_OPT_TX_SWHW = (1<<14),

	SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_TX_SWHW,

	SOF_TIMESTAMPING_MASK = (SOF_TIMESTAMPING_LAST - 1) |
				 SOF_TIMESTAMPING_LAST
};

/* From Linux include/uapi/linux/eventpoll.h: */

#include <sys/epoll.h>

/* Set exclusive wakeup mode for the target file descriptor */
#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE  (1U << 28)
#endif

/* From Linux include/uapi/linux/capability.h: */

#include <linux/capability.h>

#ifndef CAP_CHOWN
#define CAP_CHOWN		0
#endif

#ifndef CAP_DAC_OVERRIDE
#define CAP_DAC_OVERRIDE	1
#endif

#ifndef CAP_DAC_READ_SEARCH
#define CAP_DAC_READ_SEARCH	2
#endif

#ifndef CAP_FOWNER
#define CAP_FOWNER		3
#endif

#ifndef CAP_FSETID
#define CAP_FSETID		4
#endif

#ifndef CAP_KILL
#define CAP_KILL		5
#endif

#ifndef CAP_SETGID
#define CAP_SETGID		6
#endif

#ifndef CAP_SETUID
#define CAP_SETUID		7
#endif

#ifndef CAP_SETPCAP
#define CAP_SETPCAP		8
#endif

#ifndef CAP_LINUX_IMMUTABLE
#define CAP_LINUX_IMMUTABLE	9
#endif

#ifndef CAP_NET_BIND_SERVICE
#define CAP_NET_BIND_SERVICE	10
#endif

#ifndef CAP_NET_BROADCAST
#define CAP_NET_BROADCAST	11
#endif

#ifndef CAP_NET_ADMIN
#define CAP_NET_ADMIN		12
#endif

#ifndef CAP_NET_RAW
#define CAP_NET_RAW		13
#endif

#ifndef CAP_IPC_LOCK
#define CAP_IPC_LOCK		14
#endif

#ifndef CAP_IPC_OWNER
#define CAP_IPC_OWNER		15
#endif

#ifndef CAP_SYS_MODULE
#define CAP_SYS_MODULE		16
#endif

#ifndef CAP_SYS_RAWIO
#define CAP_SYS_RAWIO		17
#endif

#ifndef CAP_SYS_CHROOT
#define CAP_SYS_CHROOT		18
#endif

#ifndef CAP_SYS_PTRACE
#define CAP_SYS_PTRACE		19
#endif

#ifndef CAP_SYS_PACCT
#define CAP_SYS_PACCT		20
#endif

#ifndef CAP_SYS_ADMIN
#define CAP_SYS_ADMIN		21
#endif

#ifndef CAP_SYS_BOOT
#define CAP_SYS_BOOT		22
#endif

#ifndef CAP_SYS_NICE
#define CAP_SYS_NICE		23
#endif

#ifndef CAP_SYS_RESOURCE
#define CAP_SYS_RESOURCE	24
#endif

#ifndef CAP_SYS_TIME
#define CAP_SYS_TIME		25
#endif

#ifndef CAP_SYS_TTY_CONFIG
#define CAP_SYS_TTY_CONFIG	26
#endif

#ifndef CAP_MKNOD
#define CAP_MKNOD		27
#endif

#ifndef CAP_LEASE
#define CAP_LEASE		28
#endif

#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE		29
#endif

#ifndef CAP_AUDIT_CONTROL
#define CAP_AUDIT_CONTROL	30
#endif

#ifndef CAP_SETFCAP
#define CAP_SETFCAP		31
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE	32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN		33
#endif

#ifndef CAP_SYSLOG
#define CAP_SYSLOG		34
#endif

#ifndef CAP_WAKE_ALARM
#define CAP_WAKE_ALARM		35
#endif

#ifndef CAP_BLOCK_SUSPEND
#define CAP_BLOCK_SUSPEND	36
#endif

#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ		37
#endif

#endif  /* linux */


#endif /* __UAPI_LINUX_H__ */
