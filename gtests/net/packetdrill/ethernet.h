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
 * Ethernet-related declarations.
 *
 * We cannot include the kernel's linux/if_ether.h because this tool
 * tries to compile and work for basically any Linux/BSD kernel
 * version. So we have our version of the Ethernet-related
 * declarations we require here.
 */

#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include "types.h"

/* Bytes in an Ethernet address. */
#define ETH_ALEN        6

/* Ethernet header ether_type values. */
#define	ETHERTYPE_IP		0x0800	/* IP protocol version 4 */
#define	ETHERTYPE_IPV6		0x86dd	/* IP protocol version 6 */
#define	ETHERTYPE_MPLS_UC	0x8847	/* MPLS unicast */
#define	ETHERTYPE_MPLS_MC	0x8848	/* MPLS multicast */

/* To tell a packet socket that you want traffic for all protocols. */
#define ETH_P_ALL       0x0003

/* Ethernet address. */
struct ether_addr {
	u8 ether_addr_octet[ETH_ALEN];
} __attribute__ ((__packed__));

/* Ethernet header. */
struct ether_header {
	u8  ether_dhost[ETH_ALEN];	/* destination Ethernet address */
	u8  ether_shost[ETH_ALEN];	/* source Ethernet address */
	u16 ether_type;			/* packet type ID field */
} __attribute__ ((__packed__));

static inline void ether_copy(void *dst, const void *src)
{
	memcpy(dst, src, sizeof(struct ether_addr));
}

/* Return the ether_type field for packets of the given address family. */
static inline u16 ether_type_for_family(int address_family)
{
	if (address_family == AF_INET)
		return ETHERTYPE_IP;
	else if (address_family == AF_INET6)
		return ETHERTYPE_IPV6;
	else
		assert(!"bad address family");
}

#endif /* __ETHERNET_H__ */
