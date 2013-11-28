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
 * Types and operations for IPv4 and IPv6 address prefixes.
 */

#ifndef __IP_PREFIX_H__
#define __IP_PREFIX_H__

#include "types.h"

#include "ip_address.h"

/* IPv4 or IPv6 address prefix. */
struct ip_prefix {
	struct ip_address ip;
	int prefix_len;			/* prefix length in bits */
};

static inline void ip_prefix_reset(struct ip_prefix *prefix)
{
	memset(prefix, 0, sizeof(*prefix));
}

/* Parse a human-readable IPv4 prefix and return it. Print an error
 * to stderr and exit if there is an error parsing the prefix.
 */
extern struct ip_prefix ipv4_prefix_parse(const char *prefix_string);

/* Parse a human-readable IPv6 prefix and return it. Print an error
 * to stderr and exit if there is an error parsing the prefix.
 */
extern struct ip_prefix ipv6_prefix_parse(const char *prefix_string);

/* Fill in the given prefix using the first 'prefix_len' bits of the
 * given IP address, zeroing out bits beyond the prefix length.
 */
extern struct ip_prefix ip_to_prefix(const struct ip_address *ip,
				     int prefix_len);

/* Zero the bits beyond the prefix length. */
void ip_prefix_normalize(struct ip_prefix *prefix);

/* Print a human-readable representation of the given IP prefix in the
 * given buffer, which must be at least ADDR_STR_LEN bytes long.
 * Returns a pointer to the given buffer.
 */
extern const char *ip_prefix_to_string(struct ip_prefix *prefix,
				       char *buffer);

#endif /* __IP_PREFIX_H__ */
