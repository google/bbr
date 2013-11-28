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
 * Implementation for operations for IPv4 and IPv6 prefixes.
 */

#include "ip_prefix.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"

struct ip_prefix ip_to_prefix(const struct ip_address *ip, int prefix_len)
{
	int max_prefix_bits = 8 * ip_address_length(ip->address_family);
	struct ip_prefix prefix;

	if (prefix_len < 0 || prefix_len > max_prefix_bits)
		die("invalid prefix_len: %d bits", prefix_len);

	prefix.ip = *ip;
	prefix.prefix_len = prefix_len;

	return prefix;
}

void ip_prefix_normalize(struct ip_prefix *prefix)
{
	/* Find the byte and bit offset where the prefix ends. */
	int bytes = prefix->prefix_len / 8;
	int bits = prefix->prefix_len % 8;
	int max_prefix_bytes = ip_address_length(prefix->ip.address_family);

	/* Zero the bits beyond the prefix in the byte where it ends. */
	if (bits != 0) {
		int pos = 8 - bits;
		prefix->ip.ip.bytes[bytes] &= ~((1U << pos) - 1);
		++bytes;

	}
	/* Zero out the rest of the bytes in the address. */
	memset(prefix->ip.ip.bytes + bytes, 0, max_prefix_bytes - bytes);
}

/* Parse and return a prefix length (in bits) like /16 or /64 from the
 * end of a string, and die if the prefix is bigger than the given max
 * length. Use the maximum length if there is no prefix in the string.
 */
static int prefix_len_parse(const char *prefix_string, int max_len)
{
	int prefix_len = 0;
	const char *len_str = NULL;

	len_str = strstr(prefix_string, "/");
	if (len_str != NULL) {
		/* Parse prefix len in string */
		char *end = NULL;

		++len_str;		/* advance beyond '/' */
		errno = 0;
		prefix_len = strtol(len_str, &end, 10);

		if (errno != 0 || *end != '\0' ||
		    (prefix_len < 0) || (prefix_len > max_len))
			die("bad prefix length in prefix '%s'\n",
			    prefix_string);
	} else {
		/* Default prefix length is all address bits */
		prefix_len = max_len;
	}

	return prefix_len;
}

/* Copy the address part of a "<address>/<prefix>" string. */
static char *copy_prefix_address(const char *prefix_string)
{
	const char *slash = strstr(prefix_string, "/");
	int len = 0;
	if (slash != NULL)
		len = slash - prefix_string;
	else
		len = strlen(prefix_string);
	return strndup(prefix_string, len);
}

struct ip_prefix ipv4_prefix_parse(const char *prefix_string)
{
	char *ip_str = copy_prefix_address(prefix_string);
	struct ip_address ip = ipv4_parse(ip_str);
	int prefix_len = prefix_len_parse(prefix_string,
					  8 * ip_address_length(AF_INET));

	free(ip_str);

	return ip_to_prefix(&ip, prefix_len);
}

struct ip_prefix ipv6_prefix_parse(const char *prefix_string)
{
	char *ip_str = copy_prefix_address(prefix_string);
	struct ip_address ip = ipv6_parse(ip_str);
	int prefix_len = prefix_len_parse(prefix_string,
					  8 * ip_address_length(AF_INET6));

	free(ip_str);

	return ip_to_prefix(&ip, prefix_len);
}

const char *ip_prefix_to_string(struct ip_prefix *prefix, char *buffer)
{
	char ip_str[ADDR_STR_LEN];
	int bytes = 0;

	memset(ip_str, 0, sizeof(ip_str));
	ip_to_string(&prefix->ip, ip_str);

	if (strlen(ip_str) + strlen("/128") + 1 > ADDR_STR_LEN)
		die("address prefix would overflow buffer!");

	bytes = snprintf(buffer, ADDR_STR_LEN, "%s/%d",
			 ip_str, prefix->prefix_len);
	if (bytes >= ADDR_STR_LEN)
		die("address prefix overflowed buffer!");

	return buffer;
}
