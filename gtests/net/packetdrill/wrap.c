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
 * Wrappers for making L3-independent syscalls.
 */

#include "wrap.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "checksum.h"
#include "gre.h"
#include "logging.h"
#include "netdev.h"
#include "packet.h"
#include "packet_checksum.h"
#include "packet_to_string.h"
#include "run.h"
#include "script.h"
#include "tcp_options_iterator.h"
#include "tcp_options_to_string.h"
#include "tcp_packet.h"

int wrap_socket(enum ip_version_t ip_version, int type)
{
	int fd = -1;

	switch (ip_version) {
	case IP_VERSION_4:
		fd = socket(AF_INET, type, 0);
		if (fd < 0)
			die_perror("socket(AF_INET)");
		break;

	case IP_VERSION_4_MAPPED_6:
	case IP_VERSION_6:
		fd = socket(AF_INET6, type, 0);
		if (fd < 0)
			die_perror("socket(AF_INET6)");
		break;

	default:
		die("bad ip_version (%d) in config\n", ip_version);
		break;
	}

	return fd;
}

u16 wrap_bind_listen(int s, enum ip_version_t ip_version, u16 port)
{
	switch (ip_version) {
	case IP_VERSION_4: {
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);

		memset(&addr, 0, addrlen);
#ifndef linux
		addr.sin_len	= addrlen;
#endif
		addr.sin_family	= AF_INET;
		addr.sin_port	= htons(port);

		if (bind(s, (struct sockaddr *)&addr, addrlen) < 0)
			die_perror("bind(AF_INET)");

		memset(&addr, 0, sizeof(addr));
		if (getsockname(s, (struct sockaddr *)&addr, &addrlen) < 0)
			die_perror("getsockname(AF_INET)");
		assert(addr.sin_family == AF_INET);

		if (listen(s, 100) < 0)
			die_perror("listen(AF_INET)");

		return ntohs(addr.sin_port);
	}

	case IP_VERSION_4_MAPPED_6:
	case IP_VERSION_6: {
		struct sockaddr_in6 addr6;
		socklen_t addrlen = sizeof(addr6);

		memset(&addr6, 0, addrlen);
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);

		if (bind(s, (struct sockaddr *)&addr6, addrlen) < 0)
			die_perror("bind(AF_INET6)");

		memset(&addr6, 0, sizeof(addr6));
		if (getsockname(s, (struct sockaddr *)&addr6, &addrlen) < 0)
			die_perror("getsockname(AF_INET6)");
		assert(addr6.sin6_family == AF_INET6);

		if (listen(s, 100) < 0)
			die_perror("listen(AF_INET6)");

		return ntohs(addr6.sin6_port);
	}

	default:
		die("bad ip_version (%d) in config\n", ip_version);
		return 0;
	}
}
