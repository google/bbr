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
 * Interface for a module to allow iteration over TCP options in wire format.
 */

#ifndef __TCP_OPTIONS_ITERATOR_H__
#define __TCP_OPTIONS_ITERATOR_H__

#include "types.h"

#include "packet.h"
#include "tcp_options.h"

/* Internal state for an iterator for TCP options in wire format. */
struct tcp_options_iterator {
	u8 *current_option;
	u8 *options_end;
};

/* Initialize the iterator to iterate over the TCP options in the
 * given packet. Return a pointer to the first option in the packet,
 * or NULL if there are none.
 */
extern struct tcp_option *tcp_options_begin(
	struct packet *packet,
	struct tcp_options_iterator *iter);

/* Return a pointer to the next option in the packet, or NULL if there
 * are no more. On failure returns NULL and sets error message.
 */
extern struct tcp_option *tcp_options_next(
	struct tcp_options_iterator *iter, char **error);

#endif /* __TCP_OPTIONS_ITERATOR_H__ */
