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
 * Interface for generating human-readable representations of TCP options.
 */

#ifndef __TCP_OPTIONS_TO_STRING_H__
#define __TCP_OPTIONS_TO_STRING_H__

#include "types.h"

#include "packet.h"
#include "tcp_options.h"

/* Returns in *ascii_string a human-readable representation of the TCP
 * options for 'packet'. Returns STATUS_OK on success; on failure
 * returns STATUS_ERR and sets error message.
 */
extern int tcp_options_to_string(struct packet *packet,
				 char **ascii_string, char **error);

#endif /* __TCP_OPTIONS_TO_STRING_H__ */
