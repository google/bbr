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
 * Interface for module for formatting GRE packets.
 */

#ifndef __GRE_PACKET_H__
#define __GRE_PACKET_H__

#include "types.h"

#include "packet.h"

/* Append a GRE header to the end of the given packet.  On success,
 * return STATUS_OK; on error return STATUS_ERR and fill in a
 * malloc-allocated error message in *error.
 */
extern int gre_header_append(struct packet *packet,
			     const struct gre *gre, char **error);

/* Finalize the GRE header by filling in all necessary fields that
 * were not filled in at parse time.
 */
extern int gre_header_finish(struct packet *packet,
			     struct header *header, struct header *next_inner);

#endif /* __GRE_PACKET_H__ */
