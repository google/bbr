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
 * Interface for module for formatting MPLS packets.
 */

#ifndef __MPLS_PACKET_H__
#define __MPLS_PACKET_H__

#include "types.h"

#include "mpls.h"
#include "packet.h"

/* Fill in the given MPLS label stack entry with the given field
 * values, validating that actual parameter value fits inside the
 * width of the field on the wire. On success, return STATUS_OK; on
 * error return STATUS_ERR and fill in a malloc-allocated error
 * message in *error.
 */
extern int new_mpls_stack_entry(s64 label, s64 traffic_class,
				bool is_stack_bottom, s64 ttl,
				struct mpls *mpls, char **error);

/* Append an MPLS header to the end of the given packet.  On success,
 * return STATUS_OK; on error return STATUS_ERR and fill in a
 * malloc-allocated error message in *error.
 */
extern int mpls_header_append(struct packet *packet,
			      struct mpls_stack *mpls_stack,
			      char **error);

/* Finalize the MPLS header by filling in all necessary fields that
 * were not filled in at parse time.
 */
extern int mpls_header_finish(struct packet *packet,
			      struct header *header, struct header *next_inner);

#endif /* __MPLS_PACKET_H__ */
