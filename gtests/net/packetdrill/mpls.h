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
 * Our own MPLS header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 *
 * We cannot include the kernel's MPLS .h files because this tool tries
 * to compile and work for basically any Linux/BSD kernel version. So
 * we declare our own version of various MPLS-related definitions here.
 */

#ifndef __MPLS_HEADERS_H__
#define __MPLS_HEADERS_H__

#include <stdlib.h>
#include "types.h"

/* On-the-wire MPLS "label stack entry", per RFC 3032 and RFC 5462. */
struct mpls {
	__be32 entry;
};

/* Bit-shifting macros to access MPLS fields (the label straddles byte
 * boundaries so there's no simple/clean way to use bit fields).
 */
#define MPLS_LABEL_MASK		0xfffff000	/* label */
#define MPLS_LABEL_SHIFT	12
#define MPLS_TC_MASK		0x00000e00	/* traffic class */
#define MPLS_TC_SHIFT		9
#define MPLS_STACK_MASK		0x00000100	/* is stack bottom? */
#define MPLS_STACK_SHIFT	8
#define MPLS_TTL_MASK		0x000000ff	/* time to live */
#define MPLS_TTL_SHIFT		0

/* Return the label from an MPLS label stack entry. */
static inline u32 mpls_entry_label(const struct mpls *mpls)
{
	return (ntohl(mpls->entry) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
}

/* Return the traffic class from an MPLS label stack entry. */
static inline u8 mpls_entry_tc(const struct mpls *mpls)
{
	return (ntohl(mpls->entry) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;
}

/* Return the "is stack bottom?" bit from an MPLS label stack entry. */
static inline bool mpls_entry_stack(const struct mpls *mpls)
{
	return (ntohl(mpls->entry) & MPLS_STACK_MASK) >> MPLS_STACK_SHIFT;
}

/* Return the TTL from an MPLS label stack entry. */
static inline u8 mpls_entry_ttl(const struct mpls *mpls)
{
	return (ntohl(mpls->entry) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
}

/* Fill in an MPLS label stack entry with the given field values. */
static inline void mpls_entry_set(u32 label, u8 traffic_class,
				  bool is_stack_bottom, u8 ttl,
				  struct mpls *mpls)
{
	mpls->entry = htonl((label		<< MPLS_LABEL_SHIFT)	|
			    (traffic_class	<< MPLS_TC_SHIFT)	|
			    (is_stack_bottom	<< MPLS_STACK_SHIFT)	|
			    (ttl		<< MPLS_TTL_SHIFT));
}

/* Parse-time representation of an MPLS label stack entry. */
#define MPLS_STACK_MAX_ENTRIES	6	/* maximum number of label entries */
struct mpls_stack {
	struct mpls entries[MPLS_STACK_MAX_ENTRIES];
	int length;		/* number of MPLS label stack entries */
};

/* Allocate and initialize a new MPLS label stack as empty. */
static inline struct mpls_stack *mpls_stack_new(void)
{
	return calloc(1, sizeof(struct mpls_stack));
}

/* Appends the given MPLS label stack entry to the given stack. Returns
 * STATUS_OK on success, or STATUS_ERR on error (if the label stack is full).
 */
static inline int mpls_stack_append(struct mpls_stack *stack, struct mpls mpls)
{
	if (stack->length >= ARRAY_SIZE(stack->entries))
		return STATUS_ERR;
	stack->entries[stack->length++] = mpls;
	return STATUS_OK;
}

#endif /* __MPLS_HEADERS_H__ */
