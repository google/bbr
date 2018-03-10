/*
 * Copyright 2017 Google Inc.
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
 * Interface for tracking files in the kernel under test.
 */

#ifndef __FILE_H__
#define __FILE_H__

#include "types.h"

#include "fd_state.h"

/* The runtime state for a file */
struct file {
	/* NOTE: struct fd_state must be first field in all fd flavors. */
	struct fd_state fd;		/* info about fd for this file */
};

/* Convert to file pointer if the fd is a file, otherwise return NULL. */
static inline struct file *fd_to_file(struct fd_state *fd)
{
	if (fd && fd->ops->type == FD_FILE)
		return (struct file *)fd;
	else
		return NULL;
}

struct state;

/* Allocate and return a new file object. */
extern struct file *file_new(struct state *state);

#endif /* __FILE_H__ */
