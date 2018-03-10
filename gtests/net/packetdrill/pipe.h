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
 * Author: weiwan@google.com (Wei Wang)
 *
 * Interface for tracking pipes in the kernel under test.
 */

#ifndef __PIPE_H__
#define __PIPE_H__

#include "types.h"

#include "fd_state.h"

/* The runtime state for a pipe */
struct pipe {
	/* NOTE: struct fd_state must be first field in all fd flavors. */
	struct fd_state fd;		/* info about fd for this pipe */
};

/* Convert to pipe pointer if the fd has type FD_PIPE,
 * otherwise return NULL.
 */
static inline struct pipe *fd_to_pipe(struct fd_state *fd)
{
	if (fd && fd->ops->type == FD_PIPE)
		return (struct pipe *)fd;
	else
		return NULL;
}

struct state;

/* Allocate and return a new pipe object. */
extern struct pipe *pipe_new(struct state *state);

#endif /* __PIPE_H__ */
