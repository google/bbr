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
 * Implementation for pipe related state and logic.
 */

#include "pipe.h"

#include <stdlib.h>
#include <string.h>
#include "run.h"

void pipe_free(struct pipe *pipe)
{
	memset(pipe, 0, sizeof(*pipe));
	free(pipe);
}

void pipe_close(struct state *state, struct fd_state *fd)
{
	pipe_free(fd_to_pipe(fd));
}

/* Global info about pipe descriptors that point to pipes. */
struct fd_ops pipe_ops = {
	.type = FD_PIPE,
	.close = pipe_close,
};

struct pipe *pipe_new(struct state *state)
{
	struct pipe *pipe = calloc(1, sizeof(struct pipe));

	pipe->fd.ops = &pipe_ops;
	state_add_fd(state, to_fd(pipe));
	return pipe;
}
