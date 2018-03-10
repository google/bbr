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
 * Implementation for the epoll fd related state and logic.
 */

#include "epoll.h"

#include <stdlib.h>
#include <string.h>
#include "run.h"

void epoll_free(struct epoll *epoll)
{
	memset(epoll, 0, sizeof(*epoll));
	free(epoll);
}

void epoll_close(struct state *state, struct fd_state *fd)
{
	epoll_free(fd_to_epoll(fd));
}

/* Global info about epoll descriptors that point to epolls. */
struct fd_ops epoll_ops = {
	.type = FD_EPOLL,
	.close = epoll_close,
};

struct epoll *epoll_new(struct state *state)
{
	struct epoll *epoll = calloc(1, sizeof(struct epoll));

	epoll->fd.ops = &epoll_ops;
	state_add_fd(state, to_fd(epoll));
	return epoll;
}
