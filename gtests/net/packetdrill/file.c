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
 * Implementation for the file-related state and logic.
 */

#include "file.h"

#include <stdlib.h>
#include <string.h>
#include "run.h"

void file_free(struct file *file)
{
	memset(file, 0, sizeof(*file));  /* paranoia to help catch bugs */
	free(file);
}

void file_close(struct state *state, struct fd_state *fd)
{
	file_free(fd_to_file(fd));
}

/* Global info about file descriptors that point to files. */
struct fd_ops file_ops = {
	.type = FD_FILE,
	.close = file_close,
};

struct file *file_new(struct state *state)
{
	struct file *file = calloc(1, sizeof(struct file));

	file->fd.ops = &file_ops;
	state_add_fd(state, to_fd(file));
	return file;
}
