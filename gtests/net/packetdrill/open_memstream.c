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
 * FreeBSD does not have open_memstream(), so we roll our own minimalist
 * implementation here.
 */

#include "types.h"

#ifndef HAVE_OPEN_MEMSTREAM

#include "assert.h"
#include "open_memstream.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* Our internal state for the memstream. */
struct mem_stream {
	char   **buf;		/* pointer to the output buffer pointer */
	size_t  *sizeloc;	/* pointer to the output final buffer size */

	size_t	buf_size;	/* currently allocated size of buffer */
	size_t	offset;		/* current write offset */
};

#define INITIAL_BUF_SIZE    1024

/* Grow buffer, if needed, to write "write_bytes" bytes at the current
 * offset. We also have to take into account the extra '\0' that we
 * maintain just past the end. Returns 0 on success, or -1 on failure.
 */
static int mem_stream_grow(struct mem_stream *stream, int write_bytes)
{
	char *new_buf = NULL;
	size_t new_size = 0;
	size_t needed_bytes = 0;

	needed_bytes = stream->offset + write_bytes + 1;
	if (needed_bytes <= stream->buf_size)
		return 0;

	if (stream->buf_size == 0)
		new_size = INITIAL_BUF_SIZE;
	else
		new_size = 2 * stream->buf_size;

	if (new_size < needed_bytes)
		new_size = needed_bytes;

	new_buf = (char *) realloc(*stream->buf, new_size);
	if (new_buf == NULL)
		return -1;

	*stream->buf = new_buf;
	stream->buf_size = new_size;

	return 0;
}

/* Write the give data to our memstream, expanding our buffer if we
 * need to. Per the specification in the Linux man pages, "A null byte
 * is maintained at the end of the buffer. This byte is not included
 * in the size value stored at sizeloc."
 */
static int write_memstream(void *cookie, const char *buf, int write_bytes)
{
	struct mem_stream *stream = (struct mem_stream *) cookie;

	if (mem_stream_grow(stream, write_bytes) < 0)
		return -1;

	memcpy(*stream->buf + stream->offset, buf, write_bytes);
	stream->offset += write_bytes;

	*(*stream->buf + stream->offset) = '\0';

	*stream->sizeloc = stream->offset;  /* size does not include '\0' */

	return write_bytes;
}

/* Clean up */
static int close_memstream(void *cookie)
{
	struct mem_stream *stream = (struct mem_stream *) cookie;

	free(stream);

	return 0;
}

/* Create a memstream. */
FILE *open_memstream(char **ptr, size_t *sizeloc)
{
	FILE *f;
	struct mem_stream *stream;

	if (ptr == NULL || sizeloc == NULL) {
		errno = EINVAL;
		return NULL;
	}

	stream = (struct mem_stream *) calloc(1, sizeof(struct mem_stream));
	if (stream == NULL)
		return NULL;

	f = funopen(stream, NULL, write_memstream, NULL, close_memstream);
	if (f == NULL) {
		free(stream);
		return NULL;
	}

	*ptr = NULL;
	*sizeloc = 0;

	stream->buf = ptr;
	stream->sizeloc = sizeloc;

	return f;
}

#endif /* HAVE_OPEN_MEMSTREAM */
