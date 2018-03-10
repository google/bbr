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
 * FreeBSD does not have an fmemopen(), so we roll our own minimalist
 * implementation here.
 */

#include "types.h"

#include <stdio.h>
#include <stdlib.h>

#include "assert.h"
#include "fmemopen.h"

#if !defined(HAVE_FMEMOPEN)

struct fmemopen_read_state {
	char *next;	/* the next byte to return */
	char *end;	/* the byte after the end of the string */
};

static int fmemopen_readfn(void *cookie, char *buf, int len)
{
	struct fmemopen_read_state *read_cookie =
		(struct fmemopen_read_state *)cookie;
	int bytes = 0;

	assert(read_cookie->next <= read_cookie->end);
	if (read_cookie->next == read_cookie->end)
		return 0;

	bytes = read_cookie->end - read_cookie->next;
	if (len < bytes)
		bytes = len;

	memcpy(buf, read_cookie->next, bytes);
	read_cookie->next += bytes;

	return bytes;
}

FILE *fmemopen(char *str, size_t size, const char *mode)
{
	FILE *f = NULL;
	struct fmemopen_read_state *read_cookie;

	assert(strcmp(mode, "r") == 0);	/* only support read for now */

	read_cookie = calloc(1, sizeof(struct fmemopen_read_state));
	read_cookie->next = str;
	read_cookie->end  = str + size;

	f = fropen(read_cookie, fmemopen_readfn);
	if (!f) {
		free(read_cookie);
		return NULL;
	}

	return f;
}

#endif /* HAVE_FMEMOPEN */
