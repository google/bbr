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
 * Definitions for types and utilities used widely throughout the tool.
 */

#include "types.h"
#include <ctype.h>
#include <stdlib.h>

struct in_addr in4addr_any    = { .s_addr = INADDR_ANY };

void hex_dump(const u8 *buffer, int bytes, char **hex)
{
	size_t size = 0;
	FILE *s = open_memstream(hex, &size);  /* output string */
	int i;
	for (i = 0; i < bytes; ++i) {
		if (i % 16 == 0) {
			if (i > 0)
				fprintf(s, "\n");
			fprintf(s, "0x%04x: ", i);      /* show buffer offset */
		}
		fprintf(s, "%02x ", buffer[i]);
	}
	fprintf(s, "\n");
	fclose(s);
}

char *to_printable_string(const char *in, int in_len)
{
	int out_len, i, j;
	char *out;

	out_len = in_len * 4;	/* escape code is 4B */
	out_len += 1;		/* terminating null */
	out = malloc(out_len);

	for (i = 0, j = 0; i < in_len; i++) {
		if (isprint(in[i]) ||
		    (i == in_len - 1 && in[i] == 0) /* terminating null */)
			out[j++] = in[i];
		else
			j += sprintf(out + j, "\\x%02hhx", in[i]);
	}
	out[j] = 0;
	return out;
}
