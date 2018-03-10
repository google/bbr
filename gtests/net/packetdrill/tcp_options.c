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
 * Implementation for reading and writing TCP options in their wire format.
 */

#include "tcp_options.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"

struct tcp_options *tcp_options_new(void)
{
	return calloc(1, sizeof(struct tcp_options));
}

struct tcp_option *tcp_option_new(u8 kind, u8 length)
{
	struct tcp_option *option = calloc(1, sizeof(struct tcp_option));
	option->kind = kind;
	option->length = length;
	return option;
}

int tcp_options_append(struct tcp_options *options,
			       struct tcp_option *option)
{
	if (options->length + option->length > sizeof(options->data))
		return STATUS_ERR;
	memcpy(options->data + options->length, option, option->length);
	options->length += option->length;
	assert(options->length <= sizeof(options->data));
	free(option);
	return STATUS_OK;
}

int num_sack_blocks(u8 opt_len, int *num_blocks, char **error)
{
	if (opt_len <= 2) {
		asprintf(error, "TCP SACK option too short");
		return STATUS_ERR;
	}
	const int num_bytes = opt_len - 2;
	if (num_bytes % sizeof(struct sack_block) != 0) {
		asprintf(error,
			 "TCP SACK option not a multiple of SACK block size");
		return STATUS_ERR;
	}
	*num_blocks = num_bytes / sizeof(struct sack_block);
	return STATUS_OK;
}
