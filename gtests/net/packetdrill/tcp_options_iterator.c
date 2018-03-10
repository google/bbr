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
 * Implementation for module to allow iteration over TCP options in
 * wire format.
 */

#include "tcp_options_iterator.h"

#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "tcp.h"
#include "tcp_options.h"

/* Return the length (in bytes) we expect to see for the TCP option of
 * the given kind, or 0 if the option is variable-length. Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int get_expected_tcp_option_length(u8 kind, u8 *expected_length,
					  char **error)
{
	switch (kind) {
	case TCPOPT_EOL:
	case TCPOPT_NOP:
		*expected_length = 1;  /* no length byte or data */
		break;

	case TCPOPT_MAXSEG:
		*expected_length = TCPOLEN_MAXSEG;
		break;

	case TCPOPT_WINDOW:
		*expected_length = TCPOLEN_WINDOW;
		break;

	case TCPOPT_SACK_PERMITTED:
		*expected_length = TCPOLEN_SACK_PERMITTED;
		break;

	case TCPOPT_TIMESTAMP:
		*expected_length = TCPOLEN_TIMESTAMP;
		break;

	case TCPOPT_SACK:
	case TCPOPT_MD5SIG:
	case TCPOPT_FASTOPEN:
	case TCPOPT_EXP:
		*expected_length = 0;	/* variable-length option */
		break;

	default:
		asprintf(error, "unexpected TCP option kind: %u", kind);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Calculate the length of the TCP option at 'opt', in a block of TCP
 * options that ends at 'end'. If 'expected_length' is non-zero,
 * verify that length matches the expectation.  Return length of
 * option in bytes in *length. Returns STATUS_OK on success; on
 * failure returns STATUS_ERR and sets error message.
 */
static int get_tcp_option_length(const u8 *option, const u8 *end,
				 u8 expected_length, u8 *length, char **error)
{
	int result = STATUS_ERR;
	if (option + 1 >= end) {
		asprintf(error, "TCP option length byte extends too far");
		goto out;
	}
	*length = *(option + 1);
	if (*length < 2) {
		asprintf(error, "TCP option with length byte is too short");
		goto out;
	}

	if (option + (*length) > end) {
		asprintf(error, "TCP option data extends too far");
		goto out;
	}
	if (expected_length && (*length != expected_length)) {
		asprintf(error,
			 "bad TCP option length: was %u but expected %u",
			 *length, expected_length);
		goto out;
	}
	result = STATUS_OK;

out:
	return result;
}

static struct tcp_option *get_current_option(
	struct tcp_options_iterator *iter)
{
	assert(iter->current_option <= iter->options_end);
	if (iter->current_option >= iter->options_end)
		iter->current_option = NULL;
	return (struct tcp_option *)iter->current_option;
}

struct tcp_option *tcp_options_begin(
	struct packet *packet,
	struct tcp_options_iterator *iter)
{
	memset(iter, 0, sizeof(*iter));
	iter->current_option	= packet_tcp_options(packet);
	iter->options_end	= packet_payload(packet);
	return get_current_option(iter);
}

struct tcp_option *tcp_options_next(
	struct tcp_options_iterator *iter, char **error)
{
	/* Ensure we haven't hit the end. */
	assert(iter->current_option < iter->options_end);
	assert(iter->current_option != NULL);

	/* Find the length we expect for this kind of option. */
	u8 length = 0;			/* length of this option in bytes */
	u8 expected_length = 0;		/* expected length for this kind */
	struct tcp_option *option = (struct tcp_option *)iter->current_option;
	if (get_expected_tcp_option_length(
		    option->kind, &expected_length, error))
		goto out;

	/* Calculate and validate the actual length of the option. */
	if (expected_length == 1) {
		/* 1 byte length means no length byte, so real length is 1. */
		length = 1;
	} else {
		/* Parse and validate length byte. */
		if (get_tcp_option_length(iter->current_option,
					  iter->options_end,
					  expected_length, &length, error))
			goto out;
	}

	/* Advance to the next TCP option. */
	assert(length > 0);
	iter->current_option += length;
	assert(iter->current_option <= iter->options_end);
	return get_current_option(iter);

out:
	return NULL;

}
