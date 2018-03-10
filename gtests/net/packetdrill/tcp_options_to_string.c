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
 * Implementation for generating human-readable representations of TCP options.
 */

#include "tcp_options_to_string.h"

#include "tcp_options_iterator.h"

/* If the MD5 digest option is in the valid range of sizes, print the MD5
 * option and digest and return STATUS_OK. Otherwise, return STATUS_ERR.
 */
static int tcp_md5_option_to_string(FILE *s, struct tcp_option *option)
{
	int digest_bytes, i;

	if (option->length < TCPOLEN_MD5_BASE ||
	    option->length > TCPOLEN_MD5SIG)
		return STATUS_ERR;

	digest_bytes = option->length - TCPOLEN_MD5_BASE;
	fprintf(s, "md5");
	if (digest_bytes > 0)
		fprintf(s, " ");
	for (i = 0; i < digest_bytes; ++i)
		fprintf(s, "%02x", option->data.md5.digest[i]);
	return STATUS_OK;
}

/* See if the given experimental option is a TFO option, and if so
 * then print the TFO option and return STATUS_OK. Otherwise, return
 * STATUS_ERR.
 */
static int tcp_fast_open_option_to_string(FILE *s, struct tcp_option *option,
					  bool exp)
{
	if (exp && ((option->length < TCPOLEN_EXP_FASTOPEN_BASE) ||
	    (ntohs(option->data.fast_open_exp.magic) != TCPOPT_FASTOPEN_MAGIC)))
		return STATUS_ERR;

	fprintf(s, exp ? "FOEXP" : "FO");
	int cookie_bytes = option->length - (exp ? TCPOLEN_EXP_FASTOPEN_BASE :
						   TCPOLEN_FASTOPEN_BASE);
	assert(cookie_bytes >= 0);
	assert(cookie_bytes <= (exp ? MAX_TCP_FAST_OPEN_EXP_COOKIE_BYTES :
				      MAX_TCP_FAST_OPEN_COOKIE_BYTES));
	if (cookie_bytes > 0)
		fprintf(s, " ");
	int i;
	for (i = 0; i < cookie_bytes; ++i)
		fprintf(s, "%02x", exp ? option->data.fast_open_exp.cookie[i] :
					 option->data.fast_open.cookie[i]);
	return STATUS_OK;
}

int tcp_options_to_string(struct packet *packet,
				  char **ascii_string, char **error)
{
	int result = STATUS_ERR;	/* return value */
	size_t size = 0;
	FILE *s = open_memstream(ascii_string, &size);  /* output string */

	int index = 0;	/* number of options seen so far */

	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;
	for (option = tcp_options_begin(packet, &iter);
	     option != NULL; option = tcp_options_next(&iter, error)) {
		if (index > 0)
			fputc(',', s);

		switch (option->kind) {
		case TCPOPT_EOL:
			fputs("eol", s);
			break;

		case TCPOPT_NOP:
			fputs("nop", s);
			break;

		case TCPOPT_MAXSEG:
			fprintf(s, "mss %u", ntohs(option->data.mss.bytes));
			break;

		case TCPOPT_WINDOW:
			fprintf(s, "wscale %u",
				option->data.window_scale.shift_count);
			break;

		case TCPOPT_SACK_PERMITTED:
			fputs("sackOK", s);
			break;

		case TCPOPT_SACK:
			fprintf(s, "sack ");
			int num_blocks = 0;
			if (num_sack_blocks(option->length,
						    &num_blocks, error))
				goto out;
			int i = 0;
			for (i = 0; i < num_blocks; ++i) {
				if (i > 0)
					fputc(' ', s);
				fprintf(s, "%u:%u",
					ntohl(option->data.sack.block[i].left),
					ntohl(option->data.sack.block[i].right));
			}
			break;

		case TCPOPT_TIMESTAMP:
			fprintf(s, "TS val %u ecr %u",
				ntohl(option->data.time_stamp.val),
				ntohl(option->data.time_stamp.ecr));
			break;

		case TCPOPT_MD5SIG:
			tcp_md5_option_to_string(s, option);
			break;

		case TCPOPT_FASTOPEN:
			tcp_fast_open_option_to_string(s, option, false);
			break;

		case TCPOPT_EXP:
			if (tcp_fast_open_option_to_string(s, option, true)) {
				asprintf(error,
					 "unknown experimental option");
				goto out;
			}
			break;

		default:
			asprintf(error, "unexpected TCP option kind: %u",
				 option->kind);
			goto out;
		}
		++index;
	}
	if (*error != NULL)  /* bogus TCP options prevented iteration */
		goto out;

	result = STATUS_OK;

out:
	fclose(s);
	return result;

}
