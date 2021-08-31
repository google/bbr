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
 * Interfaces for reading and writing TCP options in their wire format.
 */

#ifndef __TCP_OPTIONS_H__
#define __TCP_OPTIONS_H__

#include "types.h"

#include "packet.h"

#define MAX_TCP_OPTION_BYTES (MAX_TCP_HEADER_BYTES - (int)sizeof(struct tcp))

/* TCP Fast Open uses the following magic number to be after the
 * option value for sharing TCP experimental options.
 *
 * For a description of experimental options, see:
 *   http://tools.ietf.org/html/draft-ietf-tcpm-experimental-options-00
 */

/*
 * For a description of TFO, see:
 *   http://tools.ietf.org/html/draft-cheng-tcpm-fastopen-02
 */
#define TCPOPT_FASTOPEN_MAGIC	0xF989

/* Experimental options must have:
 * 1-byte kind, 1-byte length, and 2-byte magic: */
#define TCPOLEN_EXP_FASTOPEN_BASE 4	/* smallest legal TFO option size */

/* RFC7413 TFO option must have: 1-byte kind, 1-byte length: */
#define TCPOLEN_FASTOPEN_BASE 2		/* smallest legal TFO option size */

/* The TFO option base prefix leaves this amount of space: */
#define MAX_TCP_FAST_OPEN_COOKIE_BYTES				\
	(MAX_TCP_OPTION_BYTES - TCPOLEN_FASTOPEN_BASE)
#define MAX_TCP_FAST_OPEN_EXP_COOKIE_BYTES			\
	(MAX_TCP_OPTION_BYTES - TCPOLEN_EXP_FASTOPEN_BASE)

/* For a description of Accurate ECN, see:
 *   https://datatracker.ietf.org/doc/html/draft-ietf-tcpm-accurate-ecn
 */
#define MAX_TCP_ACCECN_FIELDS	3

/* Represents a list of TCP options in their wire format. */
struct tcp_options {
	u8 data[MAX_TCP_OPTION_BYTES];	/* The options data, in wire format */
	u8 length;		/* The length, in bytes, of the data */
};

/* Specification of a TCP SACK block (RFC 2018) */
struct sack_block {
	u32 left;   /* left edge: 1st sequence number in block */
	u32 right;  /* right edge: 1st sequence number just past block */
};

struct accecn_field {
	u32 bytes : 24;
} __attribute__ ((packed));

/* Represents a single TCP option in its wire format. Note that for
 * EOL and NOP options the length and data field are not included in
 * the on-the-wire data. For other options, the length field describes
 * the number of bytes of the struct that go on the wire. */
struct tcp_option {
	u8 kind;
	u8 length;  /* bytes on the wire; includes kind and length byte */
	union {
		struct {
			u16 bytes;	/* in network order */
		} mss;
		struct {
			u32 val;	/* in network order */
			u32 ecr;	/* in network order */
		} time_stamp;
		struct {
			u8 shift_count;
		} window_scale;
		struct {
			/* actual number of blocks will be 1..4 */
			struct sack_block block[4];
		} sack;
		struct {
			u8 digest[TCP_MD5_DIGEST_LEN];
		} md5; /* TCP MD5 Signature Option: RFC 2385 */
		struct {
			/* The fast open chookie should be 4-16 bytes
			 * of cookie, multiple of 2 bytes, but we
			 * allow for larger sizes, so we can test what
			 * stacks do with illegal options.
			 */
			u8 cookie[MAX_TCP_FAST_OPEN_COOKIE_BYTES];
		} fast_open;
		struct {
			u16 magic;	/* must be TCPOPT_FASTOPEN_MAGIC */
			u8 cookie[MAX_TCP_FAST_OPEN_EXP_COOKIE_BYTES];
		} fast_open_exp;
		struct __attribute__ ((packed)) {
			struct accecn_field field[3];
		} accecn;
	} data;
} __packed;

/* Allocate a new options list. */
extern struct tcp_options *tcp_options_new(void);

/* Allocate a new option and initialize its kind and length fields. */
extern struct tcp_option *tcp_option_new(u8 kind, u8 length);

/* Appends the given option to the given list of options. Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
extern int tcp_options_append(struct tcp_options *options,
			      struct tcp_option *option);

/* Calculate the number of SACK blocks in a SACK option of the given
 * length and store it in *num_blocks. Returns STATUS_OK on success;
 * on failure returns STATUS_ERR and sets error message.
 */
extern int num_sack_blocks(u8 opt_len, int *num_blocks, char **error);

struct tcp_accecn_fields {
	int first;
	int present;
	u32 field[1+MAX_TCP_ACCECN_FIELDS];	/* Non-ECT (unused) included */
};

#endif /* __TCP_OPTIONS_H__ */
