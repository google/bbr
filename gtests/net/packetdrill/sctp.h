/*
 * Copyright 2013 Michael Tuexen.
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
 * Author: tuexen@fh-muenster.de (Michael Tuexen)
 *
 * Our own SCTP header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __SCTP_HEADERS_H__
#define __SCTP_HEADERS_H__

#include "types.h"

/* SCTP common header. See RFC 4960. */
struct sctp_common_header {
	__be16	src_port;
	__be16	dst_port;
	__be32	v_tag;
	__be32  crc32c;
};

#endif /* __SCTP_HEADERS_H__ */
