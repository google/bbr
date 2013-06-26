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
 * Protocol for remote on-the-wire testing using a real NIC.
 */

#include "wire_protocol.h"

const char *wire_op_to_string(enum wire_op_t op)
{
	if (op < WIRE_INVALID)
		return "NEGATIVE_WIRE_OP!";
	if (op > WIRE_NUM_OPS)
		return "WIRE_OP_TOO_BIG!";
	switch (op) {
	case WIRE_INVALID:		return "WIRE_INVALID";
	case WIRE_COMMAND_LINE_ARGS:	return "WIRE_COMMAND_LINE_ARGS";
	case WIRE_SCRIPT_PATH:		return "WIRE_SCRIPT_PATH";
	case WIRE_SCRIPT:		return "WIRE_SCRIPT";
	case WIRE_HARDWARE_ADDR:	return "WIRE_HARDWARE_ADDR";
	case WIRE_SERVER_READY:		return "WIRE_SERVER_READY";
	case WIRE_CLIENT_STARTING:	return "WIRE_CLIENT_STARTING";
	case WIRE_PACKETS_START:	return "WIRE_PACKETS_START";
	case WIRE_PACKETS_WARN:		return "WIRE_PACKETS_WARN";
	case WIRE_PACKETS_DONE:		return "WIRE_PACKETS_DONE";
	case WIRE_NUM_OPS:		return "WIRE_NUM_OPS";
	/* We omit the default case so compiler catches missing values. */
	}
	assert(!"not reached");
	return "";
}
