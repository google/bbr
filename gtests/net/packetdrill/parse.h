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
 * Interface for a module to parse test scripts.
 */

#ifndef __PARSER_H__
#define __PARSER_H__

#include "types.h"

#include "assert.h"
#include "config.h"
#include "script.h"

/* Copy the script contents into our single linear buffer. */
extern void copy_script(const char *script_buffer,
			struct script *script);

/* Read the script file into a single linear buffer. */
extern void read_script(const char *script_path,
			struct script *script);

/* The public, top-level call to parse a test script. It first parses the
 * internal linear script buffer and then fills in the
 * 'script' object with the internal representation of the
 * script. Uses the given 'config' object to look up configuration
 * info needed during parsing (such as whether packets are IPv4 or
 * IPv6). Passes the given 'callback_invocation' when calling back to
 * parse_and_finalize_config() after parsing all in-script
 * options.
 *
 * Returns STATUS_OK on success; on failure returns STATUS_ERR. The
 * implementation for this function is in the bison parser file
 * parser.y.
 */
extern int parse_script(struct config *config,
			struct script *script,
			struct invocation *callback_invocation);

/* Config for lexing and parsing. */
extern struct config *in_config;

#endif /* __PARSER_H__ */
