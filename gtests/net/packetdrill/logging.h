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
 * Logging and output functions.
 */

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include "types.h"

/* Enable this to get debug logging. */
#define DEBUG_LOGGING 0

/* Use a gcc variadic macro to conditionally compile debug printing. */
#define DEBUGP(...)				\
	if (DEBUG_LOGGING) {			\
		fprintf(stdout,  __VA_ARGS__);	\
		fflush(stdout);			\
	}

/* Log the message to stderr and then exit with a failure status code. */
extern void die(char *format, ...);

/* Call perror() with message and then exit with a failure status code. */
extern void die_perror(char *message);

#endif /* __LOGGING_H__ */
