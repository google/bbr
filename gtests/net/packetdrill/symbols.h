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
 * Definitions of strace-style symbols for our platform.
 * Allows us to map from symbolic strings to integers for system call inputs.
 */

#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

#include "types.h"

/* For tables mapping symbolic strace strings to the corresponding
 * integer values.
 */
struct int_symbol {
	s64 value;
	const char *name;
};

/* Return a pointer to a table of platform-specific string->int mappings. */
extern struct int_symbol *platform_symbols(void);

#endif /* __SYMBOLS_H__ */
