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
/* From: http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.h */

/*---------------------------------------------------------------------------
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_

#include "types.h"

#include <stdint.h>

/*---------------------------------------------------------------------------*/

void MurmurHash3_x86_32(const void *key, int len, u32 seed, void *out);

void MurmurHash3_x86_128(const void *key, int len, u32 seed, void *out);

void MurmurHash3_x64_128(const void *key, int len, u32 seed, void *out);

/*---------------------------------------------------------------------------*/

#endif  /* _MURMURHASH3_H_ */
