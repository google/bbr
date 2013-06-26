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
 * Interface and data structure declarations for a simple hash map
 * mapping u32 keys to u32 values.
 */

#ifndef __HASH_MAP_H__
#define __HASH_MAP_H__

#include "types.h"

/* Node for hash table buckets; maps u32 key to u32 value. */
struct hash_node {
	u32 key;
	u32 value;
	struct hash_node *next;
};

/* Hash map mapping u32 to u32. */
struct hash_map {
	size_t num_keys;		/* number of keys */
	size_t num_buckets;		/* number of buckets (a power of 2) */
	size_t bucket_mask;		/* bit mask to find bucket number */
	struct hash_node **buckets;	/* array of hash buckets */
};

extern struct hash_map *hash_map_new(size_t num_keys);

extern void hash_map_free(struct hash_map *map);

extern void hash_map_set(struct hash_map *map,
			 u32 key, u32 value);

extern bool hash_map_get(const struct hash_map *map,
			 u32 key, u32 *value);

#endif /* __HASH_MAP_H__ */
