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
 * Implementation for a simple hash map mapping u32 keys to u32 values.
 */

#include "hash_map.h"

#include <stdlib.h>
#include <string.h>
#include "hash.h"

static const size_t MAX_BUCKETS = 1ULL << 30;	/* max 1B buckets */

/* Hash a key. We use the fast, public-domain MurmurHash3.*/
static inline size_t hash_key(u32 key)
{
	u32 hash;
	MurmurHash3_x86_32(&key, sizeof(key), 0, &hash);
	return hash;
}

/* Find the bucket number for a key. */
static inline size_t hash_bucket_num(const struct hash_map *map, u32 key)
{
	size_t bucket_num = hash_key(key) & map->bucket_mask;
	return bucket_num;
}

/* Try to find the smallest bucket count that is a power of 2 and is
 * greater than the given number of keys.
 */
static inline size_t hash_map_pick_bucket_count(size_t num_keys)
{
	size_t buckets = 1;
	while ((buckets < num_keys) && (buckets < MAX_BUCKETS))
		buckets <<= 1;
	return buckets;
}

struct hash_map *hash_map_new(size_t num_keys)
{
	struct hash_map *map = calloc(1, sizeof(struct hash_map));
	map->num_buckets = hash_map_pick_bucket_count(num_keys);
	map->bucket_mask = map->num_buckets - 1;
	map->buckets = calloc(map->num_buckets, sizeof(struct hash_node *));
	return map;
}

void hash_map_free(struct hash_map *map)
{
	/* Walk through the buckets and free nodes. */
	int bucket_num;
	for (bucket_num = 0; bucket_num < map->num_buckets; ++bucket_num) {
		struct hash_node *node = NULL;
		struct hash_node *next = NULL;
		for (node = map->buckets[bucket_num]; node != NULL;
		     node = next) {
			next = node->next;
			free(node);
		}
	}

	free(map->buckets);
	memset(map, 0, sizeof(*map));	/* paranoia to help catch bugs */
	free(map);
}

/* Link the given node into the correct bucket linked list in the hash map. */
static void hash_map_link(struct hash_map *map,
				  struct hash_node *node)
{
	const size_t bucket_num = hash_bucket_num(map, node->key);
	node->next = map->buckets[bucket_num];
	map->buckets[bucket_num] = node;
}

/* Create a new array of buckets that's twice the size of the current
 * array. Then Walk through the old buckets and move all the nodes to
 * the new buckets.
 */
static void hash_map_grow(struct hash_map *map)
{
	const size_t old_num_buckets = map->num_buckets;
	map->num_buckets *= 2;
	map->bucket_mask = map->num_buckets - 1;
	struct hash_node **old_buckets = map->buckets;
	map->buckets = calloc(map->num_buckets, sizeof(struct hash_node *));

	size_t old_bucket_num = 0;
	for (old_bucket_num = 0; old_bucket_num < old_num_buckets;
	     ++old_bucket_num) {
		struct hash_node *node = NULL;
		struct hash_node *next = NULL;
		for (node = old_buckets[old_bucket_num]; node != NULL;
		     node = next) {
			next = node->next;
			hash_map_link(map, node);
		}
	}

	free(old_buckets);
}

/* Insert a new node in the hash map, first growing the map if needed. */
static void hash_map_insert(struct hash_map *map, u32 key, u32 value)
{
	/* To keep things simple, we target a load factor of 1.0. */
	if ((map->num_keys >= map->num_buckets) &&
	    (map->num_buckets < MAX_BUCKETS)) {
		hash_map_grow(map);
	}
	++map->num_keys;
	struct hash_node *node = calloc(1, sizeof(struct hash_node));
	node->key = key;
	node->value = value;
	hash_map_link(map, node);
}

void hash_map_set(struct hash_map *map, u32 key, u32 value)
{
	const size_t bucket_num = hash_bucket_num(map, key);
	struct hash_node *node = NULL;
	for (node = map->buckets[bucket_num]; node != NULL; node = node->next) {
		if (node->key == key) {
			node->value = value;
			return;
		}
	}
	hash_map_insert(map, key, value);
}

bool hash_map_get(const struct hash_map *map, u32 key, u32 *value)
{
	const size_t bucket_num = hash_bucket_num(map, key);
	struct hash_node *node = NULL;
	for (node = map->buckets[bucket_num]; node != NULL; node = node->next) {
		if (node->key == key) {
			*value = node->value;
			return true;
		}
	}
	return false;
}
