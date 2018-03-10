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
 * Declarations for platform-specific information.
 */

#ifndef __PLATFORMS_H__
#define __PLATFORMS_H__


/* ------------------------- Linux --------------------- */

#ifdef linux

#include <features.h>
#include <linux/types.h>

#define HAVE_OPEN_MEMSTREAM     1
#define HAVE_FMEMOPEN           1
#define TUN_PATH                "/dev/net/tun"
#define HAVE_TCP_INFO           1
#define HAVE_TCP_CC_INFO	1
#define HAVE_SO_MEMINFO		1

#include "uapi_linux.h"

#else

/* The underscore variants of the kernel-style names are defined in
 * linux/types.h, but we must define them explicitly for other platforms. */
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;

/* We also use kernel-style names for endian-specific unsigned types. */
typedef u16 __le16;
typedef u16 __be16;
typedef u32 __le32;
typedef u32 __be32;
typedef u64 __le64;
typedef u64 __be64;

typedef u16 __sum16;
typedef u32 __wsum;

#endif  /* linux */


/* ------------------------- FreeBSD --------------------- */

#if defined(__FreeBSD__)

#define USE_LIBPCAP             1
#define TUN_PATH                "/dev/tun0"
#define TUN_DEV                 "tun0"

#define HAVE_TCP_INFO           1
#if (__FreeBSD_version < 1000000 && __FreeBSD_version > 902000) || __FreeBSD_version > 1000028
#define HAVE_FMEMOPEN           1
#endif

#include "open_memstream.h"
#include "fmemopen.h"

#endif  /* __FreeBSD__ */

/* ------------------------- OpenBSD --------------------- */

#if defined(__OpenBSD__)

#define USE_LIBPCAP             1
#define TUN_PATH                "/dev/tun0"
#define TUN_DEV                 "tun0"

#define HAVE_TCP_INFO           0

#include "open_memstream.h"
#include "fmemopen.h"

#define __always_inline __attribute__((__always_inline__))

#endif  /* __OpenBSD__ */

/* ------------------------- NetBSD --------------------- */

#if defined(__NetBSD__)

#define USE_LIBPCAP             1
#define TUN_PATH                "/dev/tun0"
#define TUN_DEV                 "tun0"

#define HAVE_TCP_INFO           0

#define HAVE_FMEMOPEN           1
#include "open_memstream.h"

#define __always_inline __attribute__((__always_inline__))

#endif  /* __NetBSD__ */


#endif /* __PLATFORMS_H__ */
