// Copyright 2011 Google Inc. All Rights Reserved.
// Author: willemb@google.com (Will de Bruijn)
//
// POSIX capability support for Linux: simplified libcap
// GPL applies, as this interface was inspired by sys/capability.h

#ifndef _LINUX_GTESTS_NET_CAPABILITY_H
#define _LINUX_GTESTS_NET_CAPABILITY_H

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#else
#include <linux/capability.h>

typedef struct __user_cap_data_struct *cap_t;
typedef int cap_value_t;

typedef enum {
	CAP_EFFECTIVE=0,
	CAP_PERMITTED=1,
	CAP_INHERITABLE=2
} cap_flag_t;

typedef enum {
	CAP_CLEAR=0,
	CAP_SET=1
} cap_flag_value_t;

static struct __user_cap_header_struct header = {
	.version = _LINUX_CAPABILITY_VERSION_3,
	.pid = 0,
};

// System calls: implemented in libc
int capset(cap_user_header_t header, cap_user_data_t data);
int capget(cap_user_header_t header, const cap_user_data_t data);

// Extract a value for one name in one of the capability lists
// only supports flag CAP_EFFECTIVE
static inline int
cap_get_flag(cap_t cap, cap_value_t name, cap_flag_t flag, cap_flag_value_t *val)
{
	assert(flag == CAP_EFFECTIVE);
	assert(name < (sizeof(cap->effective) * 8));
	*val = (cap->effective & (1 << name)) ? CAP_SET : CAP_CLEAR;
	return 0;
}

// Set the value for a number of names in one of the capability lists
// only supports flag CAP_EFFECTIVE
static inline int
cap_set_flag(cap_t cap, cap_flag_t flag, int num_name,
	     const cap_value_t *names, cap_flag_value_t val)
{
	int i;

	assert(flag == CAP_EFFECTIVE);
	if (val == CAP_SET)
		for (i = 0; i < num_name; i++)
			cap->effective |= (1 << names[i]);
	else
		for (i = 0; i < num_name; i++)
			cap->effective &= ~(1 << names[i]);

	return 0;
}

// Get the capability lists from the kernel
static inline cap_t
cap_get_proc(void)
{
	cap_t capabilities = calloc(_LINUX_CAPABILITY_U32S_3,
				    sizeof(struct __user_cap_data_struct));
	if (capget(&header, capabilities)) {
		perror("capget");
		return NULL;
	}

	return capabilities;
}

// Update the capability lists in the kernel
static inline int
cap_set_proc(cap_t capabilities)
{
	if (capset(&header, capabilities)) {
		perror("capset");
		return -1;
	}
	return 0;
}

// Free a capability list
static inline int
cap_free(void *capabilities)
{
	free(capabilities);
	return 0;
}

#endif /* !HAVE_SYS_CAPABILITY_H */
#endif /* _LINUX_GTESTS_NET_CAPABILITY_H */
