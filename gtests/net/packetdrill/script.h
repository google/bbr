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
 * Type definitions for data structures to represent a parsed test script.
 */

#ifndef __SCRIPT_H__
#define __SCRIPT_H__

#include "types.h"

#include <sys/time.h>
#include "packet.h"

#define MSGHDR_MAX_CONTROLLEN 2000	/* arbitrary maximum cmsg length */

/* The types of expressions in a script */
enum expression_t {
	EXPR_ELLIPSIS,		  /* ... but no value */
	EXPR_INTEGER,		  /* integer in 'num' */
	EXPR_LINGER,		  /* struct linger for SO_LINGER */
	EXPR_WORD,		  /* unquoted word in 'string' */
	EXPR_STRING,		  /* double-quoted string in 'string' */
	EXPR_GRE,		  /* GRE header */
	EXPR_IN6_ADDR,		  /* in6_addr in 'address_ipv6' */
	EXPR_SOCKET_ADDRESS_IPV4, /* sockaddr_in in 'socket_address_ipv4' */
	EXPR_SOCKET_ADDRESS_IPV6, /* sockaddr_in6 in 'socket_address_ipv6' */
	EXPR_BINARY,		  /* binary expression, 2 sub-expressions */
	EXPR_LIST,		  /* list of expressions */
	EXPR_IOVEC,		  /* expression tree for an iovec struct */
	EXPR_MSGHDR,		  /* expression tree for a msghdr struct */
	EXPR_CMSG,		  /* expression tree for a cmsg struct */
	EXPR_POLLFD,		  /* expression tree for a pollfd struct */
	EXPR_MPLS_STACK,	  /* MPLS label stack expression */
	EXPR_SCM_TIMESTAMPING,	  /* scm_timestamping expression */
	EXPR_SOCK_EXTENDED_ERR,	  /* scm_sock_extended_err expression */
	EXPR_EPOLLEV,	          /* expression tree for a epoll_event struct */
	NUM_EXPR_TYPES,
};
/* Convert an expression type to a human-readable string */
const char *expression_type_to_string(enum expression_t type);

/* A memory buffer/string. Uses a len because it can contain \x00 bytes. */
struct memory_buffer {
	char *ptr;
	size_t len;	/* does not include any terminating '\0' for strings */
};

/* An expression in a script */
struct expression {
	enum expression_t type;
	union {
		s64 num;
		struct memory_buffer buf;
		struct linger linger;
		struct gre gre;
		struct in6_addr address_ipv6;
		struct sockaddr_in *socket_address_ipv4;
		struct sockaddr_in6 *socket_address_ipv6;
		struct binary_expression *binary;
		struct expression_list *list;
		struct iovec_expr *iovec;
		struct msghdr_expr *msghdr;
		struct cmsg_expr *cmsg;
		struct pollfd_expr *pollfd;
		struct mpls_stack *mpls_stack;
		struct scm_timestamping_expr *scm_timestamping;
		struct sock_extended_err_expr *sock_extended_err;
		struct epollev_expr *epollev;
	} value;
	const char *format;	/* the printf format for printing the value */
};

/* Two expressions combined via a binary operator */
struct binary_expression {
	char *op;			/* binary operator */
	struct expression *lhs;	/* left hand side expression */
	struct expression *rhs;	/* right hand side expression */
};

/* A list of expressions, e.g. a list of actual parameters in function call,
 * or list of elements in an array.
 */
struct expression_list {
	struct expression *expression;
	struct expression_list *next;
};

/* Parse tree for a iovec struct in a writev/readv/sendmsg/recvmsg syscall. */
struct iovec_expr {
	struct expression *iov_base;
	struct expression *iov_len;
};

/* Parse tree for a msghdr struct in a sendmsg/recvmsg syscall. */
struct msghdr_expr {
	struct expression *msg_name;
	struct expression *msg_namelen;
	struct expression *msg_iov;
	struct expression *msg_iovlen;
	struct expression *msg_control;
	struct expression *msg_flags;
};

/* Parse tree for a cmsg item in a sendmsg/recvmsg syscall. */
struct cmsg_expr {
	struct expression *cmsg_level;
	struct expression *cmsg_type;
	struct expression *cmsg_data;
};

/* A verbatim copy of Linux's struct scm_timestamping for portability. */
struct scm_timestamping_expr {
	struct timespec ts[3];
};

/* Parse tree for a sock_extended_err item in a recvmsg syscall. */
struct sock_extended_err_expr {
	struct expression *ee_errno;
	struct expression *ee_origin;
	struct expression *ee_type;
	struct expression *ee_code;
	struct expression *ee_info;
	struct expression *ee_data;
};

/* Parse tree for a pollfd struct in a poll syscall. */
struct pollfd_expr {
	struct expression *fd;		/* file descriptor */
	struct expression *events;	/* requested events */
	struct expression *revents;	/* returned events */
};

/* Parse tree for a epoll_event struct in an epoll syscall. */
struct epollev_expr {
	struct expression *events;
	struct expression *ptr;
	struct expression *fd;
	struct expression *u32;
	struct expression *u64;
};

/* The errno-related info from strace to summarize a system call error */
struct errno_spec {
	const char *errno_macro;	/* errno symbol (C macro name) */
	const char *strerror;		/* strerror translation of errno */
};

/* A system call and its expected result. System calls that should
 * return immediately have an end_usecs value of SYSCALL_NON_BLOCKING.
 * System calls that block for some non-zero time have a non-negative
 * end_usecs indicating the time at which the system call should
 * return.
 */
struct syscall_spec {
	const char *name;			/* name of system call */
	struct expression_list *arguments;	/* arguments to system call */
	struct expression *result;		/* expected result from call */
	struct errno_spec *error;		/* errno symbol or NULL */
	char *note;				/* extra note from strace */
	s64 end_usecs;				/* finish time, if it blocks */
};
#define SYSCALL_NON_BLOCKING  -1		/* end_usecs if non-blocking */

static inline bool is_blocking_syscall(struct syscall_spec *syscall)
{
	return syscall->end_usecs != SYSCALL_NON_BLOCKING;
}

/* A shell command line to execute using system(3) */
struct command_spec {
	const char *command_line;	/* executed with /bin/sh */
};

/* An ASCII text snippet of code to insert in the post-processing
 * output. This can be, for example, a snippet of Python to execute.
 */
struct code_spec {
	const char *text;	/* snippet of post-processing code */
};

/* Types of events in a script */
enum event_t {
	INVALID_EVENT = 0,
	PACKET_EVENT,
	SYSCALL_EVENT,
	COMMAND_EVENT,
	CODE_EVENT,
	NUM_EVENT_TYPES,
};

/* Types of event times */
enum event_time_t {
	ABSOLUTE_TIME = 0,
	RELATIVE_TIME,
	ANY_TIME,
	ABSOLUTE_RANGE_TIME,
	RELATIVE_RANGE_TIME,
	NUM_TIME_TYPES,
};

/* An event in a script */
struct event {
	int line_number;	/* location in test script file */
	s64 time_usecs;		/* event time in microseconds */
	s64 time_usecs_end;	/* event time range end (or NO_TIME_RANGE) */
	s64 offset_usecs;	/* relative event time offset from script start
				 * (or NO_TIME_RANGE) */
	enum event_time_t time_type; /* type of time */
	enum event_t type;	/* type of the event */
	union {
		struct packet	*packet;
		struct syscall_spec	*syscall;
		struct command_spec	*command;
		struct code_spec	*code;
	} event;		/* pointer to the event */
	struct event *next;	/* next in linked list of events */
};
#define NO_TIME_RANGE	-1		/* time_usecs_end if no range */

static inline bool is_event_time_absolute(struct event *event)
{
	return ((event->time_type == ABSOLUTE_TIME) ||
		(event->time_type == ABSOLUTE_RANGE_TIME));
}

/* A --name=value option in a script */
struct option_list {
	char *name;
	char *value;
	struct option_list *next;
};

/* A parsed script. The script owns all of the data to which
 * it points. TODO: add a script_free() to free everything when we are
 * done executing the script, instead of leaking all that memory.
 */
struct script {
	struct option_list *option_list;    /* linked list of options */
	struct command_spec *init_command;  /* untimed initialization command */
	struct event	*event_list;	    /* linked list of all events */
	struct command_spec *cleanup_command;  /* untimed cleanup command */
	char		*buffer;	    /* raw input text of the script */
	int		length;		    /* number of bytes in the script */
};

/* Global pointer for final command we always execute at end of script: */
extern const char *cleanup_cmd;
/* Path of currently-executing script, for use in cleanup command errors: */
extern const char *script_path;

/* A table entry mapping a bit mask to its human-readable name.
 * A table of such mappings must be terminated with a struct with a
 * NULL name.
 */
struct flag_name {
	u64		flag;	/* a flag with one bit set */
	const char	*name;	/* human-readable ASCII name for this bit */
};

/* Initialize a script object */
extern void init_script(struct script *script);

/* Look up the value of the given symbol, and fill it in. On success,
 * return STATUS_OK; if the symbol cannot be found, return
 * STATUS_ERR and fill in an error message in *error.
 */
extern int symbol_to_int(const char *input_symbol, s64 *output_integer,
			 char **error);

/* Convert the given bit flags to a human-readable ASCII bit-wise OR
 * ('|') expression and return the resulting malloc-allocated
 * string. Caller must free() the memory.
 */
extern struct flag_name poll_flags[];
char *flags_to_string(struct flag_name *flags_array, u64 flags);

/* Do a deep deallocation of a heap-allocated expression list,
 * including any other space that it points too.
 */
extern void free_expression(struct expression *expression);

/* Do a deep deallocation of a heap-allocated expression list,
 * including any other space that it points too.
 */
extern void free_expression_list(struct expression_list *list);

/* Return a copy of the given expression list with each expression
 * evaluated (e.g. symbols resolved to ints). On success, returns
 * STATUS_OK. On error return STATUS_ERR and fill in *error.
 */
extern int evaluate_expression_list(struct expression_list *in_list,
				    struct expression_list **out_list,
				    char **error);

#endif /* __SCRIPT_H__ */
