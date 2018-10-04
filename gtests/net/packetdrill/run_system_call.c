/*
 * Copyright 2013 Google Inc.
 * Copyright 2016 Red Hat Inc.
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
 * A module to execute a system call from a test script.
 */

#include "run_system_call.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>
#include "assert.h"
#include "file.h"
#include "epoll.h"
#include "pipe.h"
#include "logging.h"
#include "run.h"
#include "script.h"
#include "icmp.h"
#include "icmpv6.h"
#include "capability.h"

static int to_live_fd(struct state *state, int script_fd, int *live_fd,
		      char **error);

static int syscall_icmp_sendto(struct state *state,
			       struct syscall_spec *syscall,
			       struct expression_list *args, char **error);

#if defined(linux)
/* Provide a wrapper for the Linux gettid() system call
 * (glibc only provides it in version 2.30 or higher).
 */
#if (__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 30))
static pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#endif  /* old glibc versions */
#endif  /* defined(linux) */
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
static pid_t gettid(void)
{
	/* TODO(ncardwell): Implement me. XXX */
	return 0;
}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)*/

/* Read a whole file into the given buffer of the given length. */
static void read_whole_file(const char *path, char *buffer, int max_bytes)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		die_perror("open");

	int bytes = read(fd, buffer, max_bytes);
	if (bytes < 0)
		die_perror("read");
	else if (bytes == max_bytes)
		die("%s file too large to read\n", path);

	if (close(fd) < 0)
		die_perror("close");
}

/* Return true iff the given thread is sleeping. */
static bool is_thread_sleeping(pid_t process_id, pid_t thread_id)
{
	/* Read the entire thread state file, using the buffer size ps uses. */
	char *proc_path = NULL;
	asprintf(&proc_path, "/proc/%d/task/%d/stat", process_id, thread_id);
	const int STATE_BUFFER_BYTES = 1023;
	char *state = calloc(STATE_BUFFER_BYTES, 1);
	read_whole_file(proc_path, state, STATE_BUFFER_BYTES - 1);
	state[STATE_BUFFER_BYTES - 1] = '\0';

	/* Parse the thread state from the third space-delimited field. */
	const int THREAD_STATE_INDEX = 3;
	const char *field = state;
	int i = 0;
	for (i = 0; i < THREAD_STATE_INDEX - 1; i++) {
		field = strchr(field, ' ');
		if (field == NULL)
			die("unable to parse %s\n", proc_path);
		++field;
	}
	bool is_sleeping = (field[0] == 'S');

	free(proc_path);
	free(state);

	return is_sleeping;
}

/* Returns number of expressions in the list. */
static int expression_list_length(struct expression_list *list)
{
	int count = 0;
	while (list != NULL) {
		list = list->next;
		++count;
	}
	return count;
}

static int get_arg_count(struct expression_list *args)
{
	return expression_list_length(args);
}

/* Verify that the expression list has the expected number of
 * expressions. Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message.
 */
static int check_arg_count(struct expression_list *args, int expected,
			   char **error)
{
	assert(expected >= 0);
	int actual = get_arg_count(args);
	if (actual != expected) {
		asprintf(error, "Expected %d args but got %d", expected,
			 actual);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Returns the argument with the given index. Returns the argument on
 * success; on failure returns NULL and sets error message.
 */
static struct expression *get_arg(struct expression_list *args,
				   int index, char **error)
{
	assert(index >= 0);
	int current = 0;
	while ((args != NULL) && (current < index)) {
		args = args->next;
		++current;
	}
	if ((args != NULL) && (current == index)) {
		return args->expression;
	} else {
		asprintf(error, "Argument list too short");
		return NULL;
	}
}

/* Return STATUS_OK if the expression is of the expected
 * type. Otherwise fill in the error with a human-readable error
 * message about the mismatch and return STATUS_ERR.
 */
static int check_type(const struct expression *expression,
		      enum expression_t expected_type,
		      char **error)
{
	if (expression->type == expected_type) {
		return STATUS_OK;
	} else {
		asprintf(error, "Bad type; actual: %s expected: %s",
			 expression_type_to_string(expression->type),
			 expression_type_to_string(expected_type));
		return STATUS_ERR;
	}
}

/* Sets the value from the expression argument, checking that it is a
 * valid s32 or u32, and matches the expected type. Returns STATUS_OK on
 * success; on failure returns STATUS_ERR and sets error message.
 */
static int get_s32(struct expression *expression,
		   s32 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	if ((expression->value.num > UINT_MAX) ||
	    (expression->value.num < INT_MIN)) {
		asprintf(error,
			 "Value out of range for 32-bit integer: %lld",
			 expression->value.num);
		return STATUS_ERR;
	}
	*value = expression->value.num;
	return STATUS_OK;
}

/* Sets the value from the expression argument, checking that it matches the
 * expected type. Returns STATUS_OK on success; on failure returns STATUS_ERR
 * and sets error message.
 */
static int get_s64(struct expression *expression,
		   s64 *value, char **error)
{
	if (check_type(expression, EXPR_INTEGER, error))
		return STATUS_ERR;
	*value = expression->value.num;
	return STATUS_OK;
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type.
 */
static int s32_arg(struct expression_list *args,
		   int index, s32 *value, char **error)
{
	struct expression *expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	return get_s32(expression, value, error);
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type.
 */
static int s64_arg(struct expression_list *args,
		   int index, s64 *value, char **error)
{
	struct expression *expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	return get_s64(expression, value, error);
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type: a list with a single integer.
 */
static int bracketed_arg(struct expression_list *args,
			 int index, struct expression **elt, char **error)
{
	struct expression_list *list;
	struct expression *expression;

	*elt = NULL;
	expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	if (check_type(expression, EXPR_LIST, error))
		return STATUS_ERR;
	list = expression->value.list;
	if (expression_list_length(list) != 1) {
		asprintf(error,
			 "Expected [<element>] but got multiple elements");
		return STATUS_ERR;
	}
	*elt = list->expression;
	return STATUS_OK;
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type: a list with a single s32.
 */
static int s32_bracketed_arg(struct expression_list *args,
			     int index, s32 *value, char **error)
{
	struct expression *expression = NULL;

	if (bracketed_arg(args, index, &expression, error))
		return STATUS_ERR;
	return get_s32(expression, value, error);
}

/* Return the value of the argument with the given index, and verify
 * that it has the expected type: a list with a single s64.
 */
static int s64_bracketed_arg(struct expression_list *args,
			     int index, s64 *value, char **error)
{
	struct expression *expression = NULL;

	if (bracketed_arg(args, index, &expression, error))
		return STATUS_ERR;
	return get_s64(expression, value, error);
}

/* Return STATUS_OK iff the argument with the given index is an
 * ellipsis (...).
 */
static int ellipsis_arg(struct expression_list *args, int index, char **error)
{
	struct expression *expression = get_arg(args, index, error);
	if (expression == NULL)
		return STATUS_ERR;
	if (check_type(expression, EXPR_ELLIPSIS, error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Free all the space used by the given iovec. */
static void iovec_free(struct iovec *iov, size_t iov_len)
{
	int i;

	if (iov == NULL)
		return;

	for (i = 0; i < iov_len; ++i)
		free(iov[i].iov_base);
	free(iov);
}

/* Allocate and fill in an iovec described by the given expression.
 * Return STATUS_OK if the expression is a valid iovec. Otherwise
 * fill in the error with a human-readable error message and return
 * STATUS_ERR.
 */
static int iovec_new(struct expression *expression,
		     struct iovec **iov_ptr, size_t *iov_len_ptr,
		     char **error)
{
	int status = STATUS_ERR;
	int i;
	struct expression_list *list;	/* input expression from script */
	size_t iov_len = 0;
	struct iovec *iov = NULL;	/* live output */

	if (check_type(expression, EXPR_LIST, error))
		goto error_out;

	list = expression->value.list;

	iov_len = expression_list_length(list);
	iov = calloc(iov_len, sizeof(struct iovec));

	for (i = 0; i < iov_len; ++i, list = list->next) {
		size_t len;
		struct iovec_expr *iov_expr;

		if (check_type(list->expression, EXPR_IOVEC, error))
			goto error_out;

		iov_expr = list->expression->value.iovec;

		assert(iov_expr->iov_base->type == EXPR_ELLIPSIS);
		assert(iov_expr->iov_len->type == EXPR_INTEGER);

		len = iov_expr->iov_len->value.num;

		iov[i].iov_len = len;
		iov[i].iov_base = calloc(len, 1);
	}

	status = STATUS_OK;

error_out:
	*iov_ptr = iov;
	*iov_len_ptr = iov_len;
	return status;
}

static bool sendcall_may_free(struct state *state)
{
	return !state->config->send_omit_free;
}

static void sendcall_free(struct state *state, void *ptr)
{
	if (sendcall_may_free(state))
		free(ptr);
}

static inline int list_length(struct expression_list *list)
{
	int length = 0;
	while (list) {
		length++;
		list = list->next;
	}
	return length;
}

int add_nla(void *dst, int type, int len, const void *data)
{
	struct nlattr *nla = (struct nlattr *) dst;
	int attr_size = NLA_HDRLEN + len;
	int total_size = NLA_ALIGN(attr_size);

	nla->nla_type = type;
	nla->nla_len = attr_size;
	memcpy(dst + NLA_HDRLEN, data, len);
	memset(dst + attr_size, 0, total_size - attr_size);

	return total_size;
}

/* Returns whether the NLA value is valid. */
static bool nla_value_is_valid(enum expression_t type)
{
	return type == EXPR_INTEGER || type == EXPR_ELLIPSIS;
}

#define OPT_NLA_IGNORE_VAL (~0U)
#define OPT_NLA_IGNORE_VAL_U32 ((u32) OPT_NLA_IGNORE_VAL)
#define OPT_NLA_IGNORE_VAL_U8 ((u8) OPT_NLA_IGNORE_VAL)

/* Fills in the value of a TLV expression. */
static void get_nla_value(const struct expression *expr, void *out_buf,
			  int num_bytes)
{
	u64 val;

	val = (expr->type == EXPR_INTEGER) ? expr->value.num
					   : OPT_NLA_IGNORE_VAL;
	memcpy(out_buf, &val, num_bytes);
}

/* Fill in the expected values of from 'expr', which is a list of binary
 * expressions of the form: key = val.
 */
static int nla_expr_list_to_nla(struct expression_list *list,
				void *dst, int dst_len, int *len,
				struct nla_type_info *nla_info,
				int nla_info_len,
				char **error)
{
	struct expression *element, *key, *value;
	void *start = dst;
	u64 val;	/* each value uses some prefix of this space */
	s64 key_num, val_num;
	int num_bytes;

	for (; list; list = list->next) {
		element = list->expression;

		if (check_type(element, EXPR_BINARY, error))
			return STATUS_ERR;

		if (strcmp("=", element->value.binary->op) != 0)
			return STATUS_ERR;

		key = element->value.binary->lhs;
		value = element->value.binary->rhs;
		if (check_type(key, EXPR_INTEGER, error))
			return STATUS_ERR;
		if (!nla_value_is_valid(value->type)) {
			asprintf(error,
				 "values must be numeric or ellipsis");
			return STATUS_ERR;
		}

		key_num = key->value.num;
		if (key_num < 0 || key_num >= nla_info_len) {
			asprintf(error, "bad NLA type %lld\n", key_num);
			return STATUS_ERR;
		}
		val_num = value->value.num;
		num_bytes = nla_info[key_num].length;
		if (num_bytes == sizeof(u8) &&
		    value->type == EXPR_INTEGER && !is_valid_u8(val_num))
			die("out of bound u8 value specified\n");
		else if (num_bytes == sizeof(u32) &&
			 value->type == EXPR_INTEGER && !is_valid_u32(val_num))
			die("out of bound u32 value specified\n");

		get_nla_value(value, &val, num_bytes);
		dst += add_nla(dst, key_num, nla_info[key_num].length, &val);
	}

	*len = dst - start;
	return STATUS_OK;
}

/* Fill in the values of sock_extended_err structure from the expression. */
static int new_extended_err(const struct sock_extended_err_expr *expr,
			    struct sock_extended_err *ee, char **error)
{
	if (get_s32(expr->ee_errno, (s32 *)&ee->ee_errno, error))
		return STATUS_ERR;
	if (get_s32(expr->ee_origin, (s32 *)&ee->ee_origin, error))
		return STATUS_ERR;
	if (get_s32(expr->ee_type, (s32 *)&ee->ee_type, error))
		return STATUS_ERR;
	if (get_s32(expr->ee_code, (s32 *)&ee->ee_code, error))
		return STATUS_ERR;
	if (get_s32(expr->ee_info, (s32 *)&ee->ee_info, error))
		return STATUS_ERR;
	if (get_s32(expr->ee_data, (s32 *)&ee->ee_data, error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Info for various TCP NLAs */
struct nla_type_info tcp_nla[] = {
	[_TCP_NLA_PAD] = {"TCP_NLA_PAD", sizeof(u32)},
	[_TCP_NLA_BUSY]	= {"TCP_NLA_BUSY", sizeof(u64)},
	[_TCP_NLA_RWND_LIMITED]	= {"TCP_NLA_RWND_LIMITED", sizeof(u64)},
	[_TCP_NLA_SNDBUF_LIMITED] = {"TCP_NLA_SNDBUF_LIMITED", sizeof(u64)},
	[_TCP_NLA_DATA_SEGS_OUT] = {"TCP_NLA_DATA_SEGS_OUT", sizeof(u64)},
	[_TCP_NLA_TOTAL_RETRANS] = {"TCP_NLA_TOTAL_RETRANS", sizeof(u64)},
	[_TCP_NLA_PACING_RATE] = {"TCP_NLA_PACING_RATE", sizeof(u64)},
	[_TCP_NLA_DELIVERY_RATE] = {"TCP_NLA_DELIVERY_RATE", sizeof(u64)},
	[_TCP_NLA_SND_CWND] = {"TCP_NLA_SND_CWND", sizeof(u32)},
	[_TCP_NLA_REORDERING] = {"TCP_NLA_REORDERING", sizeof(u32)},
	[_TCP_NLA_MIN_RTT] = {"TCP_NLA_MIN_RTT", sizeof(u32)},
	[_TCP_NLA_RECUR_RETRANS] = {"TCP_NLA_RECUR_RETRANS", sizeof(u8)},
	[_TCP_NLA_DELIVERY_RATE_APP_LMT] = {"TCP_NLA_DELIVERY_RATE_APP_LMT",
					    sizeof(u8)},
	[_TCP_NLA_SNDQ_SIZE] = {"TCP_NLA_SNDQ_SIZE", sizeof(u32)},
	[_TCP_NLA_CA_STATE] = {"TCP_NLA_CA_STATE", sizeof(u8)},
	[_TCP_NLA_SND_SSTHRESH] = {"TCP_NLA_SND_SSTHRESH", sizeof(u32)},
	[_TCP_NLA_DELIVERED] = {"TCP_NLA_DELIVERED", sizeof(u32)},
	[_TCP_NLA_DELIVERED_CE] = {"TCP_NLA_DELIVERED_CE", sizeof(u32)},
	[_TCP_NLA_BYTES_SENT] = {"TCP_NLA_BYTES_SENT", sizeof(u64)},
	[_TCP_NLA_BYTES_RETRANS] = {"TCP_NLA_BYTES_RETRANS", sizeof(u64)},
	[_TCP_NLA_DSACK_DUPS] = {"TCP_NLA_DSACK_DUPS", sizeof(u32)},
	[_TCP_NLA_REORD_SEEN] = {"TCP_NLA_REORD_SEEN", sizeof(u32)},
	[_TCP_NLA_SRTT] = {"TCP_NLA_SRTT", sizeof(u32)},
};

/* Allocate and fill a msg_control described by the given expression.
 * Return STATUS_OK if the expression is a valid msg_control.
 * Otherwise fill in the error with a human-readable error message and
 * return STATUS_ERR.
 */
static int cmsg_new(const struct expression *expr, struct msghdr *msg,
		     char **error)
{
	int status = STATUS_ERR;
	int len, sum = 0;
	const struct expression_list *list;
	const struct cmsg_expr *cmsg_expr;
	struct sock_extended_err_expr *ee_expr;
	struct expression_list *stats_expr;
	struct cmsghdr *cmsg;
	void *data;

	assert(expr->type == EXPR_LIST);

	msg->msg_control = calloc(1, MSGHDR_MAX_CONTROLLEN);
	msg->msg_controllen = MSGHDR_MAX_CONTROLLEN;

	cmsg = CMSG_FIRSTHDR(msg);

	for (list = expr->value.list; list; list = list->next) {
		expr = list->expression;
		if (check_type(expr, EXPR_CMSG, error))
			goto error_out;

		cmsg_expr = expr->value.cmsg;
		if (get_s32(cmsg_expr->cmsg_level, &cmsg->cmsg_level, error))
			goto error_out;
		if (get_s32(cmsg_expr->cmsg_type, &cmsg->cmsg_type, error))
			goto error_out;

		data = CMSG_DATA(cmsg);

		switch (cmsg_expr->cmsg_data->type) {
		case EXPR_INTEGER:
			len = sizeof(int);
			if (get_s32(cmsg_expr->cmsg_data, data, error))
				goto error_out;
			break;

		case EXPR_SCM_TIMESTAMPING:
			len = sizeof(struct scm_timestamping);
			memcpy(data,
			       cmsg_expr->cmsg_data->value.scm_timestamping,
			       len);
			break;

		case EXPR_LIST:
			stats_expr = cmsg_expr->cmsg_data->value.list;
			if (nla_expr_list_to_nla(stats_expr, data,
						 (MSGHDR_MAX_CONTROLLEN - sum
						  - sizeof(struct cmsghdr)),
						 &len,
						 tcp_nla, ARRAY_SIZE(tcp_nla),
						 error))
				goto error_out;
			break;

		case EXPR_SOCK_EXTENDED_ERR:
			/* ip(v6)_recv_error returns a struct defined in
			 * function scope that appends a sockaddr.
			 */
			len = sizeof(struct sock_extended_err);
			if (cmsg->cmsg_level == SOL_IP)
				len += sizeof(struct sockaddr_in);
			else
				len += sizeof(struct sockaddr_in6);

			ee_expr = cmsg_expr->cmsg_data->value.sock_extended_err;
			if (new_extended_err(ee_expr,
					     (struct sock_extended_err *)data,
					     error))
				goto error_out;
			break;

		default:
			asprintf(error, "Unrecognized type for cmsg_data");
			goto error_out;
		}

		cmsg->cmsg_len = CMSG_LEN(len);
		sum += CMSG_SPACE(len);

		cmsg = CMSG_NXTHDR(msg, cmsg);
	}

	status = STATUS_OK;

error_out:
	msg->msg_controllen = sum;

	return status;
}

/* Check if the sock_extended_err structure is the same as expected. */
static bool sock_ee_expect_eq(struct sock_extended_err *expected,
			      struct sock_extended_err *actual, int index,
			      char **error) {
	if (actual->ee_errno != expected->ee_errno) {
		asprintf(error,
			 "Bad errno in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_errno, actual->ee_errno);
		return false;
	}
	if (actual->ee_origin != expected->ee_origin) {
		asprintf(error,
			 "Bad origin in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_origin, actual->ee_origin);
		return false;
	}
	if (actual->ee_type != expected->ee_type) {
		asprintf(error,
			 "Bad type in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_type, actual->ee_type);
		return false;
	}
	if (actual->ee_code != expected->ee_code) {
		asprintf(error,
			 "Bad code in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_code, actual->ee_code);
		return false;
	}
	if (actual->ee_info != expected->ee_info) {
		asprintf(error,
			 "Bad info in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_info, actual->ee_info);
		return false;
	}
	if (actual->ee_data != expected->ee_data) {
		asprintf(error,
			 "Bad data in extended err %d: "
			 "expected=%u actual=%u",
			 index, expected->ee_data, actual->ee_data);
		return false;
	}
	return true;
}

/* Convert a timespec to usecs. */
static s64 timespec_to_usecs(struct timespec *ts)
{
	if (ts == NULL)
		return -1;
	return (s64)ts->tv_sec * 1000000 + ts->tv_nsec / 1000;
}

/* Check if the scm_timestamping is the same as expected. */
static bool scm_timestamping_expect_eq(struct state *state,
				       struct scm_timestamping *expected,
				       struct scm_timestamping *actual,
				       int index, char **error)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(expected->ts); i++) {
		/* ignore the timestamps, if expected is 0. */
		if (!expected->ts[i].tv_sec && !expected->ts[i].tv_nsec)
			continue;

		s64 exp_usecs = script_time_to_live_time_usecs(state,
			timespec_to_usecs(&expected->ts[i]));
		s64 actual_usecs = timespec_to_usecs(&actual->ts[i]);
		/* difference exceeds configured timing tolerance */
		if (llabs(exp_usecs - actual_usecs) >
		    state->config->tolerance_usecs) {
			asprintf(error,
				 "Bad timestamp %d in scm_timestamping %d: "
				 "expected=%lld (%lld) actual=%lld (%lld) "
				 "start=%lld",
				 i, index,
				 exp_usecs,
				 exp_usecs - state->live_start_time_usecs,
				 actual_usecs,
				 actual_usecs - state->live_start_time_usecs,
				 state->live_start_time_usecs);
			return false;
		}
	}
	return true;
}

/* Check the stats of SCM_TIMESTAMPING_OPT_STATS */
static bool scm_opt_stats_expect_eq(struct state *state,
				    void *expected,
				    void *actual,
				    int len,
				    int index, char **error)
{
	int tolerance_us = state->config->tolerance_usecs;
	int offset = 0;
	u64 ev, av;
	u32 ev_u32, av_u32;
	u8 ev_u8, av_u8;

	while (offset < len) {
		struct nlattr *enla = (struct nlattr *) (expected + offset);
		struct nlattr *anla = (struct nlattr *) (actual + offset);

		if (enla->nla_type != anla->nla_type) {
			asprintf(error,
				 "Bad nla_type %d: "
				 "expected=%u actual=%u", index,
				 enla->nla_type, anla->nla_type);
			return false;
		}

		if (enla->nla_len != anla->nla_len) {
			asprintf(error,
				 "Bad nla_len %d: "
				 "expected=%u actual=%u", index,
				 enla->nla_len, anla->nla_len);
			return false;
		}

		switch (enla->nla_type) {
		case _TCP_NLA_BUSY:
		case _TCP_NLA_RWND_LIMITED:
		case _TCP_NLA_SNDBUF_LIMITED:
			ev = *(u64 *) ((void *) enla + NLA_HDRLEN);
			av = *(u64 *) ((void *) anla + NLA_HDRLEN);

			if (ev == OPT_NLA_IGNORE_VAL) {
				break;
			} else if (ev) {
				if (llabs((s64)(ev - av)) <= tolerance_us)
					break;
			} else if (!av) { /* Be precise about 0s */
				break;
			}

			asprintf(error, "Bad %s: expected=%llu actual=%llu",
				 tcp_nla[enla->nla_type].name, ev, av);
			return false;
		case _TCP_NLA_DATA_SEGS_OUT:
		case _TCP_NLA_TOTAL_RETRANS:
		case _TCP_NLA_PACING_RATE:
		case _TCP_NLA_DELIVERY_RATE:
		case _TCP_NLA_BYTES_SENT:
		case _TCP_NLA_BYTES_RETRANS:
			ev = *(u64 *) ((void *) enla + NLA_HDRLEN);
			av = *(u64 *) ((void *) anla + NLA_HDRLEN);
			if (ev == av || ev == OPT_NLA_IGNORE_VAL)
				break;

			asprintf(error, "Bad %s: expected=%llu actual=%llu",
				 tcp_nla[enla->nla_type].name, ev, av);
			return false;
		case _TCP_NLA_SND_CWND:
		case _TCP_NLA_REORDERING:
		case _TCP_NLA_MIN_RTT:
		case _TCP_NLA_SNDQ_SIZE:
		case _TCP_NLA_SND_SSTHRESH:
		case _TCP_NLA_DELIVERED:
		case _TCP_NLA_DELIVERED_CE:
		case _TCP_NLA_DSACK_DUPS:
		case _TCP_NLA_REORD_SEEN:
		case _TCP_NLA_SRTT:
			ev_u32 = *(u32 *) ((void *) enla + NLA_HDRLEN);
			av_u32 = *(u32 *) ((void *) anla + NLA_HDRLEN);
			if (ev_u32 == av_u32 ||
			    ev_u32 == OPT_NLA_IGNORE_VAL_U32)
				break;

			asprintf(error, "Bad %s: expected=%u actual=%u",
				 tcp_nla[enla->nla_type].name, ev_u32, av_u32);
			return false;

		case _TCP_NLA_RECUR_RETRANS:
		case _TCP_NLA_DELIVERY_RATE_APP_LMT:
		case _TCP_NLA_CA_STATE:
			ev_u8 = *(u8 *) ((void *) enla + NLA_HDRLEN);
			av_u8 = *(u8 *) ((void *) anla + NLA_HDRLEN);
			if (ev_u8 == av_u8 ||
			    ev_u8 == OPT_NLA_IGNORE_VAL_U8)
				break;

			asprintf(error, "Bad %s: expected=%u actual=%u",
				 tcp_nla[enla->nla_type].name, ev_u8, av_u8);
			return false;

		default:
			return false;
		}

		offset += NLA_ALIGN(enla->nla_len);
	}

	return true;
}

/* Check if the cmsg in actual is the same as the one in expected. */
static bool cmsg_expect_eq(struct state *state, struct msghdr *expect,
			   struct msghdr *actual, char **error)
{
	int i = 0;
	const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));
	struct cmsghdr *acm = NULL, *ecm = NULL;
	void *adata = NULL, *edata = NULL;

	for (acm = CMSG_FIRSTHDR(actual), ecm = CMSG_FIRSTHDR(expect);
	     acm && ecm && acm->cmsg_len && ecm->cmsg_len;
	     acm = CMSG_NXTHDR(actual, acm), ecm = CMSG_NXTHDR(expect, ecm),
	     i++) {
		if (acm->cmsg_level != ecm->cmsg_level) {
			asprintf(error,
				 "Bad level in cmsg %d: expected=%d actual=%d",
				 i, ecm->cmsg_level, acm->cmsg_level);
			return false;
		}
		if (acm->cmsg_type != ecm->cmsg_type) {
			asprintf(error,
				 "Bad type in cmsg %d: expected=%d actual=%d",
				 i, ecm->cmsg_type, acm->cmsg_type);
			return false;
		}
		if (acm->cmsg_len != ecm->cmsg_len) {
			asprintf(error,
				 "Bad len in cmsg %d: expected=%lu actual=%lu",
				 i, ecm->cmsg_len, acm->cmsg_len);
			return false;
		}

		edata = CMSG_DATA(ecm);
		adata = CMSG_DATA(acm);
		if (!edata && !adata)
			continue;

		if (!edata) {
			asprintf(error,
				 "Bad data in cmsg %d: "
				 "expected is null, actual is not null", i);
			return false;
		} else if (!adata) {
			asprintf(error,
				 "Bad data in cmsg %d: "
				 "expected is not null, actual is null", i);
			return false;
		}

		if ((acm->cmsg_level == SOL_IP &&
		     acm->cmsg_type == IP_RECVERR) ||
		    (acm->cmsg_level == SOL_IPV6 &&
		     acm->cmsg_type == IPV6_RECVERR)) {
			struct sock_extended_err *eee = edata;
			struct sock_extended_err *aee = adata;
			if (!sock_ee_expect_eq(eee, aee, i, error))
				return false;
		} else if (acm->cmsg_level == SOL_SOCKET &&
			   acm->cmsg_type == SCM_TIMESTAMPING) {
			struct scm_timestamping *ets = edata;
			struct scm_timestamping *ats = adata;
			if (!scm_timestamping_expect_eq(state, ets, ats, i,
							error))
				return false;
		} else if (acm->cmsg_level == SOL_SOCKET &&
			   acm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS) {
			if (!scm_opt_stats_expect_eq(state, edata, adata,
						     acm->cmsg_len - hdr_len,
						     i, error))
				return false;
		} else if (memcmp((char *)adata,  /* byte-to-byte */
				  (char *)edata, acm->cmsg_len - hdr_len)) {
			asprintf(error,
				 "Bad data in cmsg %d: expected=%s actual=%s",
				 i, (char *)edata, (char *)adata);
			return false;
		}
	}

	if (!acm && !ecm)
		return true;
	if (acm && !ecm) {
		asprintf(error, "received more than %d cmsgs", i);
		return false;
	}
	if (!acm && ecm) {
		asprintf(error, "received only %d cmsgs", i);
		return false;
	}
	asprintf(error, "cmsgs do not match");
	return false;
}

/* Free all the space used by the given msghdr. */
static void msghdr_free(struct msghdr *msg, size_t iov_len)
{
	if (msg == NULL)
		return;

	free(msg->msg_name);
	iovec_free(msg->msg_iov, iov_len);
	free(msg->msg_control);
}

/* Allocate and fill in a msghdr described by the given expression. */
static int msghdr_new(struct expression *expression,
		      struct msghdr **msg_ptr, size_t *iov_len_ptr,
		      char **error)
{
	int status = STATUS_ERR;
	s32 s32_val = 0;
	struct msghdr_expr *msg_expr;	/* input expression from script */
	socklen_t name_len = sizeof(struct sockaddr_storage);
	struct msghdr *msg = NULL;	/* live output */

	if (check_type(expression, EXPR_MSGHDR, error))
		goto error_out;

	msg_expr = expression->value.msghdr;

	msg = calloc(1, sizeof(struct msghdr));

	if (msg_expr->msg_name != NULL) {
		assert(msg_expr->msg_name->type == EXPR_ELLIPSIS);
		msg->msg_name = calloc(1, name_len);
	}

	if (msg_expr->msg_namelen != NULL) {
		assert(msg_expr->msg_namelen->type == EXPR_ELLIPSIS);
		msg->msg_namelen = name_len;
	}

	if (msg_expr->msg_iov != NULL) {
		if (iovec_new(msg_expr->msg_iov, &msg->msg_iov, iov_len_ptr,
			      error))
			goto error_out;
	}

	if (msg_expr->msg_iovlen != NULL) {
		if (get_s32(msg_expr->msg_iovlen, &s32_val, error))
			goto error_out;
		msg->msg_iovlen = s32_val;
	}

	if (msg->msg_iovlen != *iov_len_ptr) {
		asprintf(error,
			 "msg_iovlen %d does not match %d-element iovec array",
			 (int)msg->msg_iovlen, (int)*iov_len_ptr);
		goto error_out;
	}

	if (msg_expr->msg_control != NULL) {
		if (cmsg_new(msg_expr->msg_control, msg, error))
			goto error_out;
	}

	if (msg_expr->msg_flags != NULL) {
		if (get_s32(msg_expr->msg_flags, &s32_val, error))
			goto error_out;
		msg->msg_flags = s32_val;
	}

	status = STATUS_OK;

error_out:
	*msg_ptr = msg;
	return status;
}

/* Allocate and fill in a pollfds array described by the given
 * fds_expression. Return STATUS_OK if the expression is a valid
 * pollfd struct array. Otherwise fill in the error with a
 * human-readable error message and return STATUS_ERR.
 */
static int pollfds_new(struct state *state,
		       struct expression *fds_expression,
		       struct pollfd **fds_ptr, size_t *fds_len_ptr,
		       char **error)
{
	int status = STATUS_ERR;
	int i;
	struct expression_list *list;	/* input expression from script */
	size_t fds_len = 0;
	struct pollfd *fds = NULL;	/* live output */

	if (check_type(fds_expression, EXPR_LIST, error))
		goto error_out;

	list = fds_expression->value.list;

	fds_len = expression_list_length(list);
	fds = calloc(fds_len, sizeof(struct pollfd));

	for (i = 0; i < fds_len; ++i, list = list->next) {
		struct pollfd_expr *fds_expr;

		if (check_type(list->expression, EXPR_POLLFD, error))
			goto error_out;

		fds_expr = list->expression->value.pollfd;

		if (check_type(fds_expr->fd, EXPR_INTEGER, error))
			goto error_out;
		if (check_type(fds_expr->events, EXPR_INTEGER, error))
			goto error_out;
		if (check_type(fds_expr->revents, EXPR_INTEGER, error))
			goto error_out;

		if (to_live_fd(state, fds_expr->fd->value.num,
			       &fds[i].fd, error))
			goto error_out;

		fds[i].events = fds_expr->events->value.num;
		fds[i].revents = fds_expr->revents->value.num;
	}

	status = STATUS_OK;

error_out:
	*fds_ptr = fds;
	*fds_len_ptr = fds_len;
	return status;
}

/* Check the results of a poll() system call: check that the output
 * revents fields in the fds array match those in the script. Return
 * STATUS_OK if they match. Otherwise fill in the error with a
 * human-readable error message and return STATUS_ERR.
 */
static int pollfds_check(struct expression *fds_expression,
			 const struct pollfd *fds, size_t fds_len,
			 char **error)
{
	struct expression_list *list;	/* input expression from script */
	int i;

	assert(fds_expression->type == EXPR_LIST);
	list = fds_expression->value.list;

	for (i = 0; i < fds_len; ++i, list = list->next) {
		struct pollfd_expr *fds_expr;
		int expected_revents, actual_revents;

		assert(list->expression->type == EXPR_POLLFD);
		fds_expr = list->expression->value.pollfd;

		assert(fds_expr->fd->type == EXPR_INTEGER);
		assert(fds_expr->events->type == EXPR_INTEGER);
		assert(fds_expr->revents->type == EXPR_INTEGER);

		expected_revents = fds_expr->revents->value.num;
		actual_revents = fds[i].revents;
		if (actual_revents != expected_revents) {
			char *expected_revents_string =
				flags_to_string(poll_flags,
							expected_revents);
			char *actual_revents_string =
				flags_to_string(poll_flags,
							actual_revents);
			asprintf(error,
				 "Expected revents of %s but got %s "
				 "for pollfd %d",
				 expected_revents_string,
				 actual_revents_string,
				 i);
			free(expected_revents_string);
			free(actual_revents_string);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

/* For blocking system calls, give up the global lock and wake the
 * main thread so it can continue test execution. Callers should call
 * this function immediately before calling a system call in order to
 * release the global lock immediately before a system call that the
 * script expects to block.
 */
static void begin_syscall(struct state *state, struct syscall_spec *syscall)
{
	if (is_blocking_syscall(syscall)) {
		assert(state->syscalls->state == SYSCALL_ENQUEUED);
		state->syscalls->state = SYSCALL_RUNNING;
		run_unlock(state);
		DEBUGP("syscall thread: begin_syscall signals dequeued\n");
		if (pthread_cond_signal(&state->syscalls->dequeued) != 0)
			die_perror("pthread_cond_signal");
	}
}

/* Verify that the system call returned the expected result code and
 * errno value. Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message. Callers should call this function
 * immediately after returning from a system call in order to immediately
 * re-grab the global lock if this is a blocking call.
 */
enum result_check_t {
	CHECK_EXACT,		/* check that result matches exactly */
	CHECK_FD,		/* check that result is fd or matching error */
};
static int end_syscall(struct state *state, struct syscall_spec *syscall,
		       enum result_check_t mode, int actual, char **error)
{
	int actual_errno = errno;	/* in case we clobber this later */
	s32 expected = 0;

	/* For blocking calls, advance state and reacquire the global lock. */
	if (is_blocking_syscall(syscall)) {
		s64 live_end_usecs = now_usecs(state);
		DEBUGP("syscall thread: end_syscall grabs lock\n");
		run_lock(state);
		state->syscalls->live_end_usecs = live_end_usecs;
		assert(state->syscalls->state == SYSCALL_RUNNING);
		state->syscalls->state = SYSCALL_DONE;
	}
	if (state->config->verbose) {
		printf("%s syscall: %9.6f\n", syscall->name,
		       usecs_to_secs(now_usecs(state)));
	}


	/* Compare actual vs expected return value */
	if (get_s32(syscall->result, &expected, error))
		return STATUS_ERR;
	if (mode == CHECK_FD && expected >= 0) {
		if (actual < 0) {
			asprintf(error,
				 "Expected non-negative result but got %d "
				 "with errno %d (%s)",
				 actual, actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		}
	} else if (mode == CHECK_FD || mode == CHECK_EXACT) {
		if (actual != expected) {
			asprintf(error,
				 "Expected result %d but got %d "
				 "with errno %d (%s)",
				 expected,
				 actual, actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		}
	} else {
		assert(!"bad mode");
	}

	/* Compare actual vs expected errno */
	if (syscall->error != NULL) {
		s64 expected_errno = 0;
		if (symbol_to_int(syscall->error->errno_macro,
					  &expected_errno, error))
			return STATUS_ERR;
		if (actual_errno != expected_errno) {
			asprintf(error,
				 "Expected errno %d (%s) but got %d (%s)",
				 (int)expected_errno, strerror(expected_errno),
				 actual_errno, strerror(actual_errno));
			return STATUS_ERR;
		}
	}

	return STATUS_OK;
}

/* Return a pointer to the fd with the given script fd, or NULL. */
static struct fd_state *find_by_script_fd(
	struct state *state, int script_fd)
{
	struct fd_state *fd = NULL;

	for (fd = state->fds; fd != NULL; fd = fd->next)
		if (!fd->is_closed && (fd->script_fd == script_fd)) {
			assert(fd->live_fd >= 0);
			assert(fd->script_fd >= 0);
			return fd;
		}
	return NULL;
}

/* Return a pointer to the fd with the given live fd, or NULL. */
static struct fd_state *find_by_live_fd(
	struct state *state, int live_fd)
{
	struct fd_state *fd = NULL;

	for (fd = state->fds; fd != NULL; fd = fd->next)
		if (!fd->is_closed & (fd->live_fd == live_fd)) {
			assert(fd->live_fd >= 0);
			assert(fd->script_fd >= 0);
			return fd;
		}
	return NULL;
}

/* Find the live fd corresponding to the fd in a script. Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int to_live_fd(struct state *state, int script_fd, int *live_fd,
		      char **error)
{
	struct fd_state *fd = find_by_script_fd(state, script_fd);

	if (fd != NULL) {
		*live_fd = fd->live_fd;
		return STATUS_OK;
	} else {
		*live_fd = -1;
		asprintf(error, "unable to find fd with script fd %d",
			 script_fd);
		return STATUS_ERR;
	}
}

/* Look for conflicting fds. Should not happen if the script is valid and this
 * program is bug-free.
 */
static int check_duplicate_fd(struct state *state, int script_fd, int live_fd,
			      char **error)
{
	if (find_by_script_fd(state, script_fd)) {
		asprintf(error, "duplicate fd %d in script",
			 script_fd);
		return STATUS_ERR;
	}
	if (find_by_live_fd(state, live_fd)) {
		asprintf(error, "duplicate live fd %d", live_fd);
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Parse the argument with the given index
 * Set *is_null to true if arg is 0 (NULL)
 * Set *is_null to false if arg is ellipsis (...)
 * Return error if arg is neither of the above
 */
static int buffer_arg(struct expression_list *args, int index,
		      bool *is_null, char **error)
{
	struct expression *expression = get_arg(args, index, error);

	if (expression && expression->type == EXPR_ELLIPSIS) {
		*is_null = false;
		return STATUS_OK;
	}
	if (expression && expression->type == EXPR_INTEGER &&
	    expression->value.num == 0) {
		*is_null = true;
		return STATUS_OK;
	}
	asprintf(error, "Expected ... or NULL for buffer");
	return STATUS_ERR;
}

static void *alloc_buffer(bool is_null, int count, bool set_zero)
{
	void *buf;

	if (is_null)
		return NULL;

	if (set_zero)
		buf = calloc(count, 1);
	else
		buf = malloc(count);
	assert(buf != NULL);
	return buf;
}

/****************************************************************************
 * Here we have the "backend" post-processing and pre-processing that
 * we perform after and/or before each of the system calls that
 * we support...
 */

/* The app called open(). Create a struct file to track the new file.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_open(struct state *state, int script_fd, int live_fd,
			      char **error)
{
	struct file *file = NULL;

	if (check_duplicate_fd(state, script_fd, live_fd, error))
		return STATUS_ERR;

	file = file_new(state);
	file->fd.script_fd	= script_fd;
	file->fd.live_fd	= live_fd;
	return STATUS_OK;
}

/* The app called socket() in the script and we did a live reenactment
 * socket() call. Create a struct socket to track the new socket.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_socket(struct state *state, int address_family, int type,
			      int protocol, int script_fd, int live_fd,
			      char **error)
{
	/* Validate fd values. */
	if (script_fd < 0) {
		asprintf(error, "invalid socket fd %d in script", script_fd);
		return STATUS_ERR;
	}
	if (live_fd < 0) {
		asprintf(error, "invalid live socket fd %d", live_fd);
		return STATUS_ERR;
	}

	if (check_duplicate_fd(state, script_fd, live_fd, error))
		return STATUS_ERR;

	/* These fd values are kosher, so store them. */
	struct socket *socket = socket_new(state);
	socket->state		= SOCKET_NEW;
	socket->address_family	= address_family;
	socket->type		= type;
	socket->protocol	= protocol;
	socket->fd.script_fd	= script_fd;
	socket->fd.live_fd	= live_fd;

	/* Any later packets in the test script will now be mapped here. */
	state->socket_under_test = socket;

	DEBUGP("socket() creating new socket: script_fd: %d live_fd: %d\n",
	       socket->fd.script_fd, socket->fd.live_fd);
	return STATUS_OK;
}

/* Handle a close() call for the given fd.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_close(struct state *state, int script_fd,
			     int live_fd, char **error)
{
	struct fd_state *fd = find_by_script_fd(state, script_fd);
	if ((fd == NULL) || (fd->live_fd != live_fd))
		goto error_out;

	fd->is_closed = true;
	return STATUS_OK;

error_out:
	asprintf(error,
		 "unable to find fd with script fd %d and live fd %d",
		 script_fd, live_fd);
	return STATUS_ERR;
}

/* Fill in the live_addr and live_addrlen for a bind() call.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_bind(struct state *state,
			    struct sockaddr *live_addr,
			    socklen_t *live_addrlen, char **error)
{
	DEBUGP("run_syscall_bind\n");

	/* Fill in the live address we want to bind to */
	ip_to_sockaddr(&state->config->live_bind_ip,
		       state->config->live_bind_port,
		       live_addr, live_addrlen);

	return STATUS_OK;
}

/* Handle a listen() call for the given socket.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_listen(struct state *state, int script_fd,
			      int live_fd, char **error)
{
	struct socket *socket = NULL;

	socket = fd_to_socket(find_by_script_fd(state, script_fd));
	if (socket != NULL) {
		assert(socket->fd.script_fd == script_fd);
		assert(socket->fd.live_fd == live_fd);
		socket->state = SOCKET_PASSIVE_LISTENING;
		return STATUS_OK;
	} else {
		asprintf(error, "unable to find socket with script fd %d",
			 script_fd);
		return STATUS_ERR;
	}
}

/* Handle an accept() call creating a new socket with the given file
 * descriptors.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and
 * sets error message.
 */
static int run_syscall_accept(struct state *state,
			      int script_accepted_fd,
			      int live_accepted_fd,
			      struct sockaddr *live_addr,
			      int live_addrlen, char **error)
{
	struct socket *socket = NULL;
	struct fd_state *fd = NULL;
	struct ip_address ip;
	u16 port = 0;
	DEBUGP("run_syscall_accept\n");

	/* Parse the sockaddr into a nice multi-protocol ip_address struct. */
	ip_from_sockaddr(live_addr, live_addrlen, &ip, &port);

	/* For ipv4-mapped-ipv6: if ip is IPv4-mapped IPv6, map it to IPv4. */
	if (ip.address_family == AF_INET6) {
		struct ip_address ipv4;
		if (ipv6_map_to_ipv4(ip, &ipv4) == STATUS_OK)
			ip = ipv4;
	}

	for (fd = state->fds; fd != NULL; fd = fd->next) {
		if (fd->ops->type != FD_SOCKET)
			continue;
		socket = fd_to_socket(fd);
		if (DEBUG_LOGGING) {
			char remote_string[ADDR_STR_LEN];
			DEBUGP("socket state=%d script addr: %s:%d\n",
			       socket->state,
			       ip_to_string(&socket->script.remote.ip,
					    remote_string),
			       socket->script.remote.port);
		}

		if ((socket->state == SOCKET_PASSIVE_SYNACK_SENT) ||  /* TFO */
		    (socket->state == SOCKET_PASSIVE_SYNACK_ACKED)) {
			assert(is_equal_ip(&socket->live.remote.ip, &ip));
			assert(is_equal_port(socket->live.remote.port,
					     htons(port)));
			socket->fd.script_fd	= script_accepted_fd;
			socket->fd.live_fd	= live_accepted_fd;
			return STATUS_OK;
		}
	}

	if (!state->config->is_wire_client) {
		asprintf(error, "unable to find socket matching accept() call");
		return STATUS_ERR;
	}

	/* If this is a wire client, then this process just
	 * sees the system call action for this socket. Create a child
	 * passive socket for this accept call, and fill in what we
	 * know about the socket. Any further packets in the test
	 * script will be directed to this child socket.
	 */
	socket = socket_new(state);
	state->socket_under_test = socket;
	assert(socket->state == SOCKET_INIT);
	socket->address_family		= ip.address_family;

	socket->live.remote.ip		= ip;
	socket->live.remote.port	= port;
	socket->live.local.ip		= state->config->live_local_ip;
	socket->live.local.port		= htons(state->config->live_bind_port);

	socket->fd.live_fd		= live_accepted_fd;
	socket->fd.script_fd		= script_accepted_fd;

	if (DEBUG_LOGGING) {
		char local_string[ADDR_STR_LEN];
		char remote_string[ADDR_STR_LEN];
		DEBUGP("live: local: %s.%d\n",
		       ip_to_string(&socket->live.local.ip, local_string),
		       ntohs(socket->live.local.port));
		DEBUGP("live: remote: %s.%d\n",
		       ip_to_string(&socket->live.remote.ip, remote_string),
		       ntohs(socket->live.remote.port));
	}
	return STATUS_OK;
}

/* Handle an connect() or sendto() call initiating a connect to a
 * remote address. Fill in the live_addr and live_addrlen for the live
 * connect(). Returns STATUS_OK on success; on failure returns
 * STATUS_ERR and sets error message.
 */
static int run_syscall_connect(struct state *state,
			       int script_fd,
			       bool must_be_new_socket,
			       struct sockaddr *live_addr,
			       socklen_t *live_addrlen,
			       int sa_family,
			       char **error)
{
	struct socket *socket	= NULL;
	DEBUGP("run_syscall_connect\n");

	if (sa_family != -1) {
		sa_family_t sa_fa = (sa_family_t) sa_family;
		memset(live_addr, 0, sizeof(*live_addr));
		live_addr->sa_family = sa_fa;
	} else {
		/* Fill in the live address we want to connect to */
		ip_to_sockaddr(&state->config->live_connect_ip,
			       state->config->live_connect_port,
			       live_addr, live_addrlen);
	}

	socket = fd_to_socket(find_by_script_fd(state, script_fd));
	assert(socket != NULL);
	/* Reset socket state to NEW if we are about to disconnect
	 * the socket so that later connect will succeed.
	 */
	if (live_addr->sa_family == AF_UNSPEC) {
		socket->state = SOCKET_NEW;
		return STATUS_OK;
	}

	if (socket->state != SOCKET_NEW) {
		if (must_be_new_socket) {
			asprintf(error, "socket is not new");
			return STATUS_ERR;
		} else {
			return STATUS_OK;
		}
	}

	socket->state				= SOCKET_ACTIVE_CONNECTING;
	ip_reset(&socket->script.remote.ip);
	ip_reset(&socket->script.local.ip);
	socket->script.remote.port		= 0;
	socket->script.local.port		= 0;
	socket->live.remote.ip   = state->config->live_remote_ip;
	socket->live.remote.port = htons(state->config->live_connect_port);
	DEBUGP("success: setting socket to state %d\n", socket->state);
	return STATUS_OK;
}

/* The app called epoll_create(). Create a struct epoll to track this new
 * epoll event.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int run_syscall_epoll_create(struct state *state, int epfd_script,
				    int epfd_live, char **error)
{
	struct epoll *epoll = NULL;

	if (check_duplicate_fd(state, epfd_script, epfd_live, error))
		return STATUS_ERR;

	epoll = epoll_new(state);
	epoll->fd.script_fd = epfd_script;
	epoll->fd.live_fd = epfd_live;
	return STATUS_OK;
}

/* The app called pipe(). Create a struct pipe to track this new pipe event.
 * Note: both pfd_script and pfd_live point to 2-integer arrays.
 * Returns STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int run_syscall_pipe(struct state *state, int *pfd_script, int *pfd_live,
			    char **error)
{
	struct pipe *pipe = NULL;
	int i;

	for (i = 0; i < 2; i++) {
		if (check_duplicate_fd(state, pfd_script[i],
				       pfd_live[i], error))
			return STATUS_ERR;
	}

	for (i = 0; i < 2; i++) {
		pipe = pipe_new(state);
		pipe->fd.script_fd = pfd_script[i];
		pipe->fd.live_fd = pfd_live[i];
	}
	return STATUS_OK;
}

/****************************************************************************
 * Here we have the parsing and invocation of the system calls that
 * we support...
 */

static int syscall_socket(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int domain = state->config->socket_domain;
	int type, protocol, live_fd, script_fd, result;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;

	if (ellipsis_arg(args, 0, error))
		if (s32_arg(args, 0, &domain, error))
			return STATUS_ERR;

	if (s32_arg(args, 1, &type, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &protocol, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.socket(
				state->so_instance->ifc.userdata,
				domain, type, protocol);
	} else {
		result = socket(domain, type, protocol);
	}

	if (end_syscall(state, syscall, CHECK_FD, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_fd = result;
		if (get_s32(syscall->result, &script_fd, error))
			return STATUS_ERR;
		if (run_syscall_socket(state, domain, type, protocol,
				       script_fd, live_fd, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_bind(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;
	if (run_syscall_bind(
		    state,
		    (struct sockaddr *)&live_addr, &live_addrlen, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.bind(
				state->so_instance->ifc.userdata,
				live_fd, (struct sockaddr *)&live_addr,
				live_addrlen);
	} else {
		result = bind(live_fd, (struct sockaddr *)&live_addr,
			      live_addrlen);
	}

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_listen(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, backlog, result;

	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &backlog, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.listen(
				state->so_instance->ifc.userdata,
				live_fd, backlog);
	} else {
		result = listen(live_fd, backlog);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	if (run_syscall_listen(state, script_fd, live_fd, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_accept(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, live_accepted_fd, script_accepted_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.accept(
				state->so_instance->ifc.userdata,
				live_fd, (struct sockaddr *)&live_addr,
				&live_addrlen);
	} else {
		result = accept(live_fd, (struct sockaddr *)&live_addr,
				&live_addrlen);
	}

	if (end_syscall(state, syscall, CHECK_FD, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_accepted_fd = result;
		if (get_s32(syscall->result, &script_accepted_fd, error))
			return STATUS_ERR;
		if (run_syscall_accept(
			    state, script_accepted_fd, live_accepted_fd,
			    (struct sockaddr *)&live_addr, live_addrlen,
			    error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_connect(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	int sa_family = -1;
	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 1, error) &&
	    s32_arg(args, 1, &sa_family, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 2, error))
		return STATUS_ERR;

	if (run_syscall_connect(
		    state, script_fd, false,
		    (struct sockaddr *)&live_addr, &live_addrlen,
		    sa_family, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.connect(
				state->so_instance->ifc.userdata,
				live_fd, (struct sockaddr *)&live_addr,
				live_addrlen);
	} else {
		result = connect(live_fd, (struct sockaddr *)&live_addr,
				 live_addrlen);
	}

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_read(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, result;
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	buf = alloc_buffer(is_null, count, false);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.read(
				state->so_instance->ifc.userdata,
				live_fd, buf, count);
	} else {
		result = read(live_fd, buf, count);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_readv(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, iov_count, result;
	struct expression *iov_expression = NULL;
	struct iovec *iov = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	iov_expression = get_arg(args, 1, error);
	if (iov_expression == NULL)
		goto error_out;
	if (iovec_new(iov_expression, &iov, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &iov_count, error))
		goto error_out;

	if (iov_count != iov_len) {
		asprintf(error,
			 "iov_count %d does not match %d-element iovec array",
			 iov_count, (int)iov_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.readv(
				state->so_instance->ifc.userdata,
				live_fd, iov, iov_count);
	} else {
		result = readv(live_fd, iov, iov_count);
	}

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

error_out:
	iovec_free(iov, iov_len);
	return status;
}

static int syscall_recv(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	buf = alloc_buffer(is_null, count, false);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.recv(
				state->so_instance->ifc.userdata,
				live_fd, buf, count, flags);
	} else {
		result = recv(live_fd, buf, count, flags);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_recvfrom(struct state *state, struct syscall_spec *syscall,
			    struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 4, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 5, error))
		return STATUS_ERR;
	buf = alloc_buffer(is_null, count, false);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.recvfrom(
				state->so_instance->ifc.userdata,
				live_fd, buf, count, flags,
				(struct sockaddr *)&live_addr, &live_addrlen);
	} else {
		result = recvfrom(live_fd, buf, count, flags,
				  (struct sockaddr *)&live_addr, &live_addrlen);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_recvmsg(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, flags, result;
	struct expression *msg_expression = NULL;
	struct msghdr *msg = NULL, *expected_msg = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;
	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	msg_expression = get_arg(args, 1, error);
	if (msg_expression == NULL)
		goto error_out;
	if (msghdr_new(msg_expression, &msg, &iov_len, error))
		goto error_out;
	if (msghdr_new(msg_expression, &expected_msg, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &flags, error))
		goto error_out;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.recvmsg(
				state->so_instance->ifc.userdata,
				live_fd, msg, flags);
	} else {
		result = recvmsg(live_fd, msg, flags);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (msg->msg_flags != expected_msg->msg_flags) {
		asprintf(error, "Expected msg_flags 0x%08X but got 0x%08X",
			 expected_msg->msg_flags, msg->msg_flags);
		goto error_out;
	}

	if (!cmsg_expect_eq(state, expected_msg, msg, error))
		goto error_out;

	status = STATUS_OK;

error_out:
	msghdr_free(msg, iov_len);
	msghdr_free(expected_msg, iov_len);
	return status;
}

static int syscall_write(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, result;
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	buf = alloc_buffer(is_null, count, true);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.write(
				state->so_instance->ifc.userdata,
				live_fd, buf, count);
	} else {
		result = write(live_fd, buf, count);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_writev(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, iov_count, result;
	struct expression *iov_expression = NULL;
	struct iovec *iov = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	iov_expression = get_arg(args, 1, error);
	if (iov_expression == NULL)
		goto error_out;
	if (iovec_new(iov_expression, &iov, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &iov_count, error))
		goto error_out;

	if (iov_count != iov_len) {
		asprintf(error,
			 "iov_count %d does not match %d-element iovec array",
			 iov_count, (int)iov_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.writev(
				state->so_instance->ifc.userdata,
				live_fd, iov, iov_count);
	} else {
		result = writev(live_fd, iov, iov_count);
	}

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

error_out:
	iovec_free(iov, iov_len);
	return status;
}

static int syscall_send(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	buf = alloc_buffer(is_null, count, true);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.send(
				state->so_instance->ifc.userdata,
				live_fd, buf, count, flags);
	} else {
		result = send(live_fd, buf, count, flags);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	sendcall_free(state, buf);

	return status;
}

static int syscall_sendto(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	struct socket *socket = NULL;
	char *buf = NULL;
	int sa_family = -1;
	bool is_null;

	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 4, error) &&
	    s32_arg(args, 4, &sa_family, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 5, error))
		return STATUS_ERR;

	/* ICMP sockets need special handling. */
	socket = fd_to_socket(find_by_script_fd(state, script_fd));
	if (socket != NULL && socket->type == SOCK_DGRAM &&
	    ((socket->address_family == AF_INET &&
	      socket->protocol == IPPROTO_ICMP) ||
	     (socket->address_family == AF_INET6 &&
	      socket->protocol == IPPROTO_ICMPV6)))
		return syscall_icmp_sendto(state, syscall, args, error);

	if (run_syscall_connect(
		    state, script_fd, false,
		    (struct sockaddr *)&live_addr, &live_addrlen, sa_family,
		    error))
		return STATUS_ERR;

	buf = alloc_buffer(is_null, count, true);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.sendto(
				state->so_instance->ifc.userdata,
				live_fd, buf, count, flags,
				(struct sockaddr *)&live_addr, live_addrlen);
	} else {
		result = sendto(live_fd, buf, count, flags,
				(struct sockaddr *)&live_addr, live_addrlen);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	sendcall_free(state, buf);

	return status;
}

static int syscall_sendmsg(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int live_fd, script_fd, flags, result;
	struct expression *msg_expression = NULL;
	struct msghdr *msg = NULL;
	size_t iov_len = 0;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;
	if (s32_arg(args, 0, &script_fd, error))
		goto error_out;
	if (to_live_fd(state, script_fd, &live_fd, error))
		goto error_out;

	msg_expression = get_arg(args, 1, error);
	if (msg_expression == NULL)
		goto error_out;
	if (msghdr_new(msg_expression, &msg, &iov_len, error))
		goto error_out;

	if (s32_arg(args, 2, &flags, error))
		goto error_out;

	if ((msg->msg_name != NULL) &&
	    run_syscall_connect(state, script_fd, false,
				msg->msg_name, &msg->msg_namelen, -1, error))
		goto error_out;
	if (msg->msg_flags != 0) {
		asprintf(error, "sendmsg ignores msg_flags field in msghdr");
		goto error_out;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.sendmsg(
				state->so_instance->ifc.userdata,
				live_fd, msg, flags);
	} else {
		result = sendmsg(live_fd, msg, flags);
	}

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

error_out:
	if (sendcall_may_free(state))
		msghdr_free(msg, iov_len);
	return status;
}

/*
 * Send echo request using ICMP socket.
 * Note: Kernel will reject and fail the sendto() call if the data sent does not
 * have room for a proper ICMP header. And ICMP type must be 8 (ICMP_ECHO) and
 * ICMP code must be 0.
 */
static int syscall_icmp_sendto(struct state *state, struct syscall_spec *syscall,
				struct expression_list *args, char **error)
{
	int live_fd, script_fd, count, flags, result;
	struct sockaddr_storage live_addr;
	socklen_t live_addrlen = sizeof(live_addr);
	char *buf = NULL;
	bool is_null;

	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (buffer_arg(args, 1, &is_null, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &count, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &flags, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 4, error))
		return STATUS_ERR;
	if (ellipsis_arg(args, 5, error))
		return STATUS_ERR;

	if (run_syscall_connect(
		    state, script_fd, false,
		    (struct sockaddr *)&live_addr, &live_addrlen, -1, error))
		return STATUS_ERR;

	buf = alloc_buffer(is_null, count, true);
	if (state->config->wire_protocol == AF_INET &&
	    count >= sizeof(struct icmpv4)) {
		struct icmpv4 *icmp = (struct icmpv4 *)buf;
		icmp->type = ICMP_ECHO;
	} else if (state->config->wire_protocol == AF_INET6 &&
		   count >= sizeof(struct icmpv6)) {
		struct icmpv6 *icmpv6 = (struct icmpv6 *)buf;
		icmpv6->type = ICMPV6_ECHO_REQUEST;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.sendto(
				state->so_instance->ifc.userdata,
				live_fd, buf, count, flags,
				(struct sockaddr *)&live_addr, live_addrlen);
	} else {
		result = sendto(live_fd, buf, count, flags,
				(struct sockaddr *)&live_addr, live_addrlen);
	}

	int status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	free(buf);
	return status;
}

static int syscall_fcntl(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, command, result;

	/* fcntl is an odd system call - it can take either 2 or 3 args. */
	int actual_arg_count = get_arg_count(args);
	if ((actual_arg_count != 2) && (actual_arg_count != 3)) {
		asprintf(error, "fcntl expected 2-3 args but got %d",
			 actual_arg_count);
		return STATUS_ERR;
	}

	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &command, error))
		return STATUS_ERR;

	if (actual_arg_count == 2) {
		begin_syscall(state, syscall);

		if (state->so_instance) {
			result = state->so_instance->ifc.fcntl(
					state->so_instance->ifc.userdata,
					live_fd, command);
		} else {
			result = fcntl(live_fd, command);
		}
	} else if (actual_arg_count == 3) {
		s32 arg;
		if (s32_arg(args, 2, &arg, error))
			return STATUS_ERR;
		begin_syscall(state, syscall);

		if (state->so_instance) {
			result = state->so_instance->ifc.fcntl(
					state->so_instance->ifc.userdata,
					live_fd, command, arg);
		} else {
			result = fcntl(live_fd, command, arg);
		}
	} else {
		assert(0);	/* not reached */
	}

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_ioctl(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, command, result;

	/* ioctl is an odd system call - it can take either 2 or 3 args. */
	int actual_arg_count = get_arg_count(args);
	if ((actual_arg_count != 2) && (actual_arg_count != 3)) {
		asprintf(error, "ioctl expected 2-3 args but got %d",
			 actual_arg_count);
		return STATUS_ERR;
	}

	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &command, error))
		return STATUS_ERR;

	if (actual_arg_count == 2) {
		begin_syscall(state, syscall);

		if (state->so_instance) {
			result = state->so_instance->ifc.ioctl(
					state->so_instance->ifc.userdata,
					live_fd, command);
		} else {
			result = ioctl(live_fd, command);
		}

		return end_syscall(state, syscall, CHECK_EXACT, result, error);

	} else if (actual_arg_count == 3) {
		s32 script_optval, live_optval;

		if (s32_bracketed_arg(args, 2, &script_optval, error))
			return STATUS_ERR;

		begin_syscall(state, syscall);

		if (state->so_instance) {
			result = state->so_instance->ifc.ioctl(
					state->so_instance->ifc.userdata,
					live_fd, command, &live_optval);
		} else {
			result = ioctl(live_fd, command, &live_optval);
		}

		if (end_syscall(state, syscall, CHECK_EXACT, result, error))
			return STATUS_ERR;

		if (live_optval != script_optval) {
			asprintf(error,
				 "Bad ioctl optval: expected: %d actual: %d",
				 (int)script_optval, (int)live_optval);
			return STATUS_ERR;
		}

		return STATUS_OK;
	} else {
		assert(0);	/* not reached */
	}
	return STATUS_ERR;
}

static int syscall_close(struct state *state, struct syscall_spec *syscall,
			 struct expression_list *args, char **error)
{
	int live_fd, script_fd, result;
	if (check_arg_count(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.close(
				state->so_instance->ifc.userdata,
				live_fd);
	} else {
		result = close(live_fd);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	if (run_syscall_close(state, script_fd, live_fd, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_shutdown(struct state *state, struct syscall_spec *syscall,
			    struct expression_list *args, char **error)
{
	int live_fd, script_fd, how, result;
	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &how, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.shutdown(
				state->so_instance->ifc.userdata,
				live_fd, how);
	} else {
		result = shutdown(live_fd, how);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_getsockopt(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args, char **error)
{
	int script_fd, live_fd, level, optname, result;
	void *live_optval = NULL, *script_optval = NULL;
	char *live_optval_pretty = NULL, *script_optval_pretty = NULL;
	s32 script_optlen, script_optval_s32;
	socklen_t live_optlen;
	struct expression *val_expression = NULL;
	int status = STATUS_ERR;

	if (check_arg_count(args, 5, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &level, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &optname, error))
		return STATUS_ERR;
	val_expression = get_arg(args, 3, error);
	if (val_expression == NULL)
		return STATUS_ERR;
	if (s32_bracketed_arg(args, 4, &script_optlen, error))
		return STATUS_ERR;

	/* Allocate space for getsockopt output. */
	live_optlen = script_optlen;
	live_optval = calloc(1, live_optlen + 1);
	assert(live_optval != NULL);

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.getsockopt(
				state->so_instance->ifc.userdata,
				live_fd, level, optname,
				live_optval, &live_optlen);
	} else {
		result = getsockopt(live_fd, level, optname,
				    live_optval, &live_optlen);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if ((int)live_optlen != script_optlen) {
		asprintf(error,
			 "Bad getsockopt optlen: expected: %d actual: %d",
			 (int)script_optlen, (int)live_optlen);
		goto error_out;
	}

	if (val_expression->type == EXPR_STRING) {
		script_optval = val_expression->value.buf.ptr;
		script_optval_pretty =
			to_printable_string(
				val_expression->value.buf.ptr,
				val_expression->value.buf.len);
		live_optval_pretty =
			to_printable_string(live_optval, live_optlen);

		if (script_optlen != val_expression->value.buf.len) {
			asprintf(error,
				 "Bad getsockopt optval: "
				 "expected optlen (%d bytes) does not match "
				 "length of expected optval string '%s' "
				 "(%d bytes)",
				 script_optlen,
				 script_optval_pretty,
				 (int)val_expression->value.buf.len);
			goto error_out;
		}

		if (memcmp(live_optval, script_optval, script_optlen) != 0) {
			asprintf(error,
				 "Bad getsockopt optval: "
				 "expected: '%s' actual: '%s'",
				 script_optval_pretty, live_optval_pretty);
			goto error_out;
		}
	} else if (val_expression->type == EXPR_LIST) {
		if (script_optlen != 4) {
			asprintf(error, "Unsupported getsockopt optlen: %d",
				 (int)script_optlen);
			goto error_out;
		}

		if (s32_bracketed_arg(args, 3, &script_optval_s32, error))
			goto error_out;

		if (*(s32 *)live_optval != script_optval_s32) {
			asprintf(error,
				 "Bad getsockopt optval: "
				 "expected: %d actual: %d",
				 script_optval_s32, *(s32 *)live_optval);
			goto error_out;
		}
	} else if (val_expression->type == EXPR_GRE) {
		struct gre *live_gre = (struct gre *)live_optval;
		struct gre *script_gre = &val_expression->value.gre;

		if (script_optlen != sizeof(struct gre)) {
			asprintf(error, "Unsupported getsockopt optlen: %d",
				 (int)script_optlen);
			goto error_out;
		}

		if (live_gre->flags != script_gre->flags ||
		    live_gre->be16[0] != script_gre->be16[0] ||
		    live_gre->be16[1] != script_gre->be16[1] ||
		    live_gre->be32[1] != script_gre->be32[1] ||
		    live_gre->be32[2] != script_gre->be32[2]) {
			asprintf(error, "Bad getsockopt optval.");
			/* TODO: Populate this with a GRE header dump. */
			goto error_out;
		}
	} else if (val_expression->type == EXPR_IN6_ADDR) {
		struct in6_addr *live_ipv6 = (struct in6_addr *)live_optval;
		struct in6_addr *script_ipv6 = &val_expression->value.address_ipv6;

		if (script_optlen != sizeof(struct in6_addr)) { // != 16
			asprintf(error, "Unsupported getsockopt optlen: %d",
				 (int)script_optlen);
			goto error_out;
		}

		if (memcmp(live_ipv6, script_ipv6, sizeof(struct in6_addr))) {
			char live_buf[INET6_ADDRSTRLEN];
			char script_buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, live_ipv6, live_buf, sizeof(live_buf));
			inet_ntop(AF_INET6, script_ipv6, script_buf, sizeof(script_buf));
			asprintf(error,
				 "Bad getsockopt optval: "
				 "expected: %s "
				 "actual: %s ",
				 script_buf, live_buf);
			goto error_out;
		}
	} else {
		asprintf(error, "unsupported getsockopt value type: %s",
			 expression_type_to_string(
				 val_expression->type));
		goto error_out;
	}

	status = STATUS_OK;

error_out:
	free(live_optval);
	free(live_optval_pretty);
	free(script_optval_pretty);
	return status;
}

static int syscall_setsockopt(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args, char **error)
{
	int script_fd, live_fd, level, optname, optval_s32, optlen, result;
	void *optval = NULL;
	struct expression *val_expression;

	if (check_arg_count(args, 5, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &level, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &optname, error))
		return STATUS_ERR;
	if (s32_arg(args, 4, &optlen, error))
		return STATUS_ERR;

	val_expression = get_arg(args, 3, error);
	if (val_expression == NULL)
		return STATUS_ERR;
	if (val_expression->type == EXPR_LINGER) {
		optval = &val_expression->value.linger;
	} else if (val_expression->type == EXPR_GRE) {
		optval = &val_expression->value.gre;
	} else if (val_expression->type == EXPR_IN6_ADDR) {
		optval = &val_expression->value.address_ipv6;
	} else if (val_expression->type == EXPR_MPLS_STACK) {
		optval = val_expression->value.mpls_stack;
	} else if (val_expression->type == EXPR_STRING) {
		optval = val_expression->value.buf.ptr;
	} else if (val_expression->type == EXPR_LIST) {
		if (s32_bracketed_arg(args, 3, &optval_s32, error))
			return STATUS_ERR;
		optval = &optval_s32;
	} else {
		asprintf(error, "unsupported setsockopt value type: %s",
			 expression_type_to_string(
				 val_expression->type));
		return STATUS_ERR;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.setsockopt(
				state->so_instance->ifc.userdata,
				live_fd, level, optname, optval, optlen);
	} else {
		result = setsockopt(live_fd, level, optname, optval, optlen);
	}

	return end_syscall(state, syscall, CHECK_EXACT, result, error);
}

static int syscall_poll(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	struct expression *fds_expression = NULL;
	struct pollfd *fds = NULL;
	size_t fds_len;
	int nfds, timeout, result;
	int status = STATUS_ERR;

	if (check_arg_count(args, 3, error))
		goto error_out;

	fds_expression = get_arg(args, 0, error);
	if (fds_expression == NULL)
		goto error_out;
	if (pollfds_new(state, fds_expression, &fds, &fds_len, error))
		goto error_out;

	if (s32_arg(args, 1, &nfds, error))
		goto error_out;
	if (s32_arg(args, 2, &timeout, error))
		goto error_out;

	if (nfds != fds_len) {
		asprintf(error,
			 "nfds %d does not match %d-element pollfd array",
			 nfds, (int)fds_len);
		goto error_out;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.poll(
				state->so_instance->ifc.userdata,
				fds, nfds, timeout);
	} else {
		result = poll(fds, nfds, timeout);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (pollfds_check(fds_expression, fds, fds_len, error))
		goto error_out;

	status = STATUS_OK;

error_out:
	free(fds);
	return status;
}

static int syscall_cap_set(struct state *state, struct syscall_spec *syscall,
			   struct expression_list *args, char **error)
{
	int cap_flag, cap_value, cap_op;
	int result;
	cap_t caps;

	if (check_arg_count(args, 3, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &cap_flag, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &cap_value, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &cap_op, error))
		return STATUS_ERR;

	caps = cap_get_proc();
	if (caps == NULL)
		die("Error in cap_get_proc()\n");

	if (cap_set_flag(caps, cap_flag, 1, &cap_value,
			 cap_op) == -1)
		die("Error in cap_set_flag()\n");

	begin_syscall(state, syscall);

	result = cap_set_proc(caps);

	if (end_syscall(state, syscall, CHECK_FD, result, error))
		return STATUS_ERR;

	if (cap_free(caps) == -1)
		die("Error in cap_free()\n");

	return STATUS_OK;
}

static int syscall_open(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	int script_fd, live_fd, result;
	struct expression *name_expression;
	char *name;
	int flags;

	if (check_arg_count(args, 2, error))
		return STATUS_ERR;
	name_expression = get_arg(args, 0, error);
	if (check_type(name_expression, EXPR_STRING, error))
		return STATUS_ERR;
	name = name_expression->value.buf.ptr;
	if (s32_arg(args, 1, &flags, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	result = open(name, flags);

	if (end_syscall(state, syscall, CHECK_FD, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_fd = result;
		if (get_s32(syscall->result, &script_fd, error))
			return STATUS_ERR;
		if (run_syscall_open(state, script_fd, live_fd, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_sendfile(struct state *state, struct syscall_spec *syscall,
			    struct expression_list *args, char **error)
{
	int live_outfd, script_outfd;
	int live_infd, script_infd;
	s64 script_offset = 0;
	off_t live_offset;
	int count, result;
	int status = STATUS_ERR;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &script_outfd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_outfd, &live_outfd, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &script_infd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_infd, &live_infd, error))
		return STATUS_ERR;
	if (s64_bracketed_arg(args, 2, &script_offset, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &count, error))
		return STATUS_ERR;

	live_offset = script_offset;

	begin_syscall(state, syscall);

	result = sendfile(live_outfd, live_infd, &live_offset, count);

	status = end_syscall(state, syscall, CHECK_EXACT, result, error);

	return status;
}

/* Translate epoll_event expression into epoll_event data structure
 * epoll_data specifies the type of epoll_event->data
 */
static int get_epoll_event_from_expr(struct state *state,
				     struct expression *epollev,
				     struct epoll_event *event,
				     enum epoll_data_type_t *epoll_data,
				     int script_fd,
				     int live_fd,
				     char **error)
{
	struct epollev_expr *epollev_expr = NULL;

	if (epollev == NULL)
		return STATUS_ERR;
	if (check_type(epollev, EXPR_EPOLLEV, error))
		return STATUS_ERR;
	epollev_expr = epollev->value.epollev;
	if (!epollev_expr)
		return STATUS_ERR;
	if (check_type(epollev_expr->events, EXPR_INTEGER, error))
		return STATUS_ERR;
	event->events = epollev_expr->events->value.num;
	if (epollev_expr->ptr) {
		if (check_type(epollev_expr->ptr, EXPR_INTEGER, error))
			return STATUS_ERR;
		event->data.ptr = (void *)epollev_expr->ptr->value.num;
		*epoll_data = EPOLL_DATA_PTR;
	} else if (epollev_expr->fd) {
		if (check_type(epollev_expr->fd, EXPR_INTEGER, error))
			return STATUS_ERR;
		/* script_fd = -1 means we don't have a specific socket fd
		 * So we find live_fd directly from passed in event->data.fd
		 */
		if (script_fd == -1) {
			script_fd = epollev_expr->fd->value.num;
			if (to_live_fd(state, script_fd, &live_fd, error))
				return STATUS_ERR;
		} else {
			if (epollev_expr->fd->value.num != script_fd) {
				asprintf(error,
					 "wrong fd specified in epoll_event\n");
				return STATUS_ERR;
			}
		}
		event->data.fd = live_fd;
		*epoll_data = EPOLL_DATA_FD;
	} else if (epollev_expr->u32) {
		if (check_type(epollev_expr->u32, EXPR_INTEGER, error))
			return STATUS_ERR;
		event->data.u32 = epollev_expr->u32->value.num;
		*epoll_data = EPOLL_DATA_U32;
	} else if (epollev_expr->u64) {
		if (check_type(epollev_expr->u64, EXPR_INTEGER, error))
			return STATUS_ERR;
		event->data.u64 = epollev_expr->u64->value.num;
		*epoll_data = EPOLL_DATA_U64;
	} else {
		asprintf(error, "epoll_event specified incorrectly");
		return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_epoll_create(struct state *state, struct syscall_spec *syscall,
				struct expression_list *args, char **error)
{
	int size, result, script_fd, live_fd;
	if (check_arg_count(args, 1, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &size, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.epoll_create(
				state->so_instance->ifc.userdata,
				size);
	} else {
		result = epoll_create(size);
	}

	if (end_syscall(state, syscall, CHECK_FD, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		live_fd = result;
		if (get_s32(syscall->result, &script_fd, error))
			return STATUS_ERR;
		if (run_syscall_epoll_create(state, script_fd, live_fd, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_epoll_ctl(struct state *state, struct syscall_spec *syscall,
			     struct expression_list *args, char **error)
{
	int epfd_script, epfd_live, op, script_fd, live_fd, result;
	struct expression *epollev = NULL;
	struct epoll_event event;
	enum epoll_data_type_t epoll_data;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &epfd_script, error))
		return STATUS_ERR;
	if (to_live_fd(state, epfd_script, &epfd_live, error))
		return STATUS_ERR;
	if (s32_arg(args, 1, &op, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &script_fd, error))
		return STATUS_ERR;
	if (to_live_fd(state, script_fd, &live_fd, error))
		return STATUS_ERR;
	epollev = get_arg(args, 3, error);
	if (get_epoll_event_from_expr(state, epollev, &event, &epoll_data,
				      script_fd, live_fd, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.epoll_ctl(
				state->so_instance->ifc.userdata,
				epfd_live, op, live_fd, &event);
	} else {
		result = epoll_ctl(epfd_live, op, live_fd, &event);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int syscall_epoll_wait(struct state *state, struct syscall_spec *syscall,
			      struct expression_list *args, char **error)
{
	int epfd_script, epfd_live, maxevents, timeout;
	struct expression *epollev = NULL;
	struct epoll_event event_script = {0};
	struct epoll_event *event_live;
	enum epoll_data_type_t epoll_data;
	int status = STATUS_ERR;
	int result;

	if (check_arg_count(args, 4, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &epfd_script, error))
		return STATUS_ERR;
	if (to_live_fd(state, epfd_script, &epfd_live, error))
		return STATUS_ERR;
	epollev = get_arg(args, 1, error);
	if (get_epoll_event_from_expr(state, epollev, &event_script,
				      &epoll_data, -1, -1, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &maxevents, error))
		return STATUS_ERR;
	if (s32_arg(args, 3, &timeout, error))
		return STATUS_ERR;

	event_live = calloc(maxevents, sizeof(struct epoll_event));
	if (!event_live) {
		asprintf(error, "Failed to calloc %d struct epoll_event\n",
			 maxevents);
		goto error_out;
	}

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.epoll_wait(
				state->so_instance->ifc.userdata,
				epfd_live, event_live, maxevents, timeout);
	} else {
		result = epoll_wait(epfd_live, event_live, maxevents, timeout);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		goto error_out;

	if (event_script.events != event_live->events) {
		asprintf(error,
			 "epoll_event->events does not match script: "
			 "expected: 0x%x "
			 "actual: 0x%x\n",
			 event_script.events, event_live->events);
		goto error_out;
	}

	switch(epoll_data) {
	case EPOLL_DATA_PTR:
		if (event_script.data.ptr != event_live->data.ptr) {
			asprintf(error,
				 "epoll_event->data does not match script: "
				 "expected: %p "
				 "actual: %p\n",
				 event_script.data.ptr,
				 event_live->data.ptr);
			goto error_out;
		}
		break;
	case EPOLL_DATA_FD:
		if (event_script.data.fd != event_live->data.fd) {
			asprintf(error,
				 "epoll_event->data does not match script: "
				 "expected: %d "
				 "actual: %d\n",
				 event_script.data.fd,
				 event_live->data.fd);
			goto error_out;
		}
		break;
	case EPOLL_DATA_U32:
		if (event_script.data.u32 != event_live->data.u32) {
			asprintf(error,
				 "epoll_event->data does not match script: "
				 "expected: %u "
				 "actual: %u\n",
				 event_script.data.u32,
				 event_live->data.u32);
			goto error_out;
		}
		break;
	case EPOLL_DATA_U64:
		if (event_script.data.u64 != event_live->data.u64) {
			asprintf(error,
				 "epoll_event->data does not match script: "
				 "expected: %lu "
				 "actual: %lu\n",
				 event_script.data.u64,
				 event_live->data.u64);
			goto error_out;
		}
		break;
	default:
		asprintf(error, "wrong event->data type\n");
		goto error_out;
	}

	status = STATUS_OK;

error_out:
	free(event_live);
	return status;
}

static int get_pipe_expression(struct state *state,
			       struct expression *pipe_expr,
			       int *pipefd_script,
			       char **error)
{
	struct expression_list *list;
	int i = 0;
	int list_len;

	if (check_type(pipe_expr, EXPR_LIST, error))
		return STATUS_ERR;
	list = pipe_expr->value.list;
	list_len = list_length(list);
	if (list_len != 2) {
		asprintf(error, "%d pipe file descriptors instead of 2\n",
			 list_len);
		return STATUS_ERR;
	}
	for (i = 0; i < 2; i++) {
		if (check_type(list->expression, EXPR_INTEGER, error))
			return STATUS_ERR;
		pipefd_script[i] = list->expression->value.num;
		list = list->next;
	}

	return STATUS_OK;
}

static int syscall_pipe(struct state *state, struct syscall_spec *syscall,
			struct expression_list *args, char **error)
{
	struct expression *pipe_expr = NULL;
	int pipefd_script[2];
	int pipefd_live[2];
	int result;

	if (check_arg_count(args, 1, error))
		return STATUS_ERR;
	pipe_expr = get_arg(args, 0, error);
	if (pipe_expr == NULL)
		return STATUS_ERR;
	if (get_pipe_expression(state, pipe_expr, pipefd_script, error))
		return STATUS_ERR;

	begin_syscall(state, syscall);

	if (state->so_instance) {
		result = state->so_instance->ifc.pipe(
				state->so_instance->ifc.userdata,
				pipefd_live);
	} else {
		result = pipe(pipefd_live);
	}

	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	if (result >= 0) {
		if (run_syscall_pipe(state, pipefd_script, pipefd_live, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

static int syscall_splice(struct state *state, struct syscall_spec *syscall,
			  struct expression_list *args, char **error)
{
	int fd_in_script, fd_in_live;
	int fd_out_script, fd_out_live;
	s64 off_in, off_out;
	int len, flags;
	int result;

	if (check_arg_count(args, 6, error))
		return STATUS_ERR;
	if (s32_arg(args, 0, &fd_in_script, error))
		return STATUS_ERR;
	if (to_live_fd(state, fd_in_script, &fd_in_live, error))
		return STATUS_ERR;
	if (s64_arg(args, 1, &off_in, error))
		return STATUS_ERR;
	if (s32_arg(args, 2, &fd_out_script, error))
		return STATUS_ERR;
	if (to_live_fd(state, fd_out_script, &fd_out_live, error))
		return STATUS_ERR;
	if (s64_arg(args, 3, &off_out, error))
		return STATUS_ERR;
	if (s32_arg(args, 4, &len, error))
		return STATUS_ERR;
	if (s32_arg(args, 5, &flags, error))
		return STATUS_ERR;

	if (state->so_instance) {
		result = state->so_instance->ifc.splice(
				state->so_instance->ifc.userdata,
				fd_in_live, (loff_t *) &off_in,
				fd_out_live, (loff_t *) &off_out,
				len, flags);
	} else {
		result = splice(fd_in_live, (loff_t *) off_in, fd_out_live,
				(loff_t *) off_out, len, flags);
	}
	if (end_syscall(state, syscall, CHECK_EXACT, result, error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* A dispatch table with all the system calls that we support... */
struct system_call_entry {
	const char *name;
	int (*function) (struct state *state,
			 struct syscall_spec *syscall,
			 struct expression_list *args,
			 char **error);
};
struct system_call_entry system_call_table[] = {
	{"socket",     syscall_socket},
	{"bind",       syscall_bind},
	{"listen",     syscall_listen},
	{"accept",     syscall_accept},
	{"connect",    syscall_connect},
	{"read",       syscall_read},
	{"readv",      syscall_readv},
	{"recv",       syscall_recv},
	{"recvfrom",   syscall_recvfrom},
	{"recvmsg",    syscall_recvmsg},
	{"write",      syscall_write},
	{"writev",     syscall_writev},
	{"send",       syscall_send},
	{"sendto",     syscall_sendto},
	{"sendmsg",    syscall_sendmsg},
	{"fcntl",      syscall_fcntl},
	{"ioctl",      syscall_ioctl},
	{"close",      syscall_close},
	{"shutdown",   syscall_shutdown},
	{"getsockopt", syscall_getsockopt},
	{"setsockopt", syscall_setsockopt},
	{"poll",       syscall_poll},
	{"cap_set",    syscall_cap_set},
	{"open",       syscall_open},
	{"sendfile",   syscall_sendfile},
	{"epoll_create", syscall_epoll_create},
	{"epoll_ctl",    syscall_epoll_ctl},
	{"epoll_wait",   syscall_epoll_wait},
	{"pipe",         syscall_pipe},
	{"splice",       syscall_splice},
};

/* Evaluate the system call arguments and invoke the system call. */
static void invoke_system_call(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	DEBUGP("%d: invoke call: %s\n", event->line_number, syscall->name);

	char *error = NULL;
	const char *name = syscall->name;
	struct expression_list *args = NULL;
	int i = 0;
	int result = 0;

	/* Wait for the right time before firing off this event. */
	wait_for_event(state);

	/* Find and invoke the handler for this system call. */
	for (i = 0; i < ARRAY_SIZE(system_call_table); ++i)
		if (strcmp(name, system_call_table[i].name) == 0)
			break;
	if (i == ARRAY_SIZE(system_call_table)) {
		asprintf(&error, "Unknown system call: '%s'", name);
		goto error_out;
	}

	/* Evaluate script symbolic expressions to get live numeric args for
	 * system calls.
	 */
	if (evaluate_expression_list(syscall->arguments, &args, &error))
		goto error_out;

	/* Run the system call. */
	result = system_call_table[i].function(state, syscall, args, &error);

	free_expression_list(args);

	if (result == STATUS_ERR)
		goto error_out;
	return;

error_out:
	die("%s:%d: runtime error in %s call: %s\n",
	    state->config->script_path, event->line_number,
	    syscall->name, error);
	free(error);
}

/* Wait for the system call thread to go idle. To avoid mystifying
 * hangs when scripts specify overlapping time ranges for blocking
 * system calls, we limit the duration of our waiting to 1 second.
 */
static int await_idle_thread(struct state *state)
{
	struct timespec end_time = { .tv_sec = 0, .tv_nsec = 0 };
	const int MAX_WAIT_SECS = 1;
	while (state->syscalls->state != SYSCALL_IDLE) {
		/* On the first time through the loop, calculate end time. */
		if (end_time.tv_sec == 0) {
			if (clock_gettime(CLOCK_REALTIME, &end_time) != 0)
				die_perror("clock_gettime");
			end_time.tv_sec += MAX_WAIT_SECS;
		}
		/* Wait for a signal or our timeout end_time to arrive. */
		DEBUGP("main thread: awaiting idle syscall thread\n");
		int status = pthread_cond_timedwait(&state->syscalls->idle,
						    &state->mutex, &end_time);
		if (status == ETIMEDOUT)
			return STATUS_ERR;
		else if (status != 0)
			die_perror("pthread_cond_timedwait");
	}
	return STATUS_OK;
}

static int yield(void)
{
#if defined(__FreeBSD__) || defined(__OpenBSD__)
	pthread_yield();
	return 0;
#elif defined(__NetBSD__) || defined(linux)
	return sched_yield();
#endif  /* defined(__NetBSD__) || defined(linux) */
}

/* Enqueue the system call for the syscall thread and wake up the thread. */
static void enqueue_system_call(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	char *error = NULL;
	bool done = false;

	/* Wait if there are back-to-back blocking system calls. */
	if (await_idle_thread(state)) {
		asprintf(&error, "blocking system call while another blocking "
			 "system call is already in progress");
		goto error_out;
	}

	/* Enqueue the system call info and wake up the syscall thread. */
	DEBUGP("main thread: signal enqueued\n");
	state->syscalls->state = SYSCALL_ENQUEUED;
	if (pthread_cond_signal(&state->syscalls->enqueued) != 0)
		die_perror("pthread_cond_signal");

	/* Wait for the syscall thread to dequeue and start the system call. */
	while (state->syscalls->state == SYSCALL_ENQUEUED) {
		DEBUGP("main thread: waiting for dequeued signal; "
		       "state: %d\n", state->syscalls->state);
		if (pthread_cond_wait(&state->syscalls->dequeued,
				      &state->mutex) != 0) {
			die_perror("pthread_cond_wait");
		}
	}

	/* Wait for the syscall thread to block or finish the call. */
	while (!done) {
		/* Unlock and yield so the system call thread can make
		 * the system call in a timely fashion.
		 */
		DEBUGP("main thread: unlocking and yielding\n");
		pid_t thread_id = state->syscalls->thread_id;
		run_unlock(state);
		if (yield() != 0)
			die_perror("yield");

		DEBUGP("main thread: checking syscall thread state\n");
		if (is_thread_sleeping(getpid(), thread_id))
			done = true;

		/* Grab the lock again and see if the thread is idle. */
		DEBUGP("main thread: locking and reading state\n");
		run_lock(state);
		if (state->syscalls->state == SYSCALL_IDLE)
			done = true;
	}
	DEBUGP("main thread: continuing after syscall\n");
	return;

error_out:
	die("%s:%d: runtime error in %s call: %s\n",
	    state->config->script_path, event->line_number,
	    syscall->name, error);
	free(error);
}

void run_system_call_event(
	struct state *state, struct event *event, struct syscall_spec *syscall)
{
	DEBUGP("%d: system call: %s\n", event->line_number, syscall->name);

	if (is_blocking_syscall(syscall))
		enqueue_system_call(state, event, syscall);
	else {
		await_idle_thread(state);
		invoke_system_call(state, event, syscall);
	}
}

/* The code executed by our system call thread, which executes
 * blocking system calls.
 */
static void *system_call_thread(void *arg)
{
	struct state *state = (struct state *)arg;
	char *error = NULL;
	struct event *event = NULL;
	struct syscall_spec *syscall = NULL;
	bool done = false;

	DEBUGP("syscall thread: starting and locking\n");
	run_lock(state);

	state->syscalls->thread_id = gettid();
	if (state->syscalls->thread_id < 0)
		die_perror("gettid");

	while (!done) {
		DEBUGP("syscall thread: in state %d\n",
		       state->syscalls->state);

		switch (state->syscalls->state) {
		case SYSCALL_IDLE:
			DEBUGP("syscall thread: waiting\n");
			if (pthread_cond_wait(&state->syscalls->enqueued,
					      &state->mutex)) {
				die_perror("pthread_cond_wait");
			}
			break;

		case SYSCALL_RUNNING:
		case SYSCALL_DONE:
			assert(0);	/* should not be reached */
			break;

		case SYSCALL_ENQUEUED:
			DEBUGP("syscall thread: invoking syscall\n");
			/* Remember the syscall event, since below we
			 * release the global lock and the main thread
			 * will move on to other, later events.
			 */
			event = state->event;
			syscall = event->event.syscall;
			assert(event->type == SYSCALL_EVENT);
			state->syscalls->event = event;
			state->syscalls->live_end_usecs = -1;

			/* Make the system call. Note that our callees
			 * here will release the global lock before
			 * making the actual system call and then
			 * re-acquire it after the system call returns
			 * and before returning to us.
			 */
			invoke_system_call(state, event, syscall);

			/* Check end time for the blocking system call.
			 * For a blocking system call we compute the
			 * dynamic tolerance based on the start and end
			 * time. The last event here is unpredictable
			 * and irrelevant.
			 */
			assert(state->syscalls->live_end_usecs >= 0);
			if (verify_time(state,
						event->time_type,
						syscall->end_usecs, 0,
						state->syscalls->live_end_usecs,
						event->time_usecs,
						"system call return", &error)) {
				die("%s:%d: %s\n",
				    state->config->script_path,
				    event->line_number,
				    error);
			}

			/* Mark our thread idle and wake the main
			 * thread if it's waiting for this call to
			 * finish.
			 */
			assert(state->syscalls->state == SYSCALL_DONE);
			state->syscalls->state = SYSCALL_IDLE;
			state->syscalls->event = NULL;
			state->syscalls->live_end_usecs = -1;
			DEBUGP("syscall thread: now idle\n");
			if (pthread_cond_signal(&state->syscalls->idle) != 0)
				die_perror("pthread_cond_signal");
			break;

		case SYSCALL_EXITING:
			done = true;
			break;
		/* omitting default so compiler will catch missing cases */
		}
	}
	DEBUGP("syscall thread: unlocking and exiting\n");
	run_unlock(state);

	return NULL;
}

struct syscalls *syscalls_new(struct state *state)
{
	struct syscalls *syscalls = calloc(1, sizeof(struct syscalls));

	syscalls->state = SYSCALL_IDLE;

	if (pthread_create(&syscalls->thread, NULL, system_call_thread,
			   state) != 0) {
		die_perror("pthread_create");
	}

	if ((pthread_cond_init(&syscalls->idle, NULL) != 0) ||
	    (pthread_cond_init(&syscalls->enqueued, NULL) != 0) ||
	    (pthread_cond_init(&syscalls->dequeued, NULL) != 0)) {
		die_perror("pthread_cond_init");
	}

	return syscalls;
}

void syscalls_free(struct state *state, struct syscalls *syscalls)
{
	/* Wait a bit for the thread to go idle. */
	if (await_idle_thread(state)) {
		die("%s:%d: runtime error: exiting while "
		    "a blocking system call is in progress\n",
		    state->config->script_path,
		    syscalls->event->line_number);
	}

	/* Send a request to terminate the thread. */
	DEBUGP("main thread: signaling syscall thread to exit\n");
	syscalls->state = SYSCALL_EXITING;
	if (pthread_cond_signal(&syscalls->enqueued) != 0)
		die_perror("pthread_cond_signal");

	/* Release the lock briefly and wait for syscall thread to finish. */
	run_unlock(state);
	DEBUGP("main thread: unlocking, waiting for syscall thread exit\n");
	void *thread_result = NULL;
	if (pthread_join(syscalls->thread, &thread_result) != 0)
		die_perror("pthread_cancel");
	DEBUGP("main thread: joined syscall thread; relocking\n");
	run_lock(state);

	if ((pthread_cond_destroy(&syscalls->idle) != 0) ||
	    (pthread_cond_destroy(&syscalls->enqueued) != 0) ||
	    (pthread_cond_destroy(&syscalls->dequeued) != 0)) {
		die_perror("pthread_cond_destroy");
	}

	memset(syscalls, 0, sizeof(*syscalls));  /* to help catch bugs */
	free(syscalls);
}
