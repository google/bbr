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
 * Implementation of functions to help interpret a test script.
 */

#include "script.h"

#include <poll.h>
#include <stdlib.h>

#include "assert.h"
#include "symbols.h"
#include "gre.h"

/* Fill in a value representing the given expression in
 * fully-evaluated form (e.g. symbols resolved to ints). On success,
 * returns STATUS_OK. On error return STATUS_ERR and fill in *error.
 */
static int evaluate(struct expression *in,
		    struct expression **out_ptr, char **error);

/* Initialize script object */
void init_script(struct script *script)
{
	memset(script, 0, sizeof(*script));
	script->option_list = NULL;
	script->init_command = NULL;
	script->event_list = NULL;
}

/* This table maps expression types to human-readable strings */
struct expression_type_entry {
	enum expression_t type;
	const char *name;
};
struct expression_type_entry expression_type_table[] = {
	{ EXPR_ELLIPSIS,             "ellipsis" },
	{ EXPR_INTEGER,              "integer" },
	{ EXPR_WORD,                 "word" },
	{ EXPR_STRING,               "string" },
	{ EXPR_GRE,                  "gre" },
	{ EXPR_IN6_ADDR,             "in6_addr" },
	{ EXPR_SOCKET_ADDRESS_IPV4,  "sockaddr_in" },
	{ EXPR_SOCKET_ADDRESS_IPV6,  "sockaddr_in6" },
	{ EXPR_LINGER,               "linger" },
	{ EXPR_BINARY,               "binary_expression" },
	{ EXPR_LIST,                 "list" },
	{ EXPR_IOVEC,                "iovec" },
	{ EXPR_MSGHDR,               "msghdr" },
	{ EXPR_CMSG,                 "cmsg" },
	{ EXPR_POLLFD,               "pollfd" },
	{ EXPR_MPLS_STACK,           "mpls_stack" },
	{ EXPR_SCM_TIMESTAMPING,     "scm_timestamping"},
	{ EXPR_SOCK_EXTENDED_ERR,    "sock_extended_err"},
	{ EXPR_EPOLLEV,		     "epollev" },
	{-1,                         NULL}
};

const char *expression_type_to_string(enum expression_t type)
{
	int i = 0;
	assert(ARRAY_SIZE(expression_type_table) == NUM_EXPR_TYPES + 1);
	for (i = 0; expression_type_table[i].name != NULL; ++i)
		if (expression_type_table[i].type == type)
			return expression_type_table[i].name;
	return "UNKNOWN_TYPE";
}

/* Cross-platform symbols. */
struct int_symbol cross_platform_symbols[] = {
	{ AF_INET,                          "AF_INET"                         },
	{ AF_INET6,                         "AF_INET6"                        },
	{ AF_PACKET,                        "AF_PACKET"                       },

	{ PF_INET,                          "PF_INET"                         },
	{ PF_INET6,                         "PF_INET6"                        },

	{ SOCK_RAW,                         "SOCK_RAW"                        },
	{ SOCK_STREAM,                      "SOCK_STREAM"                     },
	{ SOCK_DGRAM,                       "SOCK_DGRAM"                      },
	{ SOCK_NONBLOCK,                    "SOCK_NONBLOCK"                   },

	{ IPPROTO_RAW,                      "IPPROTO_RAW"                     },
	{ IPPROTO_IP,                       "IPPROTO_IP"                      },
	{ IPPROTO_IPV6,                     "IPPROTO_IPV6"                    },
	{ IPPROTO_ICMP,                     "IPPROTO_ICMP"                    },
	{ IPPROTO_ICMPV6,                   "IPPROTO_ICMPV6"                  },
	{ IPPROTO_TCP,                      "IPPROTO_TCP"                     },
	{ IPPROTO_UDP,                      "IPPROTO_UDP"                     },

	{ SHUT_RD,                          "SHUT_RD"                         },
	{ SHUT_WR,                          "SHUT_WR"                         },
	{ SHUT_RDWR,                        "SHUT_RDWR"                       },

	{ SOL_SOCKET,                       "SOL_SOCKET"                      },

	{ 0,                                "NULL"                            },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

/* Do a symbol->int lookup, and return true iff we found the symbol. */
static bool lookup_int_symbol(const char *input_symbol, s64 *output_integer,
			      struct int_symbol *symbols)
{
	int i;
	for (i = 0; symbols[i].name != NULL ; ++i) {
		if (strcmp(input_symbol, symbols[i].name) == 0) {
			*output_integer = symbols[i].value;
			return true;
		}
	}
	return false;
}

int symbol_to_int(const char *input_symbol, s64 *output_integer,
		  char **error)
{
	if (lookup_int_symbol(input_symbol, output_integer,
			      cross_platform_symbols))
		return STATUS_OK;

	if (lookup_int_symbol(input_symbol, output_integer,
			      platform_symbols()))
		return STATUS_OK;

	asprintf(error, "unknown symbol: '%s'", input_symbol);
	return STATUS_ERR;
}

/* Names for the events and revents bit mask flags for poll() system call */
struct flag_name poll_flags[] = {

	{ POLLIN,	"POLLIN" },
	{ POLLPRI,	"POLLPRI" },
	{ POLLOUT,	"POLLOUT" },

#ifdef POLLRDNORM
	{ POLLRDNORM,	"POLLRDNORM" },
#endif
#ifdef POLLRDBAND
	{ POLLRDBAND,	"POLLRDBAND" },
#endif
#ifdef POLLWRNORM
	{ POLLWRNORM,	"POLLWRNORM" },
#endif
#ifdef POLLWRBAND
	{ POLLWRBAND,	"POLLWRBAND" },
#endif

#ifdef POLLMSG
	{ POLLMSG,	"POLLMSG" },
#endif
#ifdef POLLREMOVE
	{ POLLREMOVE,	"POLLREMOVE" },
#endif
#ifdef POLLRDHUP
	{ POLLRDHUP,	"POLLRDHUP" },
#endif

#ifdef POLLINIGNEOF
	{ POLLINIGNEOF, "POLLINIGNEOF"                    },
#endif

	{ POLLERR,	"POLLERR" },
	{ POLLHUP,	"POLLHUP" },
	{ POLLNVAL,	"POLLNVAL" },

	{ 0, "" },
};

/* Return the human-readable ASCII string corresponding to a given
 * flag value, or "???" if none matches.
 */
static const char *flag_name(struct flag_name *flags_array, u64 flag)
{
	while (flags_array->name && flags_array->flag != flag)
		flags_array++;
	if (flags_array->flag == flag)
		return flags_array->name;
	else
		return "???";
}

char *flags_to_string(struct flag_name *flags_array, u64 flags)
{
	u64 bit_mask = 1;
	int i = 0;
	char *out = strdup("");

	for (i = 0; i < 64; ++i) {
		if (flags & bit_mask) {
			char *tmp = NULL;
			asprintf(&tmp, "%s%s%s",
				 out,
				 out[0] ? "|" : "",
				 flag_name(flags_array, bit_mask));
			free(out);
			out = tmp;
		}
		bit_mask <<= 1;
	}
	return out;
}

/* Fill in 'out' with an unescaped version of the input string. On
 * success, return STATUS_OK; on error, return STATUS_ERR and store
 * an error message in *error.
 */
static int unescape_cstring_expression(const char *input_string,
				       struct expression *out, char **error)
{
	int bytes = strlen(input_string);
	out->type = EXPR_STRING;
	out->value.buf.ptr = (char *)calloc(1, bytes + 1);
	const char *c_in = input_string;
	char *c_out = out->value.buf.ptr;
	while (*c_in != '\0') {
		if (*c_in == '\\') {
			++c_in;
			switch (*c_in) {
			case '\\':
				*c_out = '\\';
			case '"':
				*c_out = '"';
			case 'f':
				*c_out = '\f';
				break;
			case 'n':
				*c_out = '\n';
				break;
			case 'r':
				*c_out = '\r';
				break;
			case 't':
				*c_out = '\t';
				break;
			case 'v':
				*c_out = '\v';
				break;
			case 'x': {
				++c_in;
				if (strlen(c_in) >= 2) {
					char s[] = { c_in[0], c_in[1], 0 };
					char *end = NULL;

					*c_out = strtol(s, &end, 16);
					if (s[0] != '\0' && *end == '\0') {
						++c_in;
						break;
					}
				}
				asprintf(error,
					 "invalid hex escape (\\xhh): '\\x%s'",
					 c_in);
				return STATUS_ERR;
			}
			default:
				asprintf(error, "unsupported escape code: '%c'",
					 *c_in);
				return STATUS_ERR;
			}
		} else {
			*c_out = *c_in;
		}
		++c_in;
		++c_out;
	}
	out->value.buf.len = c_out - out->value.buf.ptr;
	return STATUS_OK;
}

void free_expression(struct expression *expression)
{
	if (expression == NULL)
		return;
	if (expression->type >= NUM_EXPR_TYPES)
		assert(!"bad expression type");
	switch (expression->type) {
	case EXPR_ELLIPSIS:
	case EXPR_INTEGER:
	case EXPR_GRE:
	case EXPR_IN6_ADDR:
	case EXPR_LINGER:
		break;
	case EXPR_WORD:
		assert(expression->value.buf.ptr);
		free(expression->value.buf.ptr);
		break;
	case EXPR_STRING:
		assert(expression->value.buf.ptr);
		free(expression->value.buf.ptr);
		break;
	case EXPR_SOCKET_ADDRESS_IPV4:
		assert(expression->value.socket_address_ipv4);
		free(expression->value.socket_address_ipv4);
		break;
	case EXPR_SOCKET_ADDRESS_IPV6:
		assert(expression->value.socket_address_ipv6);
		free(expression->value.socket_address_ipv6);
		break;
	case EXPR_BINARY:
		assert(expression->value.binary);
		free(expression->value.binary->op);
		free_expression(expression->value.binary->lhs);
		free_expression(expression->value.binary->rhs);
		free(expression->value.binary);
		break;
	case EXPR_LIST:
		free_expression_list(expression->value.list);
		break;
	case EXPR_IOVEC:
		assert(expression->value.iovec);
		free_expression(expression->value.iovec->iov_base);
		free_expression(expression->value.iovec->iov_len);
		break;
	case EXPR_MSGHDR:
		assert(expression->value.msghdr);
		free_expression(expression->value.msghdr->msg_name);
		free_expression(expression->value.msghdr->msg_namelen);
		free_expression(expression->value.msghdr->msg_iov);
		free_expression(expression->value.msghdr->msg_iovlen);
		free_expression(expression->value.msghdr->msg_control);
		free_expression(expression->value.msghdr->msg_flags);
		break;
	case EXPR_CMSG:
		assert(expression->value.cmsg);
		free_expression(expression->value.cmsg->cmsg_level);
		free_expression(expression->value.cmsg->cmsg_type);
		free_expression(expression->value.cmsg->cmsg_data);
		break;
	case EXPR_POLLFD:
		assert(expression->value.pollfd);
		free_expression(expression->value.pollfd->fd);
		free_expression(expression->value.pollfd->events);
		free_expression(expression->value.pollfd->revents);
		break;
	case EXPR_SCM_TIMESTAMPING:
		assert(expression->value.scm_timestamping);
		free(expression->value.scm_timestamping);
		break;
	case EXPR_SOCK_EXTENDED_ERR:
		assert(expression->value.sock_extended_err);
		free_expression(expression->value.sock_extended_err->ee_errno);
		free_expression(expression->value.sock_extended_err->ee_origin);
		free_expression(expression->value.sock_extended_err->ee_type);
		free_expression(expression->value.sock_extended_err->ee_code);
		free_expression(expression->value.sock_extended_err->ee_info);
		free_expression(expression->value.sock_extended_err->ee_data);
		free(expression->value.sock_extended_err);
		break;
	case EXPR_MPLS_STACK:
		assert(expression->value.mpls_stack);
		free(expression->value.mpls_stack);
		break;
	case NUM_EXPR_TYPES:
		break;
	case EXPR_EPOLLEV:
		assert(expression->value.epollev);
		free_expression(expression->value.epollev->events);
		if (expression->value.epollev->ptr)
			free_expression(expression->value.epollev->ptr);
		if (expression->value.epollev->fd)
			free_expression(expression->value.epollev->fd);
		if (expression->value.epollev->u32)
			free_expression(expression->value.epollev->u32);
		if (expression->value.epollev->u64)
			free_expression(expression->value.epollev->u64);
		break;

	/* missing default case so compiler catches missing cases */
	}
	memset(expression, 0, sizeof(*expression));  /* paranoia */
	free(expression);
}

void free_expression_list(struct expression_list *list)
{
	while (list != NULL) {
		free_expression(list->expression);
		struct expression_list *dead = list;
		list = list->next;
		free(dead);
	}
}

/* Concatenate lhs and rhs into out. Each input may contain \x00 bytes. */
static void concatenate_string_expressions(struct expression *out,
					   struct expression *lhs,
					   struct expression *rhs)
{
	char *dest;
	u32 buf_len;

	buf_len = lhs->value.buf.len + rhs->value.buf.len;
	out->value.buf.ptr = malloc(buf_len + 1);
	out->value.buf.len = buf_len;

	dest = out->value.buf.ptr;
	memcpy(dest, lhs->value.buf.ptr, lhs->value.buf.len);
	dest += lhs->value.buf.len;
	memcpy(dest, rhs->value.buf.ptr, rhs->value.buf.len);
	dest += rhs->value.buf.len;
	*dest = '\0';  /* null-terminate for safety/debugging/printing */
}

static int evaluate_binary_expression(struct expression *in,
				      struct expression *out, char **error)
{
	int result = STATUS_ERR;
	assert(in->type == EXPR_BINARY);
	assert(in->value.binary);
	out->type = EXPR_INTEGER;

	struct expression *lhs = NULL;
	struct expression *rhs = NULL;
	if (evaluate(in->value.binary->lhs, &lhs, error))
		goto error_out;
	if (evaluate(in->value.binary->rhs, &rhs, error))
		goto error_out;
	if (strcmp("|", in->value.binary->op) == 0) {
		if (lhs->type != EXPR_INTEGER) {
			asprintf(error, "left hand side of | not an integer");
		} else if (rhs->type != EXPR_INTEGER) {
			asprintf(error, "right hand side of | not an integer");
		} else {
			out->value.num = lhs->value.num | rhs->value.num;
			result = STATUS_OK;
		}
	} else if (strcmp(".", in->value.binary->op) == 0) {
		if (lhs->type == EXPR_STRING && rhs->type == EXPR_STRING) {
			out->type = EXPR_STRING;
			concatenate_string_expressions(out, lhs, rhs);
			result = STATUS_OK;
		} else {
			asprintf(error, "bad input types for concatenation");
		}
	} else if (strcmp("=", in->value.binary->op) == 0) {
		out->value.binary = calloc(1, sizeof(struct binary_expression));
		out->value.binary->op = strdup(in->value.binary->op);
		out->value.binary->lhs = lhs;
		out->value.binary->rhs = rhs;
		out->type = EXPR_BINARY;
		return STATUS_OK;
	} else {
		asprintf(error, "bad binary operator '%s'",
			 in->value.binary->op);
	}
error_out:
	free_expression(rhs);
	free_expression(lhs);
	return result;
}

static int evaluate_list_expression(struct expression *in,
				    struct expression *out, char **error)
{
	assert(in->type == EXPR_LIST);
	assert(out->type == EXPR_LIST);

	out->value.list = NULL;
	return evaluate_expression_list(in->value.list,
					&out->value.list, error);
}

static int evaluate_iovec_expression(struct expression *in,
				     struct expression *out, char **error)
{
	struct iovec_expr *in_iov;
	struct iovec_expr *out_iov;

	assert(in->type == EXPR_IOVEC);
	assert(in->value.iovec);
	assert(out->type == EXPR_IOVEC);

	out->value.iovec = calloc(1, sizeof(struct iovec_expr));

	in_iov = in->value.iovec;
	out_iov = out->value.iovec;

	if (evaluate(in_iov->iov_base,		&out_iov->iov_base,	error))
		return STATUS_ERR;
	if (evaluate(in_iov->iov_len,		&out_iov->iov_len,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_msghdr_expression(struct expression *in,
				      struct expression *out, char **error)
{
	struct msghdr_expr *in_msg;
	struct msghdr_expr *out_msg;

	assert(in->type == EXPR_MSGHDR);
	assert(in->value.msghdr);
	assert(out->type == EXPR_MSGHDR);

	out->value.msghdr = calloc(1, sizeof(struct msghdr_expr));

	in_msg = in->value.msghdr;
	out_msg = out->value.msghdr;

	if (evaluate(in_msg->msg_name,		&out_msg->msg_name,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_namelen,	&out_msg->msg_namelen,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_iov,		&out_msg->msg_iov,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_iovlen,	&out_msg->msg_iovlen,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_control,	&out_msg->msg_control,	error))
		return STATUS_ERR;
	if (evaluate(in_msg->msg_flags,		&out_msg->msg_flags,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_cmsg_expression(struct expression *in,
				    struct expression *out, char **error)
{
	struct cmsg_expr *in_cmsg;
	struct cmsg_expr *out_cmsg;

	assert(in->type == EXPR_CMSG);
	assert(in->value.cmsg);
	assert(out->type == EXPR_CMSG);

	out->value.cmsg = calloc(1, sizeof(struct cmsg_expr));

	in_cmsg = in->value.cmsg;
	out_cmsg = out->value.cmsg;

	if (evaluate(in_cmsg->cmsg_level,	&out_cmsg->cmsg_level,	error))
		return STATUS_ERR;
	if (evaluate(in_cmsg->cmsg_type,	&out_cmsg->cmsg_type,	error))
		return STATUS_ERR;
	if (evaluate(in_cmsg->cmsg_data,	&out_cmsg->cmsg_data,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_sock_extended_err(struct expression *in,
				      struct expression *out, char **error)
{
	struct sock_extended_err_expr *in_ee_err;
	struct sock_extended_err_expr *out_ee_err;

	assert(in->type == EXPR_SOCK_EXTENDED_ERR);
	assert(in->value.sock_extended_err);
	assert(out->type == EXPR_SOCK_EXTENDED_ERR);

	out->value.sock_extended_err =
		calloc(1, sizeof(struct sock_extended_err_expr));

	in_ee_err = in->value.sock_extended_err;
	out_ee_err = out->value.sock_extended_err;

	if (evaluate(in_ee_err->ee_errno, &out_ee_err->ee_errno, error))
		return STATUS_ERR;
	if (evaluate(in_ee_err->ee_origin, &out_ee_err->ee_origin, error))
		return STATUS_ERR;
	if (evaluate(in_ee_err->ee_type, &out_ee_err->ee_type, error))
		return STATUS_ERR;
	if (evaluate(in_ee_err->ee_code, &out_ee_err->ee_code, error))
		return STATUS_ERR;
	if (evaluate(in_ee_err->ee_info, &out_ee_err->ee_info, error))
		return STATUS_ERR;
	if (evaluate(in_ee_err->ee_data, &out_ee_err->ee_data, error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_pollfd_expression(struct expression *in,
				      struct expression *out, char **error)
{
	struct pollfd_expr *in_pollfd;
	struct pollfd_expr *out_pollfd;

	assert(in->type == EXPR_POLLFD);
	assert(in->value.pollfd);
	assert(out->type == EXPR_POLLFD);

	out->value.pollfd = calloc(1, sizeof(struct pollfd_expr));

	in_pollfd = in->value.pollfd;
	out_pollfd = out->value.pollfd;

	if (evaluate(in_pollfd->fd,		&out_pollfd->fd,	error))
		return STATUS_ERR;
	if (evaluate(in_pollfd->events,		&out_pollfd->events,	error))
		return STATUS_ERR;
	if (evaluate(in_pollfd->revents,	&out_pollfd->revents,	error))
		return STATUS_ERR;

	return STATUS_OK;
}

static int evaluate_epollev_expression(struct expression *in,
				       struct expression *out, char **error)
{
	struct epollev_expr *in_epollev;
	struct epollev_expr *out_epollev;

	assert(in->type == EXPR_EPOLLEV);
	assert(in->value.epollev);
	assert(out->type == EXPR_EPOLLEV);

	out->value.epollev = calloc(1, sizeof(struct epollev_expr));
	in_epollev = in->value.epollev;
	out_epollev = out->value.epollev;

	if (evaluate(in_epollev->events, &out_epollev->events, error))
		return STATUS_ERR;

	if (in_epollev->ptr) {
		if (evaluate(in_epollev->ptr, &out_epollev->ptr, error))
			return STATUS_ERR;
	} else if (in_epollev->fd) {
		if (evaluate(in_epollev->fd, &out_epollev->fd, error))
			return STATUS_ERR;
	} else if (in_epollev->u32) {
		if (evaluate(in_epollev->u32, &out_epollev->u32, error))
			return STATUS_ERR;
	} else if (in_epollev->u64) {
		if (evaluate(in_epollev->u64, &out_epollev->u64, error))
			return STATUS_ERR;
	} else {
		return STATUS_ERR;
	}
	return STATUS_OK;
}

static int evaluate(struct expression *in,
		    struct expression **out_ptr, char **error)
{
	int result = STATUS_OK;
	struct expression *out = calloc(1, sizeof(struct expression));
	*out_ptr = out;
	out->type = in->type;	/* most types of expression stay the same */

	if (in->type >= NUM_EXPR_TYPES) {
		asprintf(error, "bad expression type: %d", in->type);
		return STATUS_ERR;
	}
	switch (in->type) {
	case EXPR_ELLIPSIS:
		break;
	case EXPR_INTEGER:		/* copy as-is */
		out->value.num = in->value.num;
		break;
	case EXPR_GRE:			/* copy as-is */
		memcpy(&out->value.gre, &in->value.gre,
		       gre_len(&in->value.gre));
		break;
	case EXPR_IN6_ADDR:		/* copy as-is */
		memcpy(&out->value.address_ipv6, &in->value.address_ipv6,
			sizeof(in->value.address_ipv6));
		break;
	case EXPR_LINGER:		/* copy as-is */
		memcpy(&out->value.linger, &in->value.linger,
		       sizeof(in->value.linger));
		break;
	case EXPR_WORD:
		out->type = EXPR_INTEGER;
		if (symbol_to_int(in->value.buf.ptr,
				  &out->value.num, error))
			return STATUS_ERR;
		break;
	case EXPR_STRING:
		if (unescape_cstring_expression(in->value.buf.ptr, out, error))
			return STATUS_ERR;
		break;
	case EXPR_SOCKET_ADDRESS_IPV4:	/* copy as-is */
		out->value.socket_address_ipv4 =
			malloc(sizeof(struct sockaddr_in));
		memcpy(out->value.socket_address_ipv4,
		       in->value.socket_address_ipv4,
		       sizeof(*(out->value.socket_address_ipv4)));
		break;
	case EXPR_SOCKET_ADDRESS_IPV6:	/* copy as-is */
		out->value.socket_address_ipv6 =
			malloc(sizeof(struct sockaddr_in6));
		memcpy(out->value.socket_address_ipv6,
		       in->value.socket_address_ipv6,
		       sizeof(*(out->value.socket_address_ipv6)));
		break;
	case EXPR_BINARY:
		result = evaluate_binary_expression(in, out, error);
		break;
	case EXPR_LIST:
		result = evaluate_list_expression(in, out, error);
		break;
	case EXPR_IOVEC:
		result = evaluate_iovec_expression(in, out, error);
		break;
	case EXPR_MSGHDR:
		result = evaluate_msghdr_expression(in, out, error);
		break;
	case EXPR_CMSG:
		result = evaluate_cmsg_expression(in, out, error);
		break;
	case EXPR_SCM_TIMESTAMPING:
		memcpy(&out->value.scm_timestamping,
		       &in->value.scm_timestamping,
		       sizeof(in->value.scm_timestamping));
		break;
	case EXPR_SOCK_EXTENDED_ERR:
		result = evaluate_sock_extended_err(in, out, error);
		break;
	case EXPR_POLLFD:
		result = evaluate_pollfd_expression(in, out, error);
		break;
	case EXPR_MPLS_STACK:		/* copy as-is */
		out->value.mpls_stack = malloc(sizeof(struct mpls_stack));
		memcpy(out->value.mpls_stack,
		       in->value.mpls_stack,
		       sizeof(*out->value.mpls_stack));
		break;
	case EXPR_EPOLLEV:
		result = evaluate_epollev_expression(in, out, error);
		break;
	case NUM_EXPR_TYPES:
		break;
	/* missing default case so compiler catches missing cases */
	}

	return result;
}

/* Return a copy of the given expression list with each expression
 * evaluated (e.g. symbols resolved to ints). On failure, return NULL
 * and fill in *error.
 */
int evaluate_expression_list(struct expression_list *in_list,
			     struct expression_list **out_list,
			     char **error)
{
	struct expression_list **node_ptr = out_list;
	while (in_list != NULL) {
		struct expression_list *node =
			calloc(1, sizeof(struct expression_list));
		*node_ptr = node;
		if (evaluate(in_list->expression,
			     &node->expression, error)) {
			free_expression_list(*out_list);
			*out_list = NULL;
			return STATUS_ERR;
		}
		node_ptr = &(node->next);
		in_list = in_list->next;
	}
	return STATUS_OK;
}
