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

#include <assert.h>
#include <poll.h>
#include <stdlib.h>

#include "symbols.h"

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
	{ EXPR_NONE,                 "none" },
	{ EXPR_ELLIPSIS,             "ellipsis" },
	{ EXPR_INTEGER,              "integer" },
	{ EXPR_WORD,                 "word" },
	{ EXPR_STRING,               "string" },
	{ EXPR_SOCKET_ADDRESS_IPV4,  "sockaddr_in" },
	{ EXPR_SOCKET_ADDRESS_IPV6,  "sockaddr_in6" },
	{ EXPR_LINGER,               "linger" },
	{ EXPR_BINARY,               "binary_expression" },
	{ EXPR_LIST,                 "list" },
	{ EXPR_IOVEC,                "iovec" },
	{ EXPR_MSGHDR,               "msghdr" },
	{ EXPR_POLLFD,               "pollfd" },
	{ NUM_EXPR_TYPES,            NULL}
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

	{ PF_INET,                          "PF_INET"                         },
	{ PF_INET6,                         "PF_INET6"                        },

	{ SOCK_STREAM,                      "SOCK_STREAM"                     },
	{ SOCK_DGRAM,                       "SOCK_DGRAM"                      },

	{ IPPROTO_IP,                       "IPPROTO_IP"                      },
	{ IPPROTO_IPV6,                     "IPPROTO_IPV6"                    },
	{ IPPROTO_ICMP,                     "IPPROTO_ICMP"                    },
	{ IPPROTO_TCP,                      "IPPROTO_TCP"                     },
	{ IPPROTO_UDP,                      "IPPROTO_UDP"                     },

	{ SHUT_RD,                          "SHUT_RD"                         },
	{ SHUT_WR,                          "SHUT_WR"                         },
	{ SHUT_RDWR,                        "SHUT_RDWR"                       },

	{ SOL_SOCKET,                       "SOL_SOCKET"                      },

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
	out->value.string = (char *)calloc(1, bytes + 1);
	const char *c_in = input_string;
	char *c_out = out->value.string;
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
	return STATUS_OK;
}

void free_expression(struct expression *expression)
{
	if (expression == NULL)
		return;
	if ((expression->type <= EXPR_NONE) ||
	    (expression->type >= NUM_EXPR_TYPES))
		assert(!"bad expression type");
	switch (expression->type) {
	case EXPR_ELLIPSIS:
	case EXPR_INTEGER:
	case EXPR_LINGER:
		break;
	case EXPR_WORD:
		assert(expression->value.string);
		free(expression->value.string);
		break;
	case EXPR_STRING:
		assert(expression->value.string);
		free(expression->value.string);
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
		free_expression(expression->value.msghdr->msg_flags);
		break;
	case EXPR_POLLFD:
		assert(expression->value.pollfd);
		free_expression(expression->value.pollfd->fd);
		free_expression(expression->value.pollfd->events);
		free_expression(expression->value.pollfd->revents);
		break;
	case EXPR_NONE:
	case NUM_EXPR_TYPES:
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
	if (evaluate(in_msg->msg_flags,		&out_msg->msg_flags,	error))
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

static int evaluate(struct expression *in,
		    struct expression **out_ptr, char **error)
{
	int result = STATUS_OK;
	struct expression *out = calloc(1, sizeof(struct expression));
	*out_ptr = out;
	out->type = in->type;	/* most types of expression stay the same */

	if ((in->type <= EXPR_NONE) ||
	    (in->type >= NUM_EXPR_TYPES)) {
		asprintf(error, "bad expression type: %d", in->type);
		return STATUS_ERR;
	}
	switch (in->type) {
	case EXPR_ELLIPSIS:
		break;
	case EXPR_INTEGER:		/* copy as-is */
		out->value.num = in->value.num;
		break;
	case EXPR_LINGER:		/* copy as-is */
		memcpy(&out->value.linger, &in->value.linger,
		       sizeof(in->value.linger));
		break;
	case EXPR_WORD:
		out->type = EXPR_INTEGER;
		if (symbol_to_int(in->value.string,
				  &out->value.num, error))
			return STATUS_ERR;
		break;
	case EXPR_STRING:
		if (unescape_cstring_expression(in->value.string, out, error))
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
	case EXPR_POLLFD:
		result = evaluate_pollfd_expression(in, out, error);
		break;
	case EXPR_NONE:
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
