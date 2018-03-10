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
 * Implementation for module for formatting ICMP packets.
 */

#include "icmp_packet.h"

#include "icmp.h"
#include "icmpv6.h"
#include "ip_packet.h"

/* A table entry mapping an ICMP code string to byte. */
struct icmp_code_info {
	u8 code_byte;				/* type byte on the wire */
	const char *code_string;		/* human-readable code */
};

/* A table entry mapping an ICMP type string to byte and code table. */
struct icmp_type_info {
	u8 type_byte;				  /* type byte on the wire */
	const char *type_string;		  /* human-readable type */
	const struct icmp_code_info *code_table;  /* codes for this type */
};

/* Values for the 'code' byte of an IPv4 ICMP_DEST_UNREACH header (RFC 1700). */
struct icmp_code_info icmpv4_unreachable_codes[] = {
	{ ICMP_NET_UNREACH,	"net_unreachable" },
	{ ICMP_HOST_UNREACH,	"host_unreachable" },
	{ ICMP_PROT_UNREACH,	"protocol_unreachable" },
	{ ICMP_PORT_UNREACH,	"port_unreachable" },
	{ ICMP_FRAG_NEEDED,	"frag_needed" },
	{ ICMP_SR_FAILED,	"source_route_failed" },
	{ ICMP_NET_UNKNOWN,	"net_unknown" },
	{ ICMP_HOST_UNKNOWN,	"host_unknown" },
	{ ICMP_HOST_ISOLATED,	"source_host_isolated" },
	{ ICMP_NET_ANO,		"net_prohibited" },
	{ ICMP_HOST_ANO,	"host_prohibited" },
	{ ICMP_NET_UNR_TOS,	"net_unreachable_for_tos" },
	{ ICMP_HOST_UNR_TOS,	"host_unreachable_for_tos" },
	{ ICMP_PKT_FILTERED,	"packet_filtered" },
	{ ICMP_PREC_VIOLATION,	"precedence_violation" },
	{ ICMP_PREC_CUTOFF,	"precedence_cutoff" },
	{ 0, NULL },
};

/* Information about the supported types of ICMPv4 header (RFC 1700). */
struct icmp_type_info icmpv4_types[] = {
	{ ICMP_ECHOREPLY,	"echo_reply" },
	{ ICMP_DEST_UNREACH,	"unreachable", icmpv4_unreachable_codes },
	{ ICMP_SOURCE_QUENCH,	"source_quench" },
	{ ICMP_REDIRECT,	"redirect" },
	{ ICMP_ECHO,		"echo_request" },
	{ ICMP_TIME_EXCEEDED,	"time_exceeded" },
	{ ICMP_PARAMETERPROB,	"parameter_problem" },
	{ ICMP_TIMESTAMP,	"timestamp_request" },
	{ ICMP_TIMESTAMPREPLY,	"timestamp_reply" },
	{ ICMP_INFO_REQUEST,	"information_request" },
	{ ICMP_INFO_REPLY,	"information_reply" },
	{ ICMP_ADDRESS,		"address_mask_request" },
	{ ICMP_ADDRESSREPLY,	"address_mask_reply" },
	{ 0, NULL, NULL },
};

/* Values for the 'code' byte of an ICMPV6_DEST_UNREACH header (RFC 2463). */
struct icmp_code_info icmpv6_unreachable_codes[] = {
	{ ICMP_NET_UNREACH,		"net_unreachable" },
	{ ICMPV6_NOROUTE,		"no_route" },
	{ ICMPV6_ADM_PROHIBITED,	"admin_prohibited" },
	{ ICMPV6_NOT_NEIGHBOUR,		"not_neighbour" },
	{ ICMPV6_ADDR_UNREACH,		"address_unreachable" },
	{ ICMPV6_PORT_UNREACH,		"port_unreachable" },
	{ 0, NULL },
};

/* Values for the 'code' byte of an ICMPV6_TIME_EXCEED header (RFC 2463). */
struct icmp_code_info icmpv6_time_exceed_codes[] = {
	{ ICMPV6_EXC_HOPLIMIT,		"exceeded_hop_limit" },
	{ ICMPV6_EXC_FRAGTIME,		"exceeded_frag_time" },
	{ 0, NULL },
};

/* Values for the 'code' byte of an ICMPV6_PARAMPROB header (RFC 2463). */
struct icmp_code_info icmpv6_paramprob_codes[] = {
	{ ICMPV6_HDR_FIELD,		"header_field" },
	{ ICMPV6_UNK_NEXTHDR,		"unknown_next_header" },
	{ ICMPV6_UNK_OPTION,		"unknown_option" },
	{ 0, NULL },
};

/* Information about the supported types of ICMPv6 header (RFC 2463). */
struct icmp_type_info icmpv6_types[] = {
	{ ICMPV6_DEST_UNREACH,	"unreachable", icmpv6_unreachable_codes },
	{ ICMPV6_PKT_TOOBIG,	"packet_too_big" },
	{ ICMPV6_TIME_EXCEED,	"time_exceeded", icmpv6_time_exceed_codes },
	{ ICMPV6_PARAMPROB,	"parameter_problem", icmpv6_paramprob_codes },
	{ ICMPV6_ECHO_REQUEST,  "echo_request" },
	{ ICMPV6_ECHO_REPLY,    "echo_reply" },
	{ 0, NULL, NULL },
};

/* Return the ICMP protocol number for the given address family. */
static int icmp_protocol(int address_family)
{
	if (address_family == AF_INET)
		return IPPROTO_ICMP;
	else if (address_family == AF_INET6)
		return IPPROTO_ICMPV6;
	else
		assert(!"bad ip version");
	return 0;
}

/* Return the length in bytes of the ICMP header. */
static int icmp_header_len(int address_family)
{
	if (address_family == AF_INET)
		return sizeof(struct icmpv4);
	else if (address_family == AF_INET6)
		return sizeof(struct icmpv6);
	else
		assert(!"bad ip version");
	return 0;
}

/* Fill in ICMPv4 header fields. */
static int set_icmpv4_header(struct icmpv4 *icmpv4, u8 type, u8 code,
			     s64 mtu, u16 echo_id, char **error)
{
	icmpv4->type = type;
	icmpv4->code = code;
	icmpv4->checksum = htons(0);

	if (mtu >= 0) {
		if ((type != ICMP_DEST_UNREACH) || (code != ICMP_FRAG_NEEDED)) {
			asprintf(error,
				 "ICMPv4 MTU is only valid for "
				 "unreachable-frag_needed");
			return STATUS_ERR;
		}
		if (!is_valid_u16(mtu)) {
			asprintf(error, "ICMPv4 MTU out of 16-bit range");
			return STATUS_ERR;
		}
		icmpv4->message.frag.mtu = htons(mtu);
	}
	if (echo_id > 0)
		icmpv4->message.echo.id = htons(echo_id);

	return STATUS_OK;
}

/* Fill in ICMPv4 header fields. */
static int set_icmpv6_header(struct icmpv6 *icmpv6, u8 type, u8 code,
			     s64 mtu, u16 echo_id, char **error)
{
	icmpv6->type = type;
	icmpv6->code = code;
	icmpv6->checksum = htons(0);

	if (mtu >= 0) {
		if ((type != ICMPV6_PKT_TOOBIG) || (code != 0)) {
			asprintf(error,
				 "ICMPv6 MTU is only valid for "
				 "packet_too_big-0");
			return STATUS_ERR;
		}
		if (!is_valid_u32(mtu)) {
			asprintf(error, "ICMPv6 MTU out of 32-bit range");
			return STATUS_ERR;
		}
		icmpv6->message.packet_too_big.mtu = htonl(mtu);
	}
	if (echo_id > 0) {
		icmpv6->message.u_echo.identifier = htons(echo_id);
	}
	return STATUS_OK;
}

/* Populate ICMP header fields. */
static int set_packet_icmp_header(struct packet *packet, void *icmp,
				  int address_family, int icmp_bytes,
				  u8 type, u8 code, s64 mtu, u16 echo_id,
				  char **error)
{
	struct header *icmp_header = NULL;

	if (address_family == AF_INET) {
		struct icmpv4 *icmpv4 = (struct icmpv4 *) icmp;
		packet->icmpv4 = icmpv4;
		assert(packet->icmpv6 == NULL);
		icmp_header = packet_append_header(packet, HEADER_ICMPV4,
						   sizeof(*icmpv4));
		icmp_header->total_bytes = icmp_bytes;
		return set_icmpv4_header(icmpv4, type, code, mtu, echo_id, error);
	} else if (address_family == AF_INET6) {
		struct icmpv6 *icmpv6 = (struct icmpv6 *) icmp;
		packet->icmpv6 = icmpv6;
		assert(packet->icmpv4 == NULL);
		icmp_header = packet_append_header(packet, HEADER_ICMPV6,
						   sizeof(*icmpv6));
		icmp_header->total_bytes = icmp_bytes;
		return set_icmpv6_header(icmpv6, type, code, mtu, echo_id, error);
	} else {
		assert(!"bad ip_version in config");
	}
	return STATUS_ERR;
}

/* Parse the given ICMP type and code strings, and fill in the
 * *type and *code with the results. If there is an error during
 * parsing, fill in *error and return STATUS_ERR; otherwise return
 * STATUS_OK.
 */
static int parse_icmp_type_and_code(int address_family,
				    const char *type_string,
				    const char *code_string,
				    s32 *type, s32 *code, char **error)
{
	int i = 0;
	const struct icmp_type_info *icmp_types = NULL;
	const struct icmp_code_info *code_table = NULL; /* for this type */

	if (address_family == AF_INET)
		icmp_types = icmpv4_types;
	else if (address_family == AF_INET6)
		icmp_types = icmpv6_types;
	else
		assert(!"bad ip_version in config");

	/* Parse the type string. */
	if (sscanf(type_string, "type_%d", type) == 1) {
		/* Legal but non-standard type in tcpdump-inspired notation. */
	} else {
		/* Look in our table of known types. */
		for (i = 0; icmp_types[i].type_string != NULL; ++i) {
			if (!strcmp(type_string, icmp_types[i].type_string)) {
				*type = icmp_types[i].type_byte;
				code_table = icmp_types[i].code_table;
			}
		}
	}
	if (!is_valid_u8(*type)) {
		asprintf(error, "bad ICMP type %s", type_string);
		return STATUS_ERR;
	}

	/* Parse the code string. */
	if (code_string == NULL) {
		*code = 0;		/* missing code means code = 0 */
	} else if (sscanf(code_string, "code_%d", code) == 1) {
		/* Legal but non-standard code in tcpdump-inspired notation. */
	} else if (code_table != NULL) {
		/* Look in our table of known codes. */
		for (i = 0; code_table[i].code_string != NULL; ++i) {
			if (!strcmp(code_string, code_table[i].code_string))
				*code = code_table[i].code_byte;
		}
	}
	if (!is_valid_u8(*code)) {
		asprintf(error, "bad ICMP code %s", code_string);
		return STATUS_ERR;
	}

	return STATUS_OK;
}

struct packet *new_icmp_packet(int address_family,
				enum direction_t direction,
				const char *type_string,
				const char *code_string,
				int protocol,
				u32 tcp_start_sequence,
				u32 payload_bytes,
				struct ip_info ip_info,
				s64 mtu,
				s64 echo_id,
				char **error)
{
	s32 type = -1;	/* bad type; means "unknown so far" */
	s32 code = -1;	/* bad code; means "unknown so far" */

	struct packet *packet = NULL;  /* the newly-allocated result packet */
	/* Calculate lengths in bytes of all sections of the packet.
	 * For TCP/UDP, for now we only support the most common ICMP message
	 * format, which includes at the end the original outgoing IP
	 * header and the first 8 bytes after that (which will
	 * typically have the port info needed to demux the message).
	 * For RAW, we pad the icmp packet with 0 and the total length is
	 * payload_bytes.
	 */
	const int ip_fixed_bytes = ip_header_min_len(address_family);
	const int ip_option_bytes = 0;
	const int ip_header_bytes = ip_fixed_bytes + ip_option_bytes;
	int echoed_bytes = 0;
	int icmp_bytes = 0;
	int ip_bytes = 0;

	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		echoed_bytes = ip_fixed_bytes + ICMP_ECHO_BYTES;
		icmp_bytes = icmp_header_len(address_family) + echoed_bytes;
		ip_bytes = ip_header_bytes + icmp_bytes;
	} else if (protocol == IPPROTO_RAW) {
		echoed_bytes = 0;
		icmp_bytes = payload_bytes;
		ip_bytes = ip_header_bytes + payload_bytes;
	}

	/* Sanity-check on echo_id to make sure it fits in u16 */
	if (echo_id < 0 || echo_id > 65535) {
		asprintf(error,
			 "invalid echo_id, must be between 0 and 65535");
		goto error_out;
	}

	/* Sanity-check all the various lengths */
	if (ip_option_bytes & 0x3) {
		asprintf(error, "IP options are not padded correctly "
			 "to ensure IP header is a multiple of 4 bytes: "
			 "%d excess bytes", ip_option_bytes & 0x3);
		goto error_out;
	}
	assert((ip_header_bytes & 0x3) == 0);
	if (icmp_bytes < icmp_header_len(address_family)) {
		asprintf(error, "icmp_bytes %d smaller than icmp header "
			 "length %d",
			 icmp_bytes, icmp_header_len(address_family));
		goto error_out;
	}


	/* Parse the ICMP type and code */
	if (parse_icmp_type_and_code(address_family, type_string, code_string,
				     &type, &code, error))
		goto error_out;
	assert(is_valid_u8(type));
	assert(is_valid_u8(code));

	/* Allocate and zero out a packet object of the desired size */
	packet = packet_new(ip_bytes);
	memset(packet->buffer, 0, ip_bytes);

	packet->direction = direction;
	packet->flags = 0;
	packet->tos_chk = ip_info.tos.check;

	/* Set IP header fields */
	set_packet_ip_header(packet, address_family, ip_bytes, ip_info.tos.value,
			     ip_info.flow_label, ip_info.ttl,
			     icmp_protocol(address_family));

	/* Find the start of the ICMP header and then populate common fields. */
	void *icmp_header = ip_start(packet) + ip_header_bytes;
	if (set_packet_icmp_header(packet, icmp_header, address_family,
				   icmp_bytes, type, code, mtu, echo_id, error))
		goto error_out;

	/* All ICMP message types currently supported by this tool
	 * include a copy of the outbound IP header and the first few
	 * bytes inside. To ensure that the inbound ICMP message gets
	 * demuxed to the correct socket in the kernel, here we
	 * construct enough of a basic IP header and during test
	 * execution we fill in the port numbers and (if specified)
	 * TCP sequence number in the TCP header.
	 */
	if (echoed_bytes) {
		u8 *echoed_ip = packet_echoed_ip_header(packet);
		const int echoed_ip_bytes = (ip_fixed_bytes +
					     layer4_header_len(protocol) +
					     payload_bytes);
		set_ip_header(echoed_ip, address_family, echoed_ip_bytes,
			      0, 0, 0, protocol);
		if (protocol == IPPROTO_TCP) {
			u32 *seq = packet_echoed_tcp_seq(packet);
			*seq = htonl(tcp_start_sequence);
		}
		packet->echoed_header = true;
	} else
		packet->echoed_header = false;

	packet->ip_bytes = ip_bytes;
	return packet;

error_out:
	if (packet != NULL)
		packet_free(packet);
	return NULL;
}
