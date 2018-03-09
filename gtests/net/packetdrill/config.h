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
 * Configuration information for a test run, and helper functions.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "types.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include "ip_address.h"
#include "ip_prefix.h"
#include "script.h"

#define TUN_DRIVER_SPEED_CUR	0	/* don't change current speed */
#define TUN_DRIVER_DEFAULT_MTU 1500	/* default MTU for tun device */

extern struct option options[];

/* A linked list of symbol->value (FOO=bar) definitions from command line. */
struct definition {
	char *symbol;	/* name of the symbol; owns the string */
	char *value;	/* value of the symbol; owns the string */
	struct definition *next;	/* link for linked list */
};

/* Return the definition in the linked list with a matching symbol, or NULL */
static inline struct definition *definition_find(struct definition *defs,
						 char *symbol)
{
	struct definition *def = NULL;

	for (def = defs; def != NULL; def = def->next) {
		if (strcmp(def->symbol, symbol) == 0)
			return def;
	}
	return NULL;
}

/* Set the value of the given symbol to the given value. */
static inline void definition_set(struct definition **defs,
				  char *symbol, char *value)
{
	struct definition *def = definition_find(*defs, symbol);

	if (def) {
		free(def->value);
		def->value = value;
	} else {
		def = calloc(1, sizeof(struct definition));
		def->symbol = symbol;
		def->value = value;
		def->next = *defs;	/* link to existing entries */
		*defs = def;	/* insert at head of linked list */
	}
}

/* Return the value of the given symbol, or NULL if not found. */
static inline char *definition_get(struct definition *defs, char *symbol)
{
	struct definition *def = definition_find(defs, symbol);

	return def ? def->value : NULL;
}

struct config {
	const char **argv;			/* a copy of process argv */

	enum ip_version_t ip_version;		/* v4, v4-mapped-v6, v6 */
	int socket_domain;			/* AF_INET or AF_INET6 */
	int wire_protocol;			/* AF_INET or AF_INET6 */

	u16 live_bind_port;			/* local port for bind() */
	u16 live_connect_port;			/* remote port for connect() */

	struct ip_address live_bind_ip;		/* address for bind() */
	struct ip_address live_connect_ip;	/* address for connect() */

	struct ip_address live_local_ip;	/* local interface IP */
	struct ip_address live_remote_ip;	/* remote interface IP */
	struct ip_prefix live_remote_prefix;	/* remote prefix under test */
	struct ip_address live_gateway_ip;	/* gateway interface IP */

	char live_local_ip_string[ADDR_STR_LEN];	/* human-readable IP */
	char live_remote_ip_string[ADDR_STR_LEN];	/* human-readable IP */
	char live_remote_prefix_string[ADDR_STR_LEN];	/* <addr>/<prefixlen> */

	char live_gateway_ip_string[ADDR_STR_LEN];	/* local gateway IP */
	char live_netmask_ip_string[ADDR_STR_LEN];	/* local netmask */

	int live_prefix_len;		/* IPv4/IPv6 interface prefix len */

	long tolerance_usecs;		/* tolerance for time divergence */
	double tolerance_percent;   /* tolerance for time divergence in percent */

	bool tcp_ts_ecr_scaled;		/* scale arbitrary inbound TS ECR? */
	int tcp_ts_tick_usecs;		/* microseconds per TS val tick */

	u32 speed;			/* speed reported by tun driver;
					 * may require special tun driver
					 */
	int mss;			/* gso_size for GRO packets to tun device */
	int mtu;			/* MTU of tun device */

	bool strict_segments;		/* check exact segmentation? */

	bool non_fatal_packet;		/* treat packet asserts as non-fatal */
	bool non_fatal_syscall;		/* treat syscall asserts as non-fatal */
	bool send_omit_free;		/* do not call free() */

	bool dry_run;			/* parse script but don't execute? */

	bool verbose;			/* print detailed debug info? */
	char *script_path;		/* pathname of script file */

	/* Shell command to invoke via system(3) to run post-processing code */
	char *code_command_line;

	/* Language to emit when generating post-processing code */
	char *code_format;

	/* setsockopt option number (TCP_INFO, ...) for code */
	char *code_sockopt;

	/* File scripts to run at beginning of test (using system) */
	char *init_scripts;

	/* For remote on-the-wire testing using a real NIC. */
	bool is_wire_client;		   /* use a real NIC and be client? */
	bool is_wire_server;		   /* use a real NIC and be server? */
	char *wire_client_device;	   /* iface name for send/receive */
	char *wire_server_device;	   /* iface name for send/receive */
	struct ip_address wire_server_ip;  /* IP of on-the-wire server */
	char *wire_server_ip_string;	   /* malloc-ed server IP string */
	u16 wire_server_port;		   /* the port the server listens on */

	/* For testing against a shared object (*.so) file. */
	char *so_filename;
	char *so_flags;

	/* For anyip testing */
	bool is_anyip;

	/* List of FOO=bar definitions from command line. */
	struct definition *defines;
};

/* Top-level info about the invocation of a test script */
struct invocation {
	int		argc;		/* count of process command line args */
	char		**argv;		/* process command line args */
	struct config *config;		/* run-time configuration */
	struct script *script;		/* parse tree of the script to run */
};

/* Set default configuration */
extern void set_default_config(struct config *config);

/* Parse the "non-fatal" command line options given the (comma-delimited) string
 * from the command line.  Modifies the associated booleans in the given
 * config.
 */
extern void parse_non_fatal_arg(char *arg, struct config *config);

/* Perform configuration processing that can only be done after we've
 * seen the full config. For example, we only know how to use IP
 * addresses after we know if we're doing ipv4, ipv4-mapped-ipv6, or
 * ipv6. Call this after all options have been parsed.
 */
extern void finalize_config(struct config *config);

extern void show_usage(void);

/* Parse command line options. Returns a pointer to the first argument
 * beyond the options.
 */
extern char **parse_command_line_options(int argc, char *argv[],
					 struct config *config);

/* The parser calls this function to finalize processing of config info. */
extern void parse_and_finalize_config(struct invocation *invocation);

#endif /* __CONFIG_H__ */
