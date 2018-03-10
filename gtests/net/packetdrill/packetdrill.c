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
 * This is the main() for the packetdrill TCP testing tool.
 */

#include "types.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "assert.h"
#include "config.h"
#include "parse.h"
#include "run.h"
#include "script.h"
#include "system.h"
#include "wire_server.h"

static void run_init_scripts(struct config *config)
{
	char *cp1, *cp2, *scripts, *error;

	if (config->init_scripts == NULL)
		return;

	cp1 = scripts = strdup(config->init_scripts);
	while (*cp1 != 0) {
		cp2 = strstr(cp1, ",");
		if (cp2 != NULL)
			*cp2 = 0;
		if (safe_system(cp1, &error)) {
			die("%s: error executing init script '%s': %s\n",
			    config->script_path, cp1, error);
		}
		if (cp2 == NULL)
			break;
		else
			cp1 = cp2 + 1;
	}
	free(scripts);
}

int main(int argc, char *argv[])
{
	struct config config;
	set_default_config(&config);
	/* Get command line options and list of test scripts. */
	char **arg = parse_command_line_options(argc, argv, &config);

	/* If we're running as a server, just listen for connections forever. */
	if (config.is_wire_server) {
		if (*arg != NULL) {
			fprintf(stderr,
				"error: do not pass script paths to "
				"the wire server on command line\n");
			show_usage();
			exit(EXIT_FAILURE);
		}

		run_wire_server(&config);
		return 0;
	}

	/* Ensure that there is at least one script path, to avoid
	 * confusion between the lack of output caused by "all tests
	 * passing" and "no tests listed on command line".
	 */
	if (*arg == NULL) {
		fprintf(stderr, "error: missing script path\n");
		show_usage();
		exit(EXIT_FAILURE);
	}

	/* Parse and run each script on the command line. */
	for (; *arg != NULL; ++arg) {
		struct script script;
		const char *script_path = *arg;

		if (parse_script_and_set_config(argc, argv, &config, &script,
						script_path, NULL))
			exit(EXIT_FAILURE);

		/* If --dry_run, then don't actually execute the script. */
		if (config.dry_run)
			continue;

		run_init_scripts(&config);
		run_script(&config, &script);
	}

	return 0;
}
