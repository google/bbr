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
 * A module to execute a command from a test script.
 */

#include "run_command.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "logging.h"
#include "run.h"
#include "script.h"
#include "system.h"

void run_command_event(
	struct state *state, struct event *event, struct command_spec *command)
{
	DEBUGP("%d: command: `%s`\n", event->line_number,
	       command->command_line);

	/* Wait for the right time before firing off this event. */
	wait_for_event(state);

	char *error = NULL;
	if (safe_system(command->command_line, &error))
		goto error_out;
	return;

error_out:
	die("%s:%d: error executing `%s` command: %s\n",
	    state->config->script_path, event->line_number,
	    command->command_line, error);
	free(error);
}
