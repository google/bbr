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
 * A module to execute a system(3) shell command and check the result.
 */

#include "system.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int safe_system(const char *command, char **error)
{
	int status = system(command);
	if (status == -1) {
		asprintf(error, "%s", strerror(errno));
		return STATUS_ERR;
	}
	if (WIFSIGNALED(status) &&
	    (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGQUIT)) {
		asprintf(error, "got signal %d (%s)",
			 WTERMSIG(status), strsignal(WTERMSIG(status)));
		return STATUS_ERR;
	}
	if (WEXITSTATUS(status) != 0) {
		asprintf(error, "non-zero status %d", WEXITSTATUS(status));
		return STATUS_ERR;
	}
	return STATUS_OK;
}
