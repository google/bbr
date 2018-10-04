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
 * Interface for the test script execution module.
 *
 * Threading And Locking Model
 *
 * There are two threads in our process:
 *
 *  1) main thread: this is the thread that invokes main() and
 *     does most of the work of test execution.
 *
 *  2) blocking system call thread: this is the thread that
 *     executes blocking system calls.
 *
 * To keep things as simple as possible, there is a single global
 * mutex, state->mutex, which protects all global data (data that is
 * not purely local to a function).
 *
 * The main thread holds the global mutex for almost the entire
 * duration of a test run. It unlocks the mutex only for:
 *
 *   o sleeping while waiting for the start time of the next event
 *   o waiting for the system call thread to block on a system call
 *   o waiting for the system call thread to exit
 *
 * The system call thread runs briefly, only to execute blocking
 * system calls, and holds the global mutex for the entire duration it
 * is running, from interpreting system call arguments to processing
 * system call outputs. It unlocks the mutex only for:
 *
 *   o sleeping while waiting for the start time of the system call
 *   o the actual function call to invoke the blocking system call itself
 */

#ifndef __RUN_H__
#define __RUN_H__

#include "types.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "code.h"
#include "config.h"
#include "fd_state.h"
#include "netdev.h"
#include "run_packet.h"
#include "run_system_call.h"
#include "script.h"
#include "socket.h"
#include "so_testing.h"
#include "wire_client.h"

/* Public top-level entry point for executing a test script */
extern void run_script(struct config *config,
		       struct script *script);

/* Public entry-point to parse a script and finalize config. If the
 * script_buffer is provided, parse that. Otherwise, read the file
 * with the given path, parse that.
 */
extern int parse_script_and_set_config(int argc, char *argv[],
				       struct config *config,
				       struct script *script,
				       const char *script_path,
				       const char *script_buffer);

/* Private implementation details follow below... */

/* All the runtime state for a test. */
struct state {
	pthread_mutex_t mutex;		/* global lock for all global state */
	struct config *config;		/* test configuration */
	struct netdev *netdev;		/* for sending/receiving TCP packets */
	struct packets *packets;	/* for processing packets */
	struct syscalls *syscalls;	/* for running system calls */
	struct fd_state *fds;		/* list of all file descriptors */
	struct socket *socket_under_test;	/* socket handling packets */
	struct script *script;			/* script we're running */
	struct event *event;			/* the current event */
	struct event *last_event;		/* previous event */
	struct code_state *code;	/* for running post-processing code */
	struct wire_client *wire_client;	/* for on-the-wire tests */
	struct so_instance *so_instance;	/* for SO testing */
	s64 script_start_time_usecs;	/* time of first event in script */
	s64 script_last_time_usecs;	/* time of previous event in script */
	s64 live_start_time_usecs;	/* time of first event in live test */
	int num_events;			/* events executed so far */
};

/* Allocate all run-time state for executing a test script. */
extern struct state *state_new(struct config *config,
			       struct script *script,
			       struct netdev *netdev);

/* Free all run-time state for a test. */
void state_free(struct state *state);

/* Add the file descriptor to the list of run-time file descriptors. */
void state_add_fd(struct state *state, struct fd_state *fd);

/* Grab the global lock for all global state. */
static inline void run_lock(struct state *state)
{
	if (pthread_mutex_lock(&state->mutex) != 0)
		die_perror("pthread_mutex_lock");
}

/* Release the global lock for all global state. */
static inline void run_unlock(struct state *state)
{
	if (pthread_mutex_unlock(&state->mutex) != 0)
		die_perror("pthread_mutex_unlock");
}

/* Get the wall clock time of day in microseconds. */
extern s64 now_usecs(struct state *state);

/* Convert script time to live wall clock time. */
static inline s64 script_time_to_live_time_usecs(struct state *state,
						 s64 script_time_usecs)
{
	s64 offset_usecs = script_time_usecs - state->script_start_time_usecs;
	s64 live_time_usecs = state->live_start_time_usecs + offset_usecs;
	return live_time_usecs;
}

/* Convert live wall clock time to script time. */
static inline s64 live_time_to_script_time_usecs(struct state *state,
						 s64 live_time_usecs)
{
	s64 offset_usecs = live_time_usecs - state->live_start_time_usecs;
	s64 script_time_usecs = state->script_start_time_usecs + offset_usecs;
	return script_time_usecs;
}

/* Get the time of the last event if exists, or NO_TIME_RANGE. */
static inline s64 last_event_time_usecs(struct state *state)
{
	return state->last_event == NULL ? NO_TIME_RANGE :
			state->last_event->time_usecs;
}

/*
 * See if something that happened at the given actual live wall time
 * in microseconds happened reasonably close to the time at which we
 * wanted it to happen in the script. verify_time compares the
 * given script and live times and returns STATUS_OK on success or on
 * failure returns STATUS_ERR and fills in *error using the given
 * description.  The check_event_time variant is a shortcut
 * for the common case: it looks at the current event and on failure
 * it prints the error message to stderr and exits with an error
 * status.  For time ranges the end time is specified in script_usecs_end.
 */
extern int verify_time(struct state *state, enum event_time_t time_type,
		       s64 script_usecs, s64 script_usecs_end,
		       s64 live_usecs, s64 last_event_usecs,
		       const char *description, char **error);
extern void check_event_time(struct state *state, s64 live_usecs);

/* Set the start (and end time, if applicable) for the event if it
 * uses wildcard or relative timing.
 */
extern void adjust_relative_event_times(struct state *state,
					struct event *event);

/*
 * Sleep and/or spin until the time at which we want the current event
 * to happen.
 */
extern void wait_for_event(struct state *state);

/* Advance the interpreter state to the next event. */
extern int get_next_event(struct state *state, char **error);

/* Set a higher priority for ourselves, to reduce test timing noise. */
extern void set_scheduling_priority(void);

/* Try to pin our pages into RAM. */
extern void lock_memory(void);

/* Run final command we always execute at end of script, to clean up. */
extern int run_cleanup_command(void);

#endif /* __RUN_H__ */
