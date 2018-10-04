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
 * Implementation for the test script execution module.
 */

#include "run.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <unistd.h>
#include "ip.h"
#include "logging.h"
#include "netdev.h"
#include "wire_client_netdev.h"
#include "parse.h"
#include "run_command.h"
#include "run_packet.h"
#include "run_system_call.h"
#include "script.h"
#include "so_testing.h"
#include "socket.h"
#include "system.h"
#include "tcp.h"
#include "tcp_options.h"

/* MAX_SPIN_USECS is the maximum amount of time (in microseconds) to
 * spin waiting for an event. We sleep up until this many microseconds
 * before a script event. We get the best results on tickless
 * (CONFIG_NO_HZ=y) kernels when we try to sleep until the exact jiffy
 * of a script event; this reduces the staleness/noise we see in
 * jiffies values on tickless kernels, since the kernel updates the
 * jiffies value at the time we wake, and then we execute the test
 * event shortly thereafter. The value below was chosen experimentally
 * based on experiences on a 2.2GHz machine for which there was a
 * measured overhead of roughly 15 usec for the unlock/usleep/lock
 * sequence that wait_for_event() must execute while waiting
 * for the next event.
 */
const int MAX_SPIN_USECS = 20;
/* Global bool init_cmd_exed */
bool init_cmd_exed = false;

/* Final command to always execute at end of script, in order to clean up: */
const char *cleanup_cmd;

/* Path of currently-executing script, for use in cleanup command errors: */
const char *script_path;

struct state *state_new(struct config *config,
			struct script *script,
			struct netdev *netdev)
{
	struct state *state = calloc(1, sizeof(struct state));

	if (pthread_mutex_init(&state->mutex, NULL) != 0)
		die_perror("pthread_mutex_init");

	run_lock(state);

	state->config = config;
	state->script = script;
	state->netdev = netdev;
	state->packets = packets_new(state);
	state->syscalls = syscalls_new(state);
	state->code = code_new(config);
	state->fds = NULL;
	state->num_events = 0;
	return state;
}

/* Add the file descriptor to the list of run-time file descriptors. */
void state_add_fd(struct state *state, struct fd_state *fd)
{
	fd->next = state->fds;
	state->fds = fd;
}

/* Close all sockets, free all the socket structs, and send a RST
 * packet to clean up kernel state for each connection.
 * TODO(ncardwell): centralize error handling and ensure test errors
 * always result in a call to these clean-up functions, so we can make
 * sure to reset connections in all cases.
 */
static void close_all_fds(struct state *state)
{
	struct fd_state *fd = state->fds, *dead_fd = NULL;

	while (fd != NULL) {
		dead_fd = fd;
		fd = fd->next;
		dead_fd->ops->close(state, dead_fd);
	}
}

void state_free(struct state *state)
{
	/* We have to stop the system call thread first, since it's using
	 * sockets that we want to close and reset.
	 */
	syscalls_free(state, state->syscalls);

	/* Then we close the sockets and reset the connections, while
	 * we still have a netdev for injecting reset packets to free
	 * per-connection kernel state.
	 */
	close_all_fds(state);

	netdev_free(state->netdev);
	packets_free(state->packets);
	code_free(state->code);

	if (state->wire_client)
		wire_client_free(state->wire_client);

	if (state->so_instance)
		so_instance_free(state->so_instance);

	run_unlock(state);
	if (pthread_mutex_destroy(&state->mutex) != 0)
		die_perror("pthread_mutex_destroy");

	memset(state, 0, sizeof(*state));  /* paranoia to help catch bugs */
	free(state);
}

s64 now_usecs(struct state *state)
{
	struct timeval tv;
	if (state->so_instance) {
		if (state->so_instance->ifc.gettimeofday(
			state->so_instance->ifc.userdata, &tv, NULL) < 0)
			die_perror("gettimeofday");
	} else {
		if (gettimeofday(&tv, NULL) < 0)
			die_perror("gettimeofday");
	}
	return timeval_to_usecs(&tv);
}

/*
 * Verify that something happened at the expected time.
 * WARNING: verify_time() should not be looking at state->event
 * because in some cases (checking the finish time for blocking system
 * calls) we call verify_time() at a time when state->event
 * points at an event other than the one whose time we're currently
 * checking.
 */
int verify_time(struct state *state, enum event_time_t time_type,
		s64 script_usecs, s64 script_usecs_end,
		s64 live_usecs, s64 last_event_usecs,
		const char *description, char **error)
{
	s64 expected_usecs = script_usecs - state->script_start_time_usecs;
	s64 expected_usecs_end = script_usecs_end -
		state->script_start_time_usecs;
	s64 actual_usecs = live_usecs - state->live_start_time_usecs;
	long tolerance_usecs = state->config->tolerance_usecs;

	DEBUGP("expected: %.3f actual: %.3f  (secs)\n",
	       usecs_to_secs(script_usecs), usecs_to_secs(actual_usecs));

	if (time_type == ANY_TIME)
		return STATUS_OK;

	if (last_event_usecs != NO_TIME_RANGE) {
		s64 delta = script_usecs - last_event_usecs;
		long dynamic_tolerance;

		dynamic_tolerance = (state->config->tolerance_percent / 100.0) * delta;
		if (dynamic_tolerance > tolerance_usecs)
			tolerance_usecs = dynamic_tolerance;
	}
	if (time_type == ABSOLUTE_RANGE_TIME ||
	    time_type == RELATIVE_RANGE_TIME) {
		DEBUGP("expected_usecs_end %.3f\n",
		       usecs_to_secs(script_usecs_end));
		if (actual_usecs < (expected_usecs - tolerance_usecs) ||
		    actual_usecs > (expected_usecs_end + tolerance_usecs)) {
			if (time_type == ABSOLUTE_RANGE_TIME) {
				asprintf(error,
					 "timing error: expected "
					 "%s in time range %.6f~%.6f sec "
					 "but happened at %.6f sec",
					 description,
					 usecs_to_secs(script_usecs),
					 usecs_to_secs(script_usecs_end),
					 usecs_to_secs(actual_usecs));
			} else if (time_type == RELATIVE_RANGE_TIME) {
				s64 offset_usecs = state->event->offset_usecs;
				asprintf(error,
					 "timing error: expected "
					 "%s in relative time range +%.6f~+%.6f "
					 "sec but happened at %+.6f sec",
					 description,
					 usecs_to_secs(script_usecs -
						       offset_usecs),
					 usecs_to_secs(script_usecs_end -
						       offset_usecs),
					 usecs_to_secs(actual_usecs -
						       offset_usecs));
			}
			return STATUS_ERR;
		} else {
			return STATUS_OK;
		}
	}

	if ((actual_usecs < (expected_usecs - tolerance_usecs)) ||
	    (actual_usecs > (expected_usecs + tolerance_usecs))) {
		asprintf(error,
			 "timing error: "
			 "expected %s at %.6f sec but happened at %.6f sec; "
			 "tolerance %.6f sec",
			 description,
			 usecs_to_secs(script_usecs),
			 usecs_to_secs(actual_usecs),
			 usecs_to_secs(tolerance_usecs));
		return STATUS_ERR;
	} else {
		return STATUS_OK;
	}
}

/* Return a static string describing the given event, for error messages. */
static const char *event_description(struct event *event)
{
	enum direction_t direction = DIRECTION_INVALID;

	if ((event->type <= INVALID_EVENT) ||
	    (event->type >= NUM_EVENT_TYPES)) {
		die("bogus event type: %d", event->type);
	}
	switch (event->type) {
	case PACKET_EVENT:
		direction = packet_direction(event->event.packet);
		if (direction == DIRECTION_INBOUND)
			return "inbound packet";
		else if (direction == DIRECTION_OUTBOUND)
			return "outbound packet";
		else
			assert(!"bad direction");
		break;
	case SYSCALL_EVENT:
		return "system call start";
	case COMMAND_EVENT:
		return "command";
	case CODE_EVENT:
		return "data collection for code";
	case INVALID_EVENT:
	case NUM_EVENT_TYPES:
		assert(!"bogus type");
		break;
	/* We omit default case so compiler catches missing values. */
	}
	return "invalid event";
}

void check_event_time(struct state *state, s64 live_usecs)
{
	char *error = NULL;
	const char *description = event_description(state->event);
	if (verify_time(state,
			state->event->time_type,
			state->event->time_usecs,
			state->event->time_usecs_end,
			live_usecs,
			last_event_time_usecs(state),
			description, &error)) {
		die("%s:%d: %s\n",
		    state->config->script_path,
		    state->event->line_number,
		    error);
	}
}

/* Consecutive relative inbound packets should be anchored relative to the
 * packet start times, to avoid accumulating errors from CPU processing
 * overheads on consecutive packets.
 */
bool is_event_start_time_anchored(struct event *event)
{
	return (event->type == PACKET_EVENT &&
		packet_direction(event->event.packet) == DIRECTION_INBOUND);
}

/* Set the start (and end time, if applicable) for the event if it
 * uses wildcard or relative timing.
 */
void adjust_relative_event_times(struct state *state, struct event *event)
{
	s64 offset_usecs = 0;

	if (event->time_type != ANY_TIME &&
	    event->time_type != RELATIVE_TIME &&
	    event->time_type != RELATIVE_RANGE_TIME)
		return;

	if (state->last_event &&
	    is_event_start_time_anchored(state->last_event) &&
	    is_event_start_time_anchored(event))
		offset_usecs = state->last_event->time_usecs;
	else
		offset_usecs = now_usecs(state) - state->live_start_time_usecs;
	event->offset_usecs = offset_usecs;

	event->time_usecs += offset_usecs;
	if (event->time_type == RELATIVE_RANGE_TIME)
		event->time_usecs_end += offset_usecs;

	/* Adjust the end time of blocking system calls using relative times. */
	if (event->time_type == RELATIVE_TIME &&
	    event->type == SYSCALL_EVENT &&
	    is_blocking_syscall(event->event.syscall)) {
		event->event.syscall->end_usecs += offset_usecs;
	}
}

void wait_for_event(struct state *state)
{
	s64 event_usecs =
		script_time_to_live_time_usecs(
			state, state->event->time_usecs);
	DEBUGP("waiting until %lld -- now is %lld\n",
	       event_usecs, now_usecs(state));
	while (1) {
		const s64 wait_usecs = event_usecs - now_usecs(state);
		if (wait_usecs <= 0)
			break;

		/* If we're waiting a long time, and we are on an OS
		 * that we know has a fine-grained usleep(), then
		 * usleep() instead of spinning on the CPU.
		 */
#ifdef linux
		/* Since the scheduler may not wake us up precisely
		 * when we tell it to, sleep until just before the
		 * event we're waiting for and then spin.
		 */
		if (state->num_events > 0 && wait_usecs > MAX_SPIN_USECS) {
			run_unlock(state);
			if (state->so_instance) {
				state->so_instance->ifc.usleep(
					state->so_instance->ifc.userdata,
					wait_usecs - MAX_SPIN_USECS);
			} else {
				usleep(wait_usecs - MAX_SPIN_USECS);
			}
			run_lock(state);
		}
#endif

		/* At this point we should only have a millisecond or
		 * two to wait, so we spin.
		 */
	}

	if (state->num_events > 0)
		check_event_time(state, now_usecs(state));
}

int get_next_event(struct state *state, char **error)
{
	DEBUGP("gettimeofday: %.6f\n", now_usecs(state)/1000000.0);

	if (state->event == NULL) {
		/* First event. */
		state->event = state->script->event_list;
		state->script_start_time_usecs = state->event->time_usecs;
		if (state->event->time_usecs != 0) {
			asprintf(error,
				 "%s:%d: first event should be at time 0\n",
				 state->config->script_path,
				 state->event->line_number);
			return STATUS_ERR;
		}
	} else {
		/* Move to the next event. */
		state->script_last_time_usecs = state->event->time_usecs;
		state->last_event = state->event;
		state->event = state->event->next;
	}

	if (state->event == NULL)
		return STATUS_OK;	/* script is done */

	assert((state->event->type > INVALID_EVENT) &&
	       (state->event->type < NUM_EVENT_TYPES));

	if (state->last_event &&
	    is_event_time_absolute(state->last_event) &&
	    is_event_time_absolute(state->event) &&
	    state->event->time_usecs < state->script_last_time_usecs) {
		asprintf(error,
			 "%s:%d: time goes backward in script "
			 "from %lld usec to %lld usec\n",
			 state->config->script_path,
			 state->event->line_number,
			 state->script_last_time_usecs,
			 state->event->time_usecs);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Run the given packet event; print warnings/errors, and exit on error. */
static void run_local_packet_event(struct state *state, struct event *event,
				   struct packet *packet)
{
	char *error = NULL;
	int result = STATUS_OK;

	result = run_packet_event(state, event, packet, &error);
	if (result == STATUS_WARN) {
		fprintf(stderr, "%s", error);
		free(error);
	} else if (result == STATUS_ERR) {
		die("%s", error);
	}
}

/* For more consistent timing, if there's more than one CPU on this
 * machine then use a real-time priority. We skip this if there's only
 * 1 CPU because we do not want to risk making the machine
 * unresponsive.
 */
void set_scheduling_priority(void)
{
	/* Get the CPU count and skip this if we only have 1 CPU. */
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (num_cpus < 0)
		die_perror("sysconf(_SC_NPROCESSORS_ONLN)");
	if (num_cpus <= 1)
		return;

#if !defined(__OpenBSD__)
	/* Chose a real-time policy, but use SCHED_RR instead of
	 * SCHED_FIFO, so that we round-robin among real-time threads
	 * of the same priority. In practice this shouldn't matter,
	 * since there will not likely be other realtime threads.
	 */
	int policy = SCHED_RR;

	/* Use the minimum priority, to be nice. */
	int priority = sched_get_priority_min(policy);
	if (priority < 0)
		die_perror("sched_get_priority_min");

	/* Set the policy and priority for our threads. */
	struct sched_param param;
	memset(&param, 0, sizeof(param));
	param.sched_priority = priority;
	if (sched_setscheduler(0, policy, &param))
		DEBUGP("sched_setscheduler failed: %s\n", strerror(errno));
#endif  /* !defined(__OpenBSD__) */
}

/* To ensure timing that's as consistent as possible, pull all our
 * pages to RAM and pin them there.
 */
void lock_memory(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE))
		die_perror("lockall(MCL_CURRENT | MCL_FUTURE)");
}

/* Wait for and return the wall time at which we should start the
 * test, in microseconds. To make test results more reproducible, we
 * wait for a start time that is well into the middle of a Linux jiffy
 * (JIFFY_OFFSET_USECS into the jiffy). If you try to run a test
 * script starting at a time that is too near the edge of a jiffy, and
 * the test tries (as most do) to schedule events at 1-millisecond
 * boundaries relative to this start time, then slight CPU or
 * scheduling variations cause the kernel to record time measurements
 * that are 1 jiffy too big or too small, so the kernel gets
 * unexpected RTT and RTT variance values, leading to unexpected RTO
 * and delayed ACK timer behavior.
 *
 * To try to find the edge of a jiffy, we spin and watch the output of
 * times(2), which increments every time the jiffies clock has
 * advanced another 10ms.  We wait for a few ticks
 * (TARGET_JIFFY_TICKS) to go by, to reduce noise from warm-up
 * effects. We could do fancier measuring and filtering here, but so
 * far this level of complexity seems sufficient.
 */
static s64 schedule_start_time_usecs(struct state *state)
{
#ifdef linux
	s64 start_usecs = 0;
	clock_t last_jiffies = times(NULL);
	int jiffy_ticks = 0;
	const int TARGET_JIFFY_TICKS = 10;
	while (jiffy_ticks < TARGET_JIFFY_TICKS) {
		clock_t jiffies = times(NULL);
		if (jiffies != last_jiffies) {
			start_usecs = now_usecs(state);
			++jiffy_ticks;
		}
		last_jiffies = jiffies;
	}
	const int JIFFY_OFFSET_USECS = 250;
	start_usecs += JIFFY_OFFSET_USECS;
	return start_usecs;
#else
	return now_usecs(state);
#endif
}

/* Run final command we always execute at end of script, to clean up.  If there
 * is a cleanup command at the end of a packetdrill script, we execute that no
 * matter whether the test passes or fails. This makes the cleanup command a
 * good place to undo any sysctl settings the script changed, for example.
 */
int run_cleanup_command(void)
{
	if (cleanup_cmd != NULL && init_cmd_exed) {
		char *error = NULL;

		if (safe_system(cleanup_cmd, &error)) {
			fprintf(stderr,
				"%s: error executing cleanup command: %s\n",
				 script_path, error);
			free(error);
			return STATUS_ERR;
		}
	}
	return STATUS_OK;
}

void run_script(struct config *config, struct script *script)
{
	char *error = NULL;
	struct state *state = NULL;
	struct netdev *netdev = NULL;
	struct event *event = NULL;

	DEBUGP("run_script: running script\n");

	set_scheduling_priority();
	lock_memory();

	/* This interpreter loop runs for local mode or wire client mode. */
	assert(!config->is_wire_server);

	script_path = config->script_path;

	/* How we use the network is of course a little different in
	 * each of the two cases....
	 */
	if (config->is_wire_client)
		netdev = wire_client_netdev_new(config);
	else if (config->so_filename)
		netdev = so_netdev_new(config);
	else
		netdev = local_netdev_new(config);

	state = state_new(config, script, netdev);

	if (config->is_wire_client) {
		state->wire_client = wire_client_new();
		wire_client_init(state->wire_client, config, script);
	}

	if (config->so_filename) {
		state->so_instance = so_instance_new();
		so_instance_init(state->so_instance, config, script, state);
	}

	init_cmd_exed = false;
	if (script->init_command != NULL) {
		if (safe_system(script->init_command->command_line,
				&error)) {
			asprintf(&error, "%s: error executing init command: %s\n",
				 config->script_path, error);
			free(error);
			exit(EXIT_FAILURE);
		}
		init_cmd_exed = true;
	}

	signal(SIGPIPE, SIG_IGN);	/* ignore EPIPE */

	state->live_start_time_usecs = schedule_start_time_usecs(state);
	DEBUGP("live_start_time_usecs is %lld\n",
	       state->live_start_time_usecs);

	if (state->wire_client != NULL)
		wire_client_send_client_starting(state->wire_client);

	while (1) {
		if (get_next_event(state, &error))
			die("%s", error);
		event = state->event;
		if (event == NULL)
			break;

		if (state->wire_client != NULL)
			wire_client_next_event(state->wire_client, event);

		/* In wire mode, we adjust relative times after
		 * getting notification that previous packet events
		 * have completed, if any.
		 */
		adjust_relative_event_times(state, event);

		switch (event->type) {
		case PACKET_EVENT:
			/* For wire clients, the server handles packets. */
			if (!config->is_wire_client) {
				run_local_packet_event(state, event,
						       event->event.packet);
			}
			break;
		case SYSCALL_EVENT:
			run_system_call_event(state, event,
					      event->event.syscall);
			break;
		case COMMAND_EVENT:
			run_command_event(state, event,
					  event->event.command);
			break;
		case CODE_EVENT:
			run_code_event(state, event,
				       event->event.code->text);
			break;
		case INVALID_EVENT:
		case NUM_EVENT_TYPES:
			assert(!"bogus type");
			break;
		/* We omit default case so compiler catches missing values. */
		}
		state->num_events++;
	}

	/* Wait for any outstanding packet events we requested on the server. */
	if (state->wire_client != NULL)
		wire_client_next_event(state->wire_client, NULL);

	if (run_cleanup_command() == STATUS_ERR)
		exit(EXIT_FAILURE);

	if (code_execute(state->code, &error)) {
		die("%s: error executing code: %s\n",
		    state->config->script_path, error);
		free(error);
	}

	state_free(state);

	DEBUGP("run_script: done running\n");
}

int parse_script_and_set_config(int argc, char *argv[],
				struct config *config,
				struct script *script,
				const char *script_path,
				const char *script_buffer)
{
	struct invocation invocation = {
		.argc = argc,
		.argv = argv,
		.config = config,
		.script = script,
	};

	DEBUGP("parse_and_run_script: %s\n", script_path);
	assert(script_path != NULL);

	init_script(script);

	set_default_config(config);
	config->script_path = strdup(script_path);

	if (script_buffer != NULL)
		copy_script(script_buffer, script);
	else
		read_script(script_path, script);

	return parse_script(config, script, &invocation);
}
