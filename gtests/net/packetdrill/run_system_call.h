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
 * Interface for a module to execute a system call from a test script.
 */

#ifndef __RUN_SYSTEM_CALL_H__
#define __RUN_SYSTEM_CALL_H__

#include "types.h"

#include <pthread.h>
#include "script.h"

struct state;

/* States in which the system call thread can be. */
enum syscall_state_t {
	SYSCALL_IDLE,		/* system call thread is idle */
	SYSCALL_ENQUEUED,	/* blocking system call is ready to execute */
	SYSCALL_RUNNING,	/* system call is running */
	SYSCALL_DONE,		/* system call is done running */
	SYSCALL_EXITING,	/* process is exiting */
};

/* Internal state for the system call module, including the "syscall
 * thread", which handles blocking system calls.
 */
struct syscalls {
	enum syscall_state_t state;	/* current state of syscall thread */
	struct event *event;		/* current system call it's running */
	s64 live_end_usecs;		/* time of last system call return */

	/* Handles for the syscall thread, for blocking system calls. */
	pthread_t thread;		/* pthread thread handle */
	pid_t thread_id;		/* kernel thread ID  */

	/* The main thread waits on this condition variable. The
	 * system call thread signals this when it has finished
	 * executing a blocking system call and is now idle and ready
	 * to execute another blocking system call.
	 */
	pthread_cond_t idle;

	/* The system call thread waits on this condition
	 * variable. The main thread signals this when it has enqueued
	 * a blocking system call to execute, and thus the system call
	 * thread should wake up and execute that system call. The
	 * main thread also signals this when it's time to exit.
	 */
	pthread_cond_t enqueued;

	/* The main thread waits on this condition variable. The
	 * system call thread signals this after it has dequeued the
	 * system call and just before it invokes the system call, at
	 * which point the main thread should wake up to continue test
	 * execution.
	 */
	pthread_cond_t dequeued;
};

/* Info for a nla type */
struct nla_type_info {
	const char* name;
	int length;
};

/* Allocate and return internal state for the system call module. */
extern struct syscalls *syscalls_new(struct state *state);

/* Tear down a syscalls and free up the resources it has allocated. */
extern void syscalls_free(struct state *state,
			  struct syscalls *syscalls);

/* Execute the given system call event. The system call may be
 * expected to block for a while, or it may be expected to return
 * immediately. To keep things simple, currently we only support
 * at most one blocking system call at a time; if a script attempts to
 * start a second blocking call before the first blocking call has
 * returned then this second call raises a runtime error.
 */
void run_system_call_event(struct state *state,
			   struct event *event,
			   struct syscall_spec *syscall);

#endif /* __RUN_SYSTEM_CALL_H__ */
