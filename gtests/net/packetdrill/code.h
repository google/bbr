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
 * Interface for a module to write out post-processing code that
 * can run custom programmatic analyses and constraint verification.
 */

#ifndef __CODE_H__
#define __CODE_H__

#include "types.h"

#include "config.h"
#include "script.h"

/* Post-processing format syntax variants we support. */
enum code_format_t {
	FORMAT_NONE,			/* uninitialized or no code so far */
	FORMAT_PYTHON,			/* Python syntax: var_name = 123  */
	FORMAT_NUM_TYPES,		/* number of types of format */
};

/* The type of a particular fragment of code. */
enum code_fragment_t {
	FRAGMENT_NONE,			/* uninitialized or none so far */
	FRAGMENT_TEXT,			/* literal code text to emit */
	FRAGMENT_DATA,			/* binary buffer to dump as text */
	FRAGMENT_NUM_TYPES,		/* number of types of fragments */
};

/* The type of a particular binary data buffer. */
enum code_data_t {
	DATA_NONE,			/* uninitialized or none so far */
#if HAVE_TCP_INFO
	DATA_TCP_INFO,			/* binary tcp_info */
#endif  /* HAVE_TCP_INFO */
#if HAVE_TCP_CC_INFO
	DATA_TCP_CC_INFO,		/* binary tcp_cc_info */
#endif	/* HAVE_SO_MEMINFO */
#if HAVE_SO_MEMINFO
	DATA_SO_MEMINFO,		/* binary so_memfino */
#endif	/* HAVE_SO_MEMINFO */
	DATA_NUM_TYPES,			/* number of types of fragments */
};

/* Info about a textual code snippet to encode in the post-processing code. */
struct code_text {
	char *text;			/* the code snippet string */
	char *file_name;		/* name of script text was read from */
	int line_number;		/* line on which text started */
};

/* Info about a data buffer to encode in the post-processing code. */
struct code_data {
	void *buffer;			/* malloc-allocated buffer */
	enum code_data_t type;		/* type of data in the buffer */
	int len;			/* length of data in buffer */
};

/* Info about a fragment to insert in the post-processing code. */
struct code_fragment {
	enum code_fragment_t type;	/* what's in this fragment? */
	union {
		struct code_text *text;	/* ASCII text code snippet */
		struct code_data *data;	/* typed binary data buffer */
	} contents;
	struct code_fragment *next;	/* next in linked list */
};

/* Internal state for the code execution module. */
struct code_state {
	bool verbose;				/* print debug info? */
	enum code_format_t format;		/* language syntax to emit */
	enum code_data_t data_type;		/* data to get for snippets */
	char *command_line;			/* system(3) command to run */
	char *path;				/* path where we write code */
	FILE *file;				/* output file we're writing */
	struct code_fragment *list_head;	/* linked list head */
	struct code_fragment **list_tail;	/* pointer to tail */
};

/* Allocate and return a new code executor using the given config. */
extern struct code_state *code_new(struct config *config);

/* Tear down a code executor and free up the resources it has allocated. */
extern void code_free(struct code_state *code);

/* Run the TCP_INFO getsockopt on the current socket under test to
 * get a snapshot of socket state, and stash the resulting data and
 * code snippet so that at the end of the test we can emit the data
 * and the code snippet, and then execute both.
 */
struct state;
extern void run_code_event(struct state *state,
			   struct event *event, const char *text);

/* Call this at the end of test execution to run the code by writing
 * out the text of the code and invoking the command line supplied by
 * the user. On success, returns STATUS_OK. On error returns
 * STATUS_ERR and fills in *error.
 */
extern int code_execute(struct code_state *code, char **error);

#endif /* __CODE_H__ */
