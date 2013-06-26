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
 * Implementation for a module to write out post-processing code that
 * can run custom programmatic analyses and constraint verification.
 */

#include "code.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "run.h"
#include "tcp.h"

/* We emit the following Python preamble at the top of the output
 * Python code. It defines a custom exception hook so that when an
 * exception is raised (such as a failed assertion) we print the file
 * name and line number of the code snippet in the original test
 * script that caused the error, not just the file name and line
 * number in the generated Python file (which will be meaningless or
 * confusing to the user).
 */
const char python_preamble[] =
"import sys\n"
"import traceback\n"
"def excepthook(etype, value, tb):\n"
"  sys.stderr.write(\"%s:%d: error in Python code\\n\" %\n"
"                   (_file, _line))\n"
"  traceback.print_exception(etype, value, tb)\n"
"\n"
"sys.excepthook = excepthook\n"
"\n";

/* Write out the standard utility routines useful for a given language. */
static void write_preamble(struct code_state *code)
{
	assert(code->format > FORMAT_NONE);
	assert(code->format < FORMAT_NUM_TYPES);
	switch (code->format) {
	case FORMAT_NONE:
	case FORMAT_NUM_TYPES:
		assert(!"bad code format type");
	case FORMAT_PYTHON:
		fprintf(code->file, "%s\n", python_preamble);
		break;
	/* omitting default so compiler catches missing cases */
	}
}

#if HAVE_TCP_INFO

/* Write out a formatted text representation of an assignment of the
 * given value to the given named variable.
 */
static void emit_var(struct code_state *code, const char *name, u64 value)
{
	assert(code->format > FORMAT_NONE);
	assert(code->format < FORMAT_NUM_TYPES);
	switch (code->format) {
	case FORMAT_NONE:
	case FORMAT_NUM_TYPES:
		assert(!"bad code format type");
	case FORMAT_PYTHON:
		fprintf(code->file, "%s = %llu\n", name, value);
		break;
	/* omitting default so compiler catches missing cases */
	}
}

/* Write out a newline to terminate a sequence of variable assignments */
static void emit_var_end(struct code_state *code)
{
	fprintf(code->file, "\n");
}

/* Write out a formatted representation of useful symbolic names. */
static void write_symbols(struct code_state *code)
{
#ifdef linux
	/* Emit symbolic names for tcpi_ca_state values. */
	emit_var(code, "TCP_CA_Open",		TCP_CA_Open);
	emit_var(code, "TCP_CA_Disorder",	TCP_CA_Disorder);
	emit_var(code, "TCP_CA_CWR",		TCP_CA_CWR);
	emit_var(code, "TCP_CA_Recovery",	TCP_CA_Recovery);
	emit_var(code, "TCP_CA_Loss",		TCP_CA_Loss);
#endif  /* linux */

	/* tcpi_options flags */
#ifdef linux
	emit_var(code, "TCPI_OPT_TIMESTAMPS",	TCPI_OPT_TIMESTAMPS);
	emit_var(code, "TCPI_OPT_WSCALE",	TCPI_OPT_WSCALE);
	emit_var(code, "TCPI_OPT_ECN",		TCPI_OPT_ECN);
#endif  /* linux */
}

#endif  /* HAVE_TCP_INFO */

#ifdef linux

/* Write out a formatted representation of the given tcp_info buffer. */
static void write_tcp_info(struct code_state *code,
				   const struct _tcp_info *info,
				   int len)
{
	assert(len >= sizeof(struct _tcp_info));

	write_symbols(code);

	/* Emit the recorded values of tcpi_foo values. */
	emit_var(code, "tcpi_state",		info->tcpi_state);
	emit_var(code, "tcpi_ca_state",		info->tcpi_ca_state);
	emit_var(code, "tcpi_retransmits",	info->tcpi_retransmits);
	emit_var(code, "tcpi_probes",		info->tcpi_probes);
	emit_var(code, "tcpi_backoff",		info->tcpi_backoff);
	emit_var(code, "tcpi_options",		info->tcpi_options);
	emit_var(code, "tcpi_snd_wscale",	info->tcpi_snd_wscale);
	emit_var(code, "tcpi_rcv_wscale",	info->tcpi_rcv_wscale);
	emit_var(code, "tcpi_rto",		info->tcpi_rto);
	emit_var(code, "tcpi_ato",		info->tcpi_ato);
	emit_var(code, "tcpi_snd_mss",		info->tcpi_snd_mss);
	emit_var(code, "tcpi_rcv_mss",		info->tcpi_rcv_mss);
	emit_var(code, "tcpi_unacked",		info->tcpi_unacked);
	emit_var(code, "tcpi_sacked",		info->tcpi_sacked);
	emit_var(code, "tcpi_lost",		info->tcpi_lost);
	emit_var(code, "tcpi_retrans",		info->tcpi_retrans);
	emit_var(code, "tcpi_fackets",		info->tcpi_fackets);
	emit_var(code, "tcpi_last_data_sent",	info->tcpi_last_data_sent);
	emit_var(code, "tcpi_last_ack_sent",	info->tcpi_last_ack_sent);
	emit_var(code, "tcpi_last_data_recv",	info->tcpi_last_data_recv);
	emit_var(code, "tcpi_last_ack_recv",	info->tcpi_last_ack_recv);
	emit_var(code, "tcpi_pmtu",		info->tcpi_pmtu);
	emit_var(code, "tcpi_rcv_ssthresh",	info->tcpi_rcv_ssthresh);
	emit_var(code, "tcpi_rtt",		info->tcpi_rtt);
	emit_var(code, "tcpi_rttvar",		info->tcpi_rttvar);
	emit_var(code, "tcpi_snd_ssthresh",	info->tcpi_snd_ssthresh);
	emit_var(code, "tcpi_snd_cwnd",		info->tcpi_snd_cwnd);
	emit_var(code, "tcpi_advmss",		info->tcpi_advmss);
	emit_var(code, "tcpi_reordering",	info->tcpi_reordering);
	emit_var(code, "tcpi_total_retrans",	info->tcpi_total_retrans);

	emit_var(code, "tcpi_rcv_rtt",		info->tcpi_rcv_rtt);
	emit_var(code, "tcpi_rcv_space",	info->tcpi_rcv_space);

	emit_var_end(code);
}

#endif  /* linux */

#if defined(__FreeBSD__)

/* Write out a formatted representation of the given tcp_info buffer. */
static void write_tcp_info(struct code_state *code,
				   const struct _tcp_info *info,
				   int len)
{
	assert(len >= sizeof(struct _tcp_info));

	write_symbols(code);

	/* Emit the recorded values of tcpi_foo values. */
	emit_var(code, "tcpi_state",		info->tcpi_state);
	emit_var(code, "tcpi_options",		info->tcpi_options);
	emit_var(code, "tcpi_snd_wscale",	info->tcpi_snd_wscale);
	emit_var(code, "tcpi_rcv_wscale",	info->tcpi_rcv_wscale);
	emit_var(code, "tcpi_rto",		info->tcpi_rto);
	emit_var(code, "tcpi_snd_mss",		info->tcpi_snd_mss);
	emit_var(code, "tcpi_rcv_mss",		info->tcpi_rcv_mss);
	emit_var(code, "tcpi_last_data_recv",	info->tcpi_last_data_recv);
	emit_var(code, "tcpi_rtt",		info->tcpi_rtt);
	emit_var(code, "tcpi_rttvar",		info->tcpi_rttvar);
	emit_var(code, "tcpi_snd_ssthresh",	info->tcpi_snd_ssthresh);
	emit_var(code, "tcpi_snd_cwnd",		info->tcpi_snd_cwnd);
	emit_var(code, "tcpi_rcv_space",	info->tcpi_rcv_space);

	/* FreeBSD extensions to tcp_info. */
	emit_var(code, "tcpi_snd_wnd",		info->tcpi_snd_wnd);
	emit_var(code, "tcpi_snd_bwnd",		info->tcpi_snd_bwnd);
	emit_var(code, "tcpi_snd_nxt",		info->tcpi_snd_nxt);
	emit_var(code, "tcpi_rcv_nxt",		info->tcpi_rcv_nxt);
	emit_var(code, "tcpi_toe_tid",		info->tcpi_toe_tid);
	emit_var(code, "tcpi_snd_rexmitpack",	info->tcpi_snd_rexmitpack);
	emit_var(code, "tcpi_rcv_ooopack",	info->tcpi_rcv_ooopack);
	emit_var(code, "tcpi_snd_zerowin",	info->tcpi_snd_zerowin);

	emit_var_end(code);
}

#endif  /* __FreeBSD__ */

/* Allocate a new empty struct code_text struct. */
static struct code_text *text_new(void)
{
	struct code_text *text = calloc(1, sizeof(struct code_text));
	return text;
}

/* Free the given text struct and all storage to which it points. */
static void text_free(struct code_text *text)
{
	free(text->text);
	free(text->file_name);
	free(text);
}

/* Allocate a new empty struct code_data struct. */
static struct code_data *data_new(void)
{
	struct code_data *data = calloc(1, sizeof(struct code_data));
	return data;
}

/* Free the given data and all storage to which it points. */
static void data_free(struct code_data *data)
{
	free(data->buffer);
	free(data);
}

/* Allocate a new empty fragment. */
static struct code_fragment *fragment_new(void)
{
	struct code_fragment *fragment =
		calloc(1, sizeof(struct code_fragment));
	return fragment;
}

/* Free the given fragment and all storage to which it points. */
static void fragment_free(struct code_fragment *fragment)
{
	assert(fragment->type > FRAGMENT_NONE);
	assert(fragment->type < FRAGMENT_NUM_TYPES);
	switch (fragment->type) {
	case FRAGMENT_NONE:
	case FRAGMENT_NUM_TYPES:
		assert(!"bad code fragment type");
		break;
	case FRAGMENT_TEXT:
		text_free(fragment->contents.text);
		break;
	case FRAGMENT_DATA:
		data_free(fragment->contents.data);
		break;
	/* omitting default so compiler catches missing cases */
	}
	free(fragment);
}

/* Write out the text to the given file. */
static void write_text(struct code_state *code, struct code_text *text)
{
	assert(code->format > FORMAT_NONE);
	assert(code->format < FORMAT_NUM_TYPES);
	switch (code->format) {
	case FORMAT_NONE:
	case FORMAT_NUM_TYPES:
		assert(!"bad code format type");
	case FORMAT_PYTHON:
		fprintf(code->file,
			"_file = '%s'\n"
			"_line = %d\n"
			"%s\n\n",
			text->file_name, text->line_number, text->text);
		break;
	/* omitting default so compiler catches missing cases */
	}
}

/* Write out a textual representation of the data to the given file. */
static void write_data(struct code_state *code, struct code_data *data)
{
	assert(data->type > DATA_NONE);
	assert(data->type < DATA_NUM_TYPES);
	switch (data->type) {
	case DATA_NONE:
	case DATA_NUM_TYPES:
		assert(!"bad data type");
		break;
#if HAVE_TCP_INFO
	case DATA_TCP_INFO:
		write_tcp_info(code, data->buffer, data->len);
		break;
#endif  /* HAVE_TCP_INFO */
	/* omitting default so compiler catches missing cases */
	}
}

/* Write out a textual representation of the fragment to the given file. */
static void write_fragment(struct code_state *code,
			   struct code_fragment *fragment)
{
	assert(fragment->type > FRAGMENT_NONE);
	assert(fragment->type < FRAGMENT_NUM_TYPES);
	switch (fragment->type) {
	case FRAGMENT_NONE:
	case FRAGMENT_NUM_TYPES:
		assert(!"bad code fragment type");
		break;
	case FRAGMENT_TEXT:
		write_text(code, fragment->contents.text);
		break;
	case FRAGMENT_DATA:
		write_data(code, fragment->contents.data);
		break;
	/* omitting default so compiler catches missing cases */
	}
}

/* Format and write out all the code fragments. */
static void write_all_fragments(struct code_state *code)
{
	struct code_fragment *fragment = NULL;
	for (fragment = code->list_head; fragment != NULL;
	     fragment = fragment->next) {
		write_fragment(code, fragment);
	}
}

/* Append the code fragment to the end of the list of code fragments. */
static void append_fragment(struct code_state *code,
			    struct code_fragment *fragment)
{
	*(code->list_tail) = fragment;
	code->list_tail = &(fragment->next);
}

/* Append a literal ASCII text code snippet that we should emit.
 * Takes ownership of the malloc-allocated text memory and frees it.
 */
static void append_text(struct code_state *code,
			const char *file_name, int line_number,
			char *text_buffer)
{
	struct code_text *text = text_new();
	text->text = text_buffer;
	text->file_name = strdup(file_name);
	text->line_number = line_number;

	struct code_fragment *fragment = fragment_new();
	fragment->type = FRAGMENT_TEXT;
	fragment->contents.text = text;
	append_fragment(code, fragment);
}

/* Append a live binary buffer that we should translate into the
 * format configured earlier by the user for this script.
 * Takes ownership of the malloc-allocated buffer and frees it.
 */
static void append_data(struct code_state *code, enum code_data_t data_type,
			void *data_buffer, int data_len)
{
	struct code_data *data = data_new();
	data->buffer = data_buffer;
	data->type = data_type;
	data->len = data_len;

	struct code_fragment *fragment = fragment_new();
	fragment->type = FRAGMENT_DATA;
	fragment->contents.data = data;
	append_fragment(code, fragment);
}

struct code_state *code_new(struct config *config)
{
	struct code_state *code = calloc(1, sizeof(struct code_state));

	/* Set up the pointer to the tail of the empty linked list. */
	code->list_tail = &(code->list_head);

	if (strcmp(config->code_format, "python") == 0)
		code->format = FORMAT_PYTHON;
	else
		die("unsupported --code_format '%s'\n", config->code_format);

	/* See which getsockopt we should use to get data for our code. */
	if (strcmp(config->code_sockopt, "") == 0) {
		code->data_type = DATA_NONE;		/* auto-detect */
#if HAVE_TCP_INFO
	} else if (strcmp(config->code_sockopt, "TCP_INFO") == 0) {
		code->data_type = DATA_TCP_INFO;
#endif
	} else {
		die("unsupported --code_sockopt '%s'\n", config->code_sockopt);
	}

	code->command_line = strdup(config->code_command_line);
	code->verbose = config->verbose;

	return code;
}

void code_free(struct code_state *code)
{
	if (code->command_line != NULL)
		free(code->command_line);
	if (code->path != NULL)
		free(code->path);

	/* Free all the code fragments. */
	struct code_fragment *fragment = code->list_head;
	while (fragment != NULL) {
		struct code_fragment *dead_fragment = fragment;
		fragment = fragment->next;
		fragment_free(dead_fragment);
	}

	memset(code, 0, sizeof(*code));  /* paranoia to help catch bugs */
	free(code);
}

/* Write all the code fragments to a newly-chosen temporary file and
 * store the name of the file in code->path.
 */
static void write_code_file(struct code_state *code)
{
	/* mkstemp will fill this in with the actual unique path name. */
	char path_template[] = "/tmp/code_XXXXXX";
	int code_fd = mkstemp(path_template);
	if (code_fd < 0)
		die_perror("error making temp output file for code: mkstemp");

	assert(code->path == NULL);
	code->path = strdup(path_template);

	code->file = fdopen(code_fd, "w");
	if (code->file == NULL)
		die_perror("error opening temp output file for code: fdopen");

	write_preamble(code);
	write_all_fragments(code);

	if (fclose(code->file) != 0)
		die_perror("error closing temp output file for code: fclose");

	code->file = NULL;
}

/* Execute the code in the file at code->path by executing the
 * configured command line. On success, returns STATUS_OK. On error
 * returns STATUS_ERR and fills in *error.
 */
static int execute_code_command_line(struct code_state *code, char **error)
{
	int result = STATUS_ERR;	/* return value */
	char *full_command_line = NULL;
	asprintf(&full_command_line, "%s %s", code->command_line, code->path);

	/* For verbose debugging we dump the full output file. */
	if (code->verbose) {
		char *verbose_command_line = NULL;
		asprintf(&verbose_command_line, "cat %s", code->path);
		system(verbose_command_line);
		free(verbose_command_line);
		printf("running: '%s'\n", full_command_line);
	}

	int status = system(full_command_line);
	if (status == -1) {
		asprintf(error, "error running '%s' with system(3): %s",
			 code->command_line, strerror(errno));
		goto out;
	}
	if (WIFSIGNALED(status) &&
	    (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGQUIT)) {
		asprintf(error, "'%s' got signal %d (%s)",
			 code->command_line,
			 WTERMSIG(status), strsignal(WTERMSIG(status)));
		goto out;
	}
	if (WEXITSTATUS(status) != 0) {
		asprintf(error, "'%s' returned non-zero status %d",
			 code->command_line, WEXITSTATUS(status));
		goto out;
	}
	result = STATUS_OK;

out:
	free(full_command_line);
	return result;
}

/* Delete the temporary file at code->path. */
static void delete_code_file(struct code_state *code)
{
	if ((code->path != NULL) && (unlink(code->path) != 0))
		die_perror("error deleting code file: unlink:");
}

/* Write out the code to a file, execute the code, and delete the file. */
int code_execute(struct code_state *code, char **error)
{
	if (code->list_head == NULL)
		return STATUS_OK;	/* no code to execute */

	write_code_file(code);
	int result = execute_code_command_line(code, error);
	delete_code_file(code);
	return result;
}

/* Run a getsockopt for the given fd to grab data of the given type.
 * On success, return a pointer the filled-in buffer (allocated by malloc);
 * on failure, return NULL.
 */
static void *get_data(int fd, enum code_data_t data_type, int *len)
{
	int opt_name = 0;
	int data_len = 0;
	int min_data_len = 0;

	assert(data_type > DATA_NONE);
	assert(data_type < DATA_NUM_TYPES);
	switch (data_type) {
	case DATA_NONE:
	case DATA_NUM_TYPES:
		assert(!"bad data type");
		break;
#if HAVE_TCP_INFO
	case DATA_TCP_INFO:
		opt_name = TCP_INFO;
		data_len = sizeof(struct _tcp_info);
		min_data_len = data_len;
		break;
#endif  /* HAVE_TCP_INFO */
	/* omitting default so compiler catches missing cases */
	}
	assert(opt_name != 0);
	assert(data_len > 0);
	socklen_t opt_len = data_len;
	void *data = calloc(1, data_len);

	int result = getsockopt(fd, SOL_TCP, opt_name, data, &opt_len);
	if (result < 0) {
		free(data);
		return NULL;
	}
	if (opt_len < min_data_len) {
		die("expected getsockopt(SOL_TCP, %d) output "
		    "of at least %d bytes; got %d bytes",
		    opt_name, min_data_len, opt_len);
	}
	*len = opt_len;
	return data;
}

void run_code_event(struct state *state, struct event *event,
			    const char *text)
{
	DEBUGP("%d: run code event\n", event->line_number);

	char *error = NULL;

	/* Wait for the right time before firing off this event. */
	wait_for_event(state);

	if (state->socket_under_test == NULL) {
		asprintf(&error, "no socket to use for code");
		goto error_out;
	}
	int fd = state->socket_under_test->live.fd;
	struct code_state *code = state->code;

	void *data = NULL;
	int  data_len = 0;
	if (code->data_type == DATA_NONE) {
		/* First time: try various getsockopt calls until one works. */
#if HAVE_TCP_INFO
		if (data == NULL) {
			code->data_type = DATA_TCP_INFO;
			data = get_data(fd, code->data_type, &data_len);
		}
#endif  /* HAVE_TCP_INFO */
		if (data == NULL) {
			asprintf(&error,
				 "can't find getsockopt to get TCP info");
			goto error_out;
		}
	} else {
		/* Run the getsockopt we already picked above. */
		data = get_data(fd, code->data_type, &data_len);
		if (!data) {
			asprintf(&error, "can't get info for socket");
			goto error_out;
		}
	}
	assert(code->data_type != DATA_NONE);
	assert(data != NULL);

	append_data(code, code->data_type, data, data_len);
	append_text(code, state->config->script_path, event->line_number,
		    strdup(text));

	return;

error_out:
	die("%s:%d: runtime error in code: %s\n",
	    state->config->script_path, event->line_number, error);
	free(error);
}
