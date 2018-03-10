%{
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
 * This is the specification for the lexical scanner for the packetdrill
 * script language. It is processed by the flex lexical scanner
 * generator.
 *
 * For full documentation see: http://flex.sourceforge.net/manual/
 *
 * Here is a quick and dirty tutorial on flex:
 *
 * A flex lexical scanner specification is basically a list of rules,
 * where each rule is a regular expressions for a lexical token to
 * match, followed by a C fragment to execute when the scanner sees
 * that pattern.
 *
 * The lexer feeds a stream of terminal symbols up to this parser,
 * passing up a FOO token for each "return FOO" in the lexer spec. The
 * lexer specifies what value to pass up to the parser by setting a
 * yylval.fooval field, where fooval is a field in the %union in the
 * .y file.
 *
 * TODO: detect overflow in numeric literals.
 */

#include "types.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include "script.h"
#include "tcp_options.h"
#include "parse.h"
#include "config.h"

/* This include of the bison-generated .h file must go last so that we
 * can first include all of the declarations on which it depends.
 */
#include "parser.h"

/* Suppress flex's generation of an uncalled static input() function, which
 * leads to a compiler warning:
 *    warning: ‘input’ defined but not used
 */
#define YY_NO_INPUT

/* Copy the string name "foo" after the "--" of a "--foo" option. */
static char *option(const char *s)
{
	const int dash_dash_len = 2;
	return strndup(s + dash_dash_len, strlen(s) - dash_dash_len);
}

/* Copy the string inside a quoted string. */
static char *quoted(const char *s)
{
	const int delim_len = 1;
	return strndup(s + delim_len, strlen(s) - 2*delim_len);
}

/* Check to see if the word in yytext is a user-defined symbol, and if so then
 * return its value. Otherwise return the word itself.
 */
int word(void)
{
	char *word = yytext;
	char *value = NULL;

	/* Look in symbol table for matching user-defined symbol->value map. */
	value = definition_get(in_config->defines, word);
	if (value) {
		if (value[0] == '"') {
			yylval.string = quoted(value);		/* SYM="val" */
			return STRING;
		} else if (value[0] == '`') {
			yylval.string = quoted(value);		/* SYM=`val` */
			return BACK_QUOTED;
		} else {
			yylval.string = strdup(value);		/* SYM=val */
			return WORD;
		}
	}
	/* A literal word (e.g. system call name or socket option name). */
	yylval.string = strdup(word);
	return WORD;
}

/* Copy the code inside a code snippet that is enclosed in %{ }% after
 * first stripping the space and tab characters from either end of the
 * snippet. We strip leading and trailing whitespace for Python users
 * to remain sane, since Python is sensitive to whitespace. To summarize,
 * given an input %{<space><code><space>}% we return: <code>
 */
static char *code(const char *s)
{
	const int delim_len = sizeof("%{")-1;

	const char *start = s + delim_len;
	while ((*start == ' ') || (*start == '\t'))
		++start;

	const char *end = s + (strlen(s) - 1) - delim_len;
	while ((*end == ' ') || (*end == '\t'))
		--end;

	const int code_len = end - start + 1;
	return strndup(start, code_len);
}

/* Convert a hex string prefixed by "0x" to an integer value. */
static s64 hextol(const char *s)
{
	return strtol(yytext + 2, NULL, 16);
}

%}

%{
#define YY_USER_ACTION yylloc.first_line = yylloc.last_line = yylineno;
%}
%option yylineno
%option nounput

/* A regexp for C++ comments: */
cpp_comment	\/\/[^\n]*\n

/* Here is a summary of the regexp for C comments:
 *   open-comment
 *   any number of:
 *     (non-stars) or (star then non-slash)
 *   close comment
 */
c_comment	\/\*(([^*])|(\*[^\/]))*\*\/

/* The regexp for code snippets is analogous to that for C comments.
 * Here is a summary of the regexp for code snippets:
 *   %{
 *   any number of:
 *     (non-}) or (} then non-%)
 *   }%
 */
code		\%\{(([^}])|(\}[^\%]))*\}\%

/* IPv4: a regular experssion for an IPv4 address */
ipv4_addr		[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+

/* IPv6: a regular experssion for an IPv6 address. The complexity is
 * unfortunate, but we can't use a super-simple approach because TCP
 * sequence number ranges like 1:1001 can look like IPv6 addresses if
 * we use a naive approach.
 */
seg	[0-9a-fA-F]{1,4}
v0	[:][:]
v1	({seg}[:]){7,7}{seg}
v2	({seg}[:]){1,7}[:]
v3	({seg}[:]){1,6}[:]{seg}
v4	({seg}[:]){1,5}([:]{seg}){1,2}
v5	({seg}[:]){1,4}([:]{seg}){1,3}
v6	({seg}[:]){1,3}([:]{seg}){1,4}
v7	({seg}[:]){1,2}([:]{seg}){1,5}
v8	{seg}[:](([:]{seg}){1,6})
v9	[:]([:]{seg}){1,7}
/* IPv4-mapped IPv6 address: */
v10	[:][:]ffff[:]{ipv4_addr}
/* IPv4-translated IPv6 address: */
v11	[:][:]ffff[:](0){1,4}[:]{ipv4_addr}
/* IPv4-embedded IPv6 addresses: */
v12	({seg}[:]){1,4}[:]{ipv4_addr}
ipv6_addr ({v0}|{v1}|{v2}|{v3}|{v4}|{v5}|{v6}|{v7}|{v8}|{v9}|{v10}|{v11}|{v12})

%%
sa_family		return SA_FAMILY;
sin_port		return SIN_PORT;
sin_addr		return SIN_ADDR;
msg_name		return MSG_NAME;
msg_iov			return MSG_IOV;
msg_flags		return MSG_FLAGS;
msg_control		return MSG_CONTROL;
cmsg_data		return CMSG_DATA;
cmsg_level		return CMSG_LEVEL;
cmsg_type		return CMSG_TYPE;
ee_errno		return EE_ERRNO;
ee_origin		return EE_ORIGIN;
ee_type			return EE_TYPE;
ee_code			return EE_CODE;
ee_info			return EE_INFO;
ee_data			return EE_DATA;
scm_sec			return SCM_SEC;
scm_nsec		return SCM_NSEC;
fd			return FD;
u32			return U32;
u64			return U64;
ptr			return PTR;
events			return EVENTS;
revents			return REVENTS;
onoff			return ONOFF;
linger			return LINGER;
htons			return _HTONS_;
ipv4			return IPV4;
ipv6			return IPV6;
icmp			return ICMP;
udp			return UDP;
GREv0			return GRE;
gre			return GRE;
raw			return RAW;
sum			return SUM;
off			return OFF;
key			return KEY;
seq			return SEQ;
none			return NONE;
checksum		return CHECKSUM;
sequence#		return SEQUENCE;
present			return PRESENT;
mpls			return MPLS;
label			return LABEL;
tc			return TC;
ttl			return TTL;
inet_addr		return INET_ADDR;
inet6_addr		return INET6_ADDR;
ack			return ACK;
eol			return EOL;
ecr			return ECR;
mss			return MSS;
mtu			return MTU;
nop			return NOP;
sack			return SACK;
sackOK			return SACKOK;
md5			return MD5;
TS			return TIMESTAMP;
FO			return FAST_OPEN;
FOEXP			return FAST_OPEN_EXP;
tos			return TOS;
flowlabel		return FLOWLABEL;
flags			return FLAGS;
Flags			return FLAGS;
val			return VAL;
win			return WIN;
urg			return URG;
wscale			return WSCALE;
ect01			return ECT01;
ect0			return ECT0;
ect1			return ECT1;
noecn			return NO_ECN;
ce			return CE;
id			return ID;
[.][.][.]		return ELLIPSIS;
--[a-zA-Z0-9_]+		yylval.string	= option(yytext); return OPTION;
[-]?[0-9]*[.][0-9]+	yylval.floating	= atof(yytext);   return FLOAT;
[-]?[0-9]+		yylval.integer	= atoll(yytext);  return INTEGER;
0x[0-9a-fA-F]+		yylval.integer	= hextol(yytext); return HEX_INTEGER;
[a-zA-Z0-9_]+		return word();
\"(\\.|[^"])*\"		yylval.string	= quoted(yytext); return STRING;
\`(\\.|[^`])*\`		yylval.string	= quoted(yytext); return BACK_QUOTED;
[^ \t\n]		return (int) yytext[0];
[ \t\n]+		/* ignore whitespace */;
{cpp_comment}		/* ignore C++-style comment */;
{c_comment}		/* ignore C-style comment */;
{code}			yylval.string = code(yytext);   return CODE;
{ipv4_addr}		yylval.string = strdup(yytext); return IPV4_ADDR;
{ipv6_addr}		yylval.string = strdup(yytext); return IPV6_ADDR;
%%
