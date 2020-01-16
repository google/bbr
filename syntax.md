### Packetdrill Syntax Structure

You can make the latest version of the grammar with command `yacc -v parser.y`.
Here is the grammar for the packetdrill scripting language, as of the time of
writing (October 2019), produced with `bison -v parser.y`:

```
$accept: script $end

script: opt_options opt_init_command events opt_cleanup_command

opt_options: %empty
           | options

options: option
       | options option

option: option_flag '=' option_value
      | option_flag

option_flag: OPTION

option_value: INTEGER
            | WORD
            | STRING
            | IPV4_ADDR
            | IPV6_ADDR
            | IPV4
            | IPV6
            | WORD '=' WORD
            | WORD '=' STRING
            | WORD '=' BACK_QUOTED

opt_init_command: %empty
                | init_command

init_command: command_spec

events: event
      | events event

event: event_time action

event_time: '+' time
          | time
          | '*'
          | time '~' time
          | '+' time '~' '+' time

time: FLOAT
    | INTEGER

action: packet_spec
      | syscall_spec
      | command_spec
      | code_spec

packet_spec: tcp_packet_spec
           | udp_packet_spec
           | icmp_packet_spec

tcp_packet_spec: packet_prefix opt_ip_info opt_port_info flags seq opt_ack opt_window opt_urg_ptr opt_tcp_options

udp_packet_spec: packet_prefix opt_ip_info UDP opt_port_info '(' INTEGER ')'

icmp_packet_spec: packet_prefix opt_ip_info ICMP icmp_type opt_icmp_code opt_icmp_mtu opt_icmp_echo_id opt_icmp_echoed

packet_prefix: direction
             | packet_prefix IPV4 opt_ip_info IPV4_ADDR '>' IPV4_ADDR ':'
             | packet_prefix IPV6 opt_ip_info IPV6_ADDR '>' IPV6_ADDR ':'
             | packet_prefix GRE ':'
             | packet_prefix GRE opt_comma gre_header_expression ':'
             | packet_prefix MPLS mpls_stack ':'

gre_header_expression: gre_flags_list opt_comma gre_sum opt_comma gre_off opt_comma gre_key opt_comma gre_seq

gre_flags_list: FLAGS '[' gre_flags ']'
              | FLAGS any_int

gre_flags: gre_flag
         | gre_flag ',' gre_flags

gre_flag: NONE
        | CHECKSUM PRESENT
        | KEY PRESENT
        | SEQUENCE PRESENT

gre_sum: SUM any_int

gre_off: OFF any_int

gre_key: KEY opt_equals any_int

gre_seq: SEQ any_int

opt_comma: %empty
         | ','

opt_equals: %empty
          | '='

mpls_stack: %empty
          | mpls_stack mpls_stack_entry

mpls_stack_entry: '(' LABEL INTEGER ',' TC INTEGER ',' opt_mpls_stack_bottom TTL INTEGER ')'

opt_mpls_stack_bottom: %empty
                     | '[' WORD ']' ','

icmp_type: WORD

opt_icmp_code: %empty
             | WORD

opt_icmp_echoed: %empty
               | '[' UDP '(' INTEGER ')' ']'
               | '[' seq ']'
               | '[' RAW '(' INTEGER ')' ']'

opt_icmp_mtu: %empty
            | MTU INTEGER

opt_icmp_echo_id: %empty
                | ID INTEGER

opt_port_info: %empty
             | INTEGER '>' INTEGER

direction: '<'
         | '>'

tos_spec: ip_ecn
        | ECT01
        | TOS HEX_INTEGER

ip_ecn: NO_ECN
      | ECT0
      | ECT1
      | CE

flags: WORD
     | '.'
     | WORD '.'
     | '-'

flow_label: FLOWLABEL HEX_INTEGER

ip_info: tos_spec
       | flow_label
       | TTL INTEGER
       | tos_spec ',' flow_label

opt_ip_info: %empty
           | '(' ip_info ')'
           | '[' ip_info ']'

seq: INTEGER ':' INTEGER '(' INTEGER ')'

opt_ack: %empty
       | ACK INTEGER

opt_window: %empty
          | WIN INTEGER

opt_urg_ptr: %empty
           | URG INTEGER

opt_tcp_options: %empty
               | '<' tcp_option_list '>'
               | '<' ELLIPSIS '>'

tcp_option_list: tcp_option
               | tcp_option_list ',' tcp_option

opt_tcp_fast_open_cookie: %empty
                        | hex_blob

hex_blob: WORD
        | INTEGER

tcp_option: NOP
          | EOL
          | MSS INTEGER
          | WSCALE INTEGER
          | SACKOK
          | SACK sack_block_list
          | MD5 hex_blob
          | TIMESTAMP VAL INTEGER ECR INTEGER
          | FAST_OPEN opt_tcp_fast_open_cookie
          | FAST_OPEN_EXP opt_tcp_fast_open_cookie

sack_block_list: sack_block
               | sack_block_list sack_block

sack_block: INTEGER ':' INTEGER

syscall_spec: opt_end_time function_name function_arguments '=' expression opt_errno opt_note

opt_end_time: %empty
            | ELLIPSIS time

function_name: WORD

function_arguments: '(' ')'
                  | '(' expression_list ')'

expression_list: expression
               | expression_list ',' expression

expression: ELLIPSIS
          | any_int
          | WORD
          | STRING
          | STRING ELLIPSIS
          | binary_expression
          | array
          | inaddr
          | in6addr
          | sockaddr
          | msghdr
          | iovec
          | pollfd
          | linger
          | mpls_stack_expression
          | cmsg_expr
          | scm_timestamping_expr
          | sub_expr_list
          | sock_extended_err_expr
          | '{' gre_header_expression '}'
          | epollev

any_int: decimal_integer
       | hex_integer

decimal_integer: INTEGER

hex_integer: HEX_INTEGER

binary_expression: expression '|' expression
                 | WORD '=' expression

array: '[' ']'
     | '[' expression_list ']'

inaddr: INET_ADDR '(' STRING ')'

in6addr: INET6_ADDR '(' STRING ')'

sockaddr: '{' SA_FAMILY '=' WORD ',' SIN_PORT '=' _HTONS_ '(' INTEGER ')' ',' SIN_ADDR '=' INET_ADDR '(' STRING ')' '}'

msghdr: '{' MSG_NAME '(' ELLIPSIS ')' '=' ELLIPSIS ',' MSG_IOV '(' decimal_integer ')' '=' array ',' MSG_FLAGS '=' expression opt_cmsg '}'

opt_cmsg: %empty
        | ',' MSG_CONTROL '=' array

cmsg_expr: '{' CMSG_LEVEL '=' expression ',' CMSG_TYPE '=' expression ',' CMSG_DATA '=' expression '}'

scm_timestamping_expr: '{' SCM_SEC '=' INTEGER ',' SCM_NSEC '=' INTEGER '}'

sub_expr_list: '{' expression_list '}'

sock_extended_err_expr: '{' EE_ERRNO '=' expression ',' EE_ORIGIN '=' expression ',' EE_TYPE '=' expression ',' EE_CODE '=' expression ',' EE_INFO '=' expression ',' EE_DATA '=' expression '}'

iovec: '{' ELLIPSIS ',' decimal_integer '}'

pollfd: '{' FD '=' expression ',' EVENTS '=' expression opt_revents '}'

epollev: '{' EVENTS '=' expression ',' FD '=' expression '}'
       | '{' EVENTS '=' expression ',' PTR '=' expression '}'
       | '{' EVENTS '=' expression ',' U32 '=' expression '}'
       | '{' EVENTS '=' expression ',' U64 '=' expression '}'

opt_revents: %empty
           | ',' REVENTS '=' expression

linger: '{' ONOFF '=' INTEGER ',' LINGER '=' INTEGER '}'

mpls_stack_expression: '{' mpls_stack '}'

opt_errno: %empty
         | WORD note

opt_note: %empty
        | note

note: '(' word_list ')'

word_list: WORD
         | FLAGS
         | word_list WORD

command_spec: BACK_QUOTED

code_spec: CODE

opt_cleanup_command: %empty
                   | cleanup_command

cleanup_command: command_spec
```
