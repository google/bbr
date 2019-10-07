cmake_minimum_required (VERSION 3.5.1)

project (packetdrill)

set (SRC_PACKETDRILL_LIB
checksum.c
code.c
config.c
epoll.c
file.c
fmemopen.c
gre_packet.c
hash.c
hash_map.c
icmp_packet.c
ip_address.c
ip_packet.c
ip_prefix.c
link_layer.c
logging.c
mpls_packet.c
netdev.c
net_utils.c
open_memstream.c
packet.c
packet_checksum.c
packet_parser.c
packet_socket_linux.c
packet_socket_pcap.c
packet_to_string.c
pipe.c
run.c
run_command.c
run_packet.c
run_system_call.c
script.c
socket.c
so_testing.c
symbols_freebsd.c
symbols_linux.c
symbols_netbsd.c
symbols_openbsd.c
system.c
tcp_options.c
tcp_options_iterator.c
tcp_options_to_string.c
tcp_packet.c
types.c
udp_packet.c
wire_client.c
wire_client_netdev.c
wire_conn.c
wire_protocol.c
wire_server.c
wire_server_netdev.c
wrap.c)

find_program(FLEX_EXECUTABLE flex)
if(FLEX_EXECUTABLE STREQUAL "LEX_EXE-NOTFOUND")
    message(FATAL_ERROR "flex is not found")
endif(FLEX_EXECUTABLE STREQUAL "LEX_EXE-NOTFOUND")

find_program(BISON_EXECUTABLE bison)
if(BISON_EXECUTABLE STREQUAL "BISON_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "bison is not found")
endif(BISON_EXECUTABLE STREQUAL "BISON_EXECUTABLE-NOTFOUND")

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/lexer.c
  COMMAND ${FLEX_EXECUTABLE}
  ARGS -o ${CMAKE_CURRENT_SOURCE_DIR}/lexer.c
       ${CMAKE_CURRENT_SOURCE_DIR}/lexer.l)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/parser.c
	 ${CMAKE_CURRENT_SOURCE_DIR}/parser.h
  COMMAND ${BISON_EXECUTABLE}
  ARGS --output=${CMAKE_CURRENT_SOURCE_DIR}/parser.c
	   --defines=${CMAKE_CURRENT_SOURCE_DIR}/parser.h
	   --report=state
	   ${CMAKE_CURRENT_SOURCE_DIR}/parser.y)

set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/parser.c GENERATED)
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/parser.h GENERATED)
set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/lexer.c GENERATED)

add_library(packetdrill-lib ${SRC_PACKETDRILL_LIB} parser.c parser.h lexer.c)
set(packetdrill-ext-libs pthread pcap dl)

# packetdrill executable file
find_package(Threads REQUIRED)
add_executable(${PROJECT_NAME} packetdrill.c)
target_link_libraries(${PROJECT_NAME} packetdrill-lib ${packetdrill-ext-libs})

# Testing
include(CTest)

if(BUILD_TESTING)
  enable_testing()
endif()

add_executable(checksum_test checksum_test.c)
target_link_libraries(checksum_test packetdrill-lib ${packetdrill-ext-libs})

add_executable(packet_parser_test packet_parser_test.c)
target_link_libraries(packet_parser_test packetdrill-lib ${packetdrill-ext-libs})

add_executable(packet_to_string_test packet_to_string_test.c)
target_link_libraries(packet_to_string_test packetdrill-lib ${packetdrill-ext-libs})
