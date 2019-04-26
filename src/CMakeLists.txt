cmake_minimum_required(VERSION 2.8)

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
    COMMAND xargs nm
    COMMAND grep __libc_mallinfo
    COMMAND awk "{print \"0x\"$1}"
    OUTPUT_VARIABLE MALLINFO_OFFSET)
if ("${MALLINFO_OFFSET}" STREQUAL "")
    message(FATAL_ERROR "Can't find MALLINFO_OFFSET")
endif ()
add_definitions(-DMALLINFO_OFFSET=${MALLINFO_OFFSET})
message(STATUS "MALLINFO_OFFSET: " ${MALLINFO_OFFSET})

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_executable(malldump ${SRC})
target_link_libraries(malldump dl)

install(TARGETS malldump
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
