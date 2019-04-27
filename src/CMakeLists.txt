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

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
    COMMAND xargs nm
    COMMAND grep -e "d mp_"
    COMMAND awk "{print \"0x\"$1}"
    OUTPUT_VARIABLE MP__OFFSET)
if ("${MP__OFFSET}" STREQUAL "")
    message(FATAL_ERROR "Can't find MP__OFFSET")
endif ()
add_definitions(-DMP__OFFSET=${MP__OFFSET})
message(STATUS "MP__OFFSET: " ${MP__OFFSET})

message(WARNING "cmake bug: too many definations may break into multiple lines")
message(WARNING "Please modify 'src/CMakeFiles/malldump.dir/flags.make' manually")

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_executable(malldump ${SRC})
target_link_libraries(malldump dl)

install(TARGETS malldump
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
