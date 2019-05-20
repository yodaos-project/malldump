cmake_minimum_required(VERSION 2.8)

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-sysroot
    COMMAND awk "{printf $0}"
    OUTPUT_VARIABLE SYSROOT)
if ("${SYSROOT}" STREQUAL "")
    message(FATAL_ERROR "Unknown sysroot")
endif ()
message(STATUS "sysroot: " ${SYSROOT})

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-file-name=libc.so.6
    COMMAND xargs readlink -f
    COMMAND awk "{printf $0}"
    OUTPUT_VARIABLE LIBC_PATH)
if ("${LIBC_PATH}" STREQUAL "")
    message(FATAL_ERROR "Can't find libc.so.6")
endif ()
if (EXISTS "${SYSROOT}/usr/lib/debug")
    set(LIBC_PATH "${SYSROOT}/usr/lib/debug/${LIBC_PATH}")
endif ()
message(STATUS "LIBC_PATH: " ${LIBC_PATH})

execute_process(
    COMMAND echo ${LIBC_PATH}
    COMMAND xargs nm
    COMMAND grep __libc_mallinfo
    COMMAND awk "{printf \"0x\"$1}"
    OUTPUT_VARIABLE MALLINFO_OFFSET)
if ("${MALLINFO_OFFSET}" STREQUAL "")
    message(FATAL_ERROR "Can't find MALLINFO_OFFSET")
endif ()
add_definitions(-DMALLINFO_OFFSET=${MALLINFO_OFFSET})
message(STATUS "MALLINFO_OFFSET: " ${MALLINFO_OFFSET})

execute_process(
    COMMAND echo ${LIBC_PATH}
    COMMAND xargs nm
    COMMAND grep -e "d mp_"
    COMMAND awk "{printf \"0x\"$1}"
    OUTPUT_VARIABLE MP__OFFSET)
if ("${MP__OFFSET}" STREQUAL "")
    message(FATAL_ERROR "Can't find MP__OFFSET")
endif ()
add_definitions(-DMP__OFFSET=${MP__OFFSET})
message(STATUS "MP__OFFSET: " ${MP__OFFSET})

execute_process(
    COMMAND echo ${LIBC_PATH}
    COMMAND xargs nm
    COMMAND grep -e "d narenas"
    COMMAND awk "{printf \"0x\"$1}"
    OUTPUT_VARIABLE NARENAS_OFFSET)
if ("${NARENAS_OFFSET}" STREQUAL "")
    message(FATAL_ERROR "Can't find NARENAS_OFFSET")
endif ()
add_definitions(-DNARENAS_OFFSET=${NARENAS_OFFSET})
message(STATUS "NARENAS_OFFSET: " ${NARENAS_OFFSET})

file(GLOB_RECURSE SRC *.c)
file(GLOB_RECURSE INC *.h)
include_directories(extlibc)

add_executable(malldump ${SRC})

install(TARGETS malldump
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
