cmake_minimum_required(VERSION 2.8)
set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall")
option(BUILD_DEBUG "Build with debug info." OFF)
if (BUILD_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    message(STATUS "Build with -g for debug")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    message(STATUS "Build without -g but with -O3 for release")
endif ()

include_directories(src)
include_directories(include)
link_directories(${PROJECT_SOURCE_DIR}/lib ${PROJECT_SOURCE_DIR}/lib64)

add_subdirectory(src)
