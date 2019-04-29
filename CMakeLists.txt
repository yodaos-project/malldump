cmake_minimum_required(VERSION 2.8)
set(CMAKE_MACOSX_RPATH 1)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -g -Wall")
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

include_directories(src)
include_directories(include)
link_directories(${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(src)

#option(WITH_TESTS "Build all tests." ON)
#if (WITH_TESTS)
#	enable_testing()
#	add_subdirectory(tests)
#endif ()
