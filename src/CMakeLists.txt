cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_executable(ptmalloc_dump ${SRC})
target_link_libraries(ptmalloc_dump dl)
set_target_properties(ptmalloc_dump PROPERTIES VERSION 0.1.0 SOVERSION 0.1)

install(TARGETS ptmalloc_dump
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)

install(FILES ${INC} DESTINATION include/ptmalloc_dump)
