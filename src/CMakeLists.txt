cmake_minimum_required(VERSION 2.8)

file(GLOB SRC *.c)
file(GLOB INC *.h)

add_executable(malldump ${SRC})
target_link_libraries(malldump dl)

install(TARGETS malldump
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib)
