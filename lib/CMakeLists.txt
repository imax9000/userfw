project(userfw_lib C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

file(GLOB C_SRCS *.c)
file(GLOB C_HEADERS *.h)

add_library(userfw SHARED ${C_SRCS})
set_target_properties(userfw PROPERTIES 
	SOVERSION 1
	VERSION 1.0)

install(FILES ${C_HEADERS}
	DESTINATION include/userfw)

install(TARGETS userfw
	DESTINATION lib)
