project(userfw_cli C)

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -Werror)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

file(GLOB SRCS *.c)
file(GLOB HEADERS *.h)

add_executable(userfw_cli ${SRCS})
target_link_libraries(userfw_cli userfw)
set_property(TARGET userfw_cli
	PROPERTY OUTPUT_NAME userfw)

install(TARGETS userfw_cli
	DESTINATION bin)
