cmake_minimum_required(VERSION 2.8)
project(userfw C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(SYS_ROOT    "/usr/src/sys" CACHE PATH "Path to FreeBSD kernel source tree")
list(APPEND CMAKE_INCLUDE_PATH "${SYS_ROOT}")

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "userfw doesn't support in-source-tree builds, please use separate directory for building.")
endif (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

add_subdirectory(core)
add_subdirectory(modules)
add_subdirectory(lib)
add_subdirectory(include)
add_subdirectory(cli)
