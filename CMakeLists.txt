cmake_minimum_required(VERSION 2.8)
project(userfw C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(core)
add_subdirectory(modules)
add_subdirectory(lib)
add_subdirectory(include)
add_subdirectory(cli)
