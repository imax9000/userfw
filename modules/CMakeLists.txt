include(userfw_module)

set(USERFW_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../include")

add_subdirectory(bpf)
add_subdirectory(counters)
add_subdirectory(dummy EXCLUDE_FROM_ALL)
add_subdirectory(dummynet)
add_subdirectory(ipfw)
add_subdirectory(log)
add_subdirectory(multiruleset)
add_subdirectory(ng_userfw_connector)
