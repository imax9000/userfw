project(userfw_core C)

set(KMODDIR	"/boot/modules" CACHE PATH "Kernel modules directory")
set(DOMAIN_STUB ON CACHE BOOL "Use AF_USERFW domain stub to allow kldunload userfw.ko")
set(OPCODE_VERIFICATION OFF CACHE BOOL "Use runtime opcode verification")

set(MAKE_ARGS "S=${CMAKE_CURRENT_SOURCE_DIR}" "MAKEOBJDIRPREFIX=${CMAKE_BINARY_DIR}")
if (NOT OPCODE_VERIFICATION)
	list(APPEND MAKE_ARGS "SKIP_OPCODE_VERIFICATION=1")
endif (NOT OPCODE_VERIFICATION)

if (DOMAIN_STUB)
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/userfw.ko"
		COMMAND make ARGS ${MAKE_ARGS} obj
		COMMAND make ARGS ${MAKE_ARGS}
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/domain_stub/userfw_domain_stub.ko"
		COMMAND make ${MAKE_ARGS} obj
		COMMAND make ${MAKE_ARGS}
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/domain_stub")
	add_custom_target(userfw_domain_stub_kmod ALL
		DEPENDS "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/domain_stub/userfw_domain_stub.ko")
else (DOMAIN_STUB)
	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/userfw.ko"
		COMMAND make ${MAKE_ARGS} obj
		COMMAND make SKIP_DOMAIN_STUB=1 ${MAKE_ARGS}
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif (DOMAIN_STUB)

add_custom_target(userfw_core_kmod ALL
	DEPENDS "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/userfw.ko")

install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\" ${MAKE_ARGS}
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
if (DOMAIN_STUB)
	install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\" ${MAKE_ARGS}
			WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}/domain_stub\")")
endif (DOMAIN_STUB)
