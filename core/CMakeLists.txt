project(userfw_core C)

set(KMODDIR	"/boot/modules" CACHE PATH "Kernel modules directory")

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/userfw.ko"
	COMMAND make
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(userfw_core_kmod ALL
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/userfw.ko")

install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\"
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
