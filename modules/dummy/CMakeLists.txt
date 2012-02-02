project(userfw_dummy C)

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummy.ko"
	COMMAND make
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(userfw_dummy ALL
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummy.ko")

install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\"
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
