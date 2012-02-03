project(userfw_dummynet C)

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummynet.ko"
	COMMAND make
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(userfw_dummynet ALL
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummynet.ko")

install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\"
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
