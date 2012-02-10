project(userfw_dummynet C)

set(MAKE_ARGS "")
if (NOT OPCODE_VERIFICATION)
	set(MAKE_ARGS "${MAKE_ARGS} SKIP_OPCODE_VERIFICATION=1")
endif (NOT OPCODE_VERIFICATION)

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummynet.ko"
	COMMAND make ${MAKE_ARGS}
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(userfw_dummynet ALL
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/userfw_dummynet.ko")

install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\"
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
