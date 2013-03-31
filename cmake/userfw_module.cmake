function(declare_userfw_module modname)
	declare_userfw_module_with_name(${modname} userfw_${modname})
endfunction(declare_userfw_module)

function(declare_userfw_module_with_name modname filename)
	set(MAKE_ARGS "S=${CMAKE_CURRENT_SOURCE_DIR}" "MAKEOBJDIRPREFIX=${CMAKE_BINARY_DIR}")
	if (NOT OPCODE_VERIFICATION)
		list(APPEND MAKE_ARGS "SKIP_OPCODE_VERIFICATION=1")
	endif (NOT OPCODE_VERIFICATION)

	add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/${filename}.ko"
		COMMAND make ${MAKE_ARGS} obj
		COMMAND make ${MAKE_ARGS}
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

	add_custom_target(userfw_${modname} ALL
		DEPENDS "${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/${filename}.ko")

	install(CODE "execute_process(COMMAND make install \"KMODDIR=${KMODDIR}\" \"PREFIX=${CMAKE_INSTALL_PREFIX}\" ${MAKE_ARGS}
		WORKING_DIRECTORY \"${CMAKE_CURRENT_SOURCE_DIR}\")")
endfunction(declare_userfw_module_with_name)
