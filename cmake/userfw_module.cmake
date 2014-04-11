function(declare_userfw_module modname srcs hdrs)
	declare_userfw_module_with_name(${modname} userfw_${modname} "${srcs}" "${hdrs}")
endfunction(declare_userfw_module)

function(declare_userfw_module_with_name modname filename srcs hdrs)
	# generate makefile
	set(MAKEFILE "${CMAKE_CURRENT_BINARY_DIR}/Makefile_userfw")
	file(WRITE "${MAKEFILE}" "
.PATH: ${CMAKE_CURRENT_SOURCE_DIR}

KMOD=	${filename}
KMODDIR=	${KMODDIR}
CFLAGS+=	-I${CMAKE_CURRENT_SOURCE_DIR}/../../include\n")
	if (NOT OPCODE_VERIFICATION)
		file(APPEND "${MAKEFILE}" "CFLAGS+=	-DSKIP_OPCODE_VERIFICATION\n")
	endif (NOT OPCODE_VERIFICATION)
	foreach(filename ${srcs} ${hdrs})
		file(APPEND "${MAKEFILE}" "SRCS+=	${filename}\n")
	endforeach(filename)
	file(APPEND "${MAKEFILE}" "\n.include <bsd.kmod.mk>\n")

	add_custom_command(OUTPUT "${filename}.ko"
		COMMAND make -f Makefile_userfw)

	add_custom_target(userfw_${modname} ALL
		DEPENDS "${filename}.ko")

	install(FILES ${hdrs}
		DESTINATION include/userfw/modules)

	install(CODE "execute_process(COMMAND pwd COMMAND make -f Makefile_userfw install \"PREFIX=${CMAKE_INSTALL_PREFIX}\"
		WORKING_DIRECTORY \"${CMAKE_CURRENT_BINARY_DIR}\")")
endfunction(declare_userfw_module_with_name)
