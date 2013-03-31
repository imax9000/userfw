project(userfw_ipfw C)

declare_userfw_module(ipfw)

find_file(IP_FW_PRIVATE_H
	NAMES netinet/ipfw/ip_fw_private.h
		netpfil/ipfw/ip_fw_private.h)

configure_file(ip_fw_private.h.in ${CMAKE_BINARY_DIR}/${CMAKE_CURRENT_SOURCE_DIR}/ip_fw_private.h)
