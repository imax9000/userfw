project(userfw_ipfw C)

declare_userfw_module(ipfw ipfw.c ipfw.h)

find_file(IP_FW_PRIVATE_H
	NAMES netinet/ipfw/ip_fw_private.h
		netpfil/ipfw/ip_fw_private.h)

configure_file(ip_fw_private.h.in ip_fw_private.h)
